using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

static class SecurityRoles
{
    public const string Admin = "Admin";
    public const string Operator = "Operator";
    public const string Viewer = "Viewer";
    public static readonly HashSet<string> All = [Admin, Operator, Viewer];
}

static class SecurityClaims { public const string AgentHost = "agent_host"; public const string SecurityStamp = "security_stamp"; }

static class SecurityPolicies
{
    public const string Admin = "Admin";
    public const string Operator = "Operator";
    public const string Viewer = "Viewer";
    public const string Agent = "Agent";

    public static void Configure(Microsoft.AspNetCore.Authorization.AuthorizationOptions options)
    {
        options.AddPolicy(Admin, policy => policy.RequireAuthenticatedUser().RequireRole(SecurityRoles.Admin));
        options.AddPolicy(Operator, policy => policy.RequireAuthenticatedUser().RequireRole(SecurityRoles.Admin, SecurityRoles.Operator));
        options.AddPolicy(Viewer, policy => policy.RequireAuthenticatedUser().RequireRole(SecurityRoles.Admin, SecurityRoles.Operator, SecurityRoles.Viewer));
        options.AddPolicy(Agent, policy => policy.AddAuthenticationSchemes(AgentCertificateAuthenticationHandler.SchemeName, AgentKeyAuthenticationHandler.SchemeName).RequireAuthenticatedUser().RequireClaim(SecurityClaims.AgentHost));
    }
}

sealed class AgentCertificateAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    MonitoringDbContext db) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "AgentCertificate";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var certificate = await Context.Connection.GetClientCertificateAsync();
        if (certificate is null) return AuthenticateResult.NoResult();
        var hostName = Request.Headers[AgentKeyAuthenticationHandler.HostHeader].ToString().Trim().ToUpperInvariant();
        if (hostName.Length is < 1 or > 64 || !string.Equals(certificate.GetNameInfo(X509NameType.SimpleName, false), hostName, StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.Fail("Client certificate subject does not match the agent host.");
        if (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            return AuthenticateResult.Fail("Client certificate is not currently valid.");
        var clientAuth = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.OfType<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"));
        if (!clientAuth) return AuthenticateResult.Fail("Client certificate is missing the Client Authentication EKU.");
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            if (!chain.Build(certificate)) return AuthenticateResult.Fail("Client certificate chain is not trusted.");
        }
        var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == hostName);
        if (host is null) return AuthenticateResult.Fail("Unknown agent.");
        var credential = await db.AgentCredentials.FindAsync(host.Id);
        var sha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var now = DateTimeOffset.UtcNow;
        var isCurrent = credential?.RequireCertificate == true && credential.CertificateSha256 is not null &&
            string.Equals(credential.CertificateSha256, sha256, StringComparison.OrdinalIgnoreCase) && credential.CertificateNotAfter.HasValue && credential.CertificateNotAfter.Value > now;
        var isPreviousDuringRotation = credential?.RequireCertificate == true && credential.PreviousCertificateSha256 is not null &&
            string.Equals(credential.PreviousCertificateSha256, sha256, StringComparison.OrdinalIgnoreCase) && credential.PreviousCertificateValidUntil.HasValue && credential.PreviousCertificateValidUntil.Value > now;
        if (!isCurrent && !isPreviousDuringRotation)
            return AuthenticateResult.Fail("Client certificate is not registered or has expired.");
        var identity = new ClaimsIdentity(SchemeName);
        identity.AddClaim(new Claim(ClaimTypes.Name, hostName));
        identity.AddClaim(new Claim(SecurityClaims.AgentHost, hostName));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }
}

static class SecurityPrincipal
{
    public static int? UserId(ClaimsPrincipal principal) => int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    public static ClaimsPrincipal ForUser(LocalUser user)
    {
        var identity = new ClaimsIdentity(BearerTokenDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
        identity.AddClaim(new Claim(ClaimTypes.Role, user.Role));
        identity.AddClaim(new Claim(SecurityClaims.SecurityStamp, user.SecurityStamp));
        return new ClaimsPrincipal(identity);
    }
}

sealed class AgentKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    MonitoringDbContext db,
    IOptions<AgentEnrollmentOptions> enrollment) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "AgentKey";
    public const string HostHeader = "X-Agent-Name";
    public const string KeyHeader = "X-Agent-Key";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var hostName = Request.Headers[HostHeader].ToString().Trim().ToUpperInvariant();
        var suppliedKey = Request.Headers[KeyHeader].ToString();
        if (hostName.Length is < 1 or > 64 || suppliedKey.Length is < 32 or > 256)
            return AuthenticateResult.Fail("Missing or invalid agent credentials.");
        var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == hostName);
        if (host is null) return AuthenticateResult.Fail("Unknown agent.");
        var credential = await db.AgentCredentials.FindAsync(host.Id);
        if (credential?.RequireCertificate == true || (enrollment.Value.Enabled && !enrollment.Value.AllowLegacyAgentKeys))
            return AuthenticateResult.Fail("This agent must use a registered client certificate.");
        if (credential is null || !KeyMatches(credential.KeyHash, suppliedKey))
            return AuthenticateResult.Fail("Invalid agent credentials.");
        var identity = new ClaimsIdentity(SchemeName);
        identity.AddClaim(new Claim(ClaimTypes.Name, hostName));
        identity.AddClaim(new Claim(SecurityClaims.AgentHost, hostName));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    public static string CreateKey() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string key) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    private static bool KeyMatches(string expectedHash, string suppliedKey)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(expectedHash), Convert.FromBase64String(Hash(suppliedKey)));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

static class SecurityValidation
{
    public static string? ValidateUser(string? username, string? password, string? role)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Trim().Length is < 3 or > 64) return "用户名长度必须为 3 到 64 个字符。";
        if (role is null || !SecurityRoles.All.Contains(role)) return "角色必须为 Admin、Operator 或 Viewer。";
        return ValidatePassword(password);
    }

    public static string? ValidatePassword(string? password)
    {
        if (password is null || password.Length < 12 || !password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit) || password.All(char.IsLetterOrDigit))
            return "密码至少 12 位，并同时包含大写字母、小写字母、数字和符号。";
        return null;
    }
}

static class LocalUserBootstrap
{
    public static async Task EnsureAsync(IServiceProvider services, IConfiguration configuration, IHostEnvironment environment)
    {
        var db = services.GetRequiredService<MonitoringDbContext>();
        if (await db.LocalUsers.AnyAsync()) return;
        var section = environment.IsDevelopment()
            ? configuration.GetSection("DevelopmentAuth")
            : configuration.GetSection("Authentication:BootstrapAdmin");
        if (!section.GetValue("Enabled", false))
            throw new InvalidOperationException("No local users exist. Configure a one-time bootstrap admin through environment variables; no production default password is provided.");
        var username = section["Username"] ?? "";
        var password = section["Password"] ?? "";
        var validation = SecurityValidation.ValidateUser(username, password, SecurityRoles.Admin);
        if (validation is not null) throw new InvalidOperationException($"Bootstrap admin configuration is invalid: {validation}");
        var user = new LocalUser { UserName = username.Trim(), NormalizedUserName = LocalUser.Normalize(username), PasswordHash = "", Role = SecurityRoles.Admin, SecurityStamp = Guid.NewGuid().ToString("N"), Enabled = true, CreatedAt = DateTimeOffset.UtcNow };
        var hasher = services.GetRequiredService<IPasswordHasher<LocalUser>>();
        user.PasswordHash = hasher.HashPassword(user, password);
        db.LocalUsers.Add(user);
        db.AuditLogs.Add(new AuditLog { Actor = "system", Action = "初始化管理员", Detail = user.UserName, CreatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
    }
}
