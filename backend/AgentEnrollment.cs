using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

sealed class AgentEnrollmentOptions
{
    public const string SectionName = "AgentEnrollment";
    public bool Enabled { get; set; }
    public bool AllowLegacyAgentKeys { get; set; }
    public string IssuerCertificateSubject { get; set; } = "";
    public string IssuerCertificateSha256 { get; set; } = "";
    public StoreName IssuerStoreName { get; set; } = StoreName.My;
    public StoreLocation IssuerStoreLocation { get; set; } = StoreLocation.LocalMachine;
    public int TokenMinutes { get; set; } = 10;
    public int CertificateDays { get; set; } = 90;
    public int RotationGraceMinutes { get; set; } = 15;
}

sealed record AgentEnrollmentResult(string CertificateDerBase64, string CertificateSha256, DateTimeOffset NotAfter);

sealed class AgentEnrollmentService(IOptions<AgentEnrollmentOptions> configured, MonitoringDbContext db)
{
    private readonly AgentEnrollmentOptions _options = configured.Value;

    public async Task<AgentEnrollmentResult?> EnrollAsync(AgentEnrollmentRequest request, string suppliedToken, CancellationToken cancellationToken)
    {
        if (!_options.Enabled || request.HostName is null || request.HostName.Length > 64 || request.CsrPem is null || request.CsrPem.Length is < 128 or > 16384 || suppliedToken.Length is < 32 or > 256) return null;
        var hostName = request.HostName.Trim().ToUpperInvariant();
        var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == hostName, cancellationToken);
        if (host is null) return null;
        var token = await db.AgentEnrollmentTokens.AsNoTracking().SingleOrDefaultAsync(item => item.HostId == host.Id, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (token is null || token.UsedAt is not null || token.ExpiresAt <= now || !FixedTimeHashEquals(token.TokenHash, suppliedToken)) return null;

        // Validate and issue before consuming the one-time token, then claim it atomically.
        // A malformed CSR must not permanently consume the enrollment token.
        using var certificate = IssueCertificate(hostName, request.CsrPem, now);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var claimed = await db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE "AgentEnrollmentTokens"
            SET "UsedAt" = {now}
            WHERE "HostId" = {host.Id} AND "UsedAt" IS NULL AND "ExpiresAt" > {now} AND "TokenHash" = {token.TokenHash}
            """, cancellationToken);
        if (claimed != 1) return null;
        var raw = certificate.Export(X509ContentType.Cert);
        var sha256 = Convert.ToHexString(SHA256.HashData(raw));
        var credential = await db.AgentCredentials.FindAsync([host.Id], cancellationToken);
        if (credential is null)
        {
            credential = new AgentCredential { HostId = host.Id, KeyHash = AgentKeyAuthenticationHandler.Hash(AgentKeyAuthenticationHandler.CreateKey()), RotatedAt = now };
            db.AgentCredentials.Add(credential);
        }
        else
        {
            // Invalidate the previously issued shared key when mTLS enrollment succeeds.
            credential.KeyHash = AgentKeyAuthenticationHandler.Hash(AgentKeyAuthenticationHandler.CreateKey());
            credential.RotatedAt = now;
        }
        credential.RequireCertificate = true;
        credential.PreviousCertificateSha256 = credential.CertificateSha256;
        credential.PreviousCertificateValidUntil = credential.CertificateSha256 is null
            ? null
            : now.AddMinutes(Math.Clamp(_options.RotationGraceMinutes, 5, 60));
        credential.CertificateSha256 = sha256;
        credential.CertificateNotAfter = certificate.NotAfter.ToUniversalTime();
        db.AuditLogs.Add(new AuditLog { Actor = $"agent-enrollment:{hostName}", Action = "Agent mTLS 注册", Detail = $"{hostName}: {sha256}", CreatedAt = now });
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new AgentEnrollmentResult(Convert.ToBase64String(raw), sha256, certificate.NotAfter.ToUniversalTime());
    }

    public static string CreateToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    public static string HashToken(string token) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private X509Certificate2 IssueCertificate(string hostName, string csrPem, DateTimeOffset now)
    {
        var normalizedPem = NormalizeCsrPem(csrPem);
        var loaded = CertificateRequest.LoadSigningRequestPem(normalizedPem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.Default, RSASignaturePadding.Pkcs1);
        if (!string.Equals(loaded.SubjectName.Name, $"CN={hostName}", StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("CSR subject must match the registered host name.");
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(loaded.PublicKey.ExportSubjectPublicKeyInfo(), out _);
        if (rsa.KeySize < 2048) throw new CryptographicException("Agent CSR RSA key must be at least 2048 bits.");

        var request = new CertificateRequest(new X500DistinguishedName($"CN={hostName}"), loaded.PublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using var issuer = LoadIssuer(now);
        var notBefore = now.AddMinutes(-5);
        var desiredNotAfter = now.AddDays(Math.Clamp(_options.CertificateDays, 7, 365));
        var issuerLimit = new DateTimeOffset(issuer.NotAfter.ToUniversalTime()).AddMinutes(-5);
        var notAfter = desiredNotAfter < issuerLimit ? desiredNotAfter : issuerLimit;
        if (notAfter <= notBefore) throw new InvalidOperationException("Agent certificate issuer expires too soon.");
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        return request.Create(issuer, notBefore, notAfter, serial);
    }

    private X509Certificate2 LoadIssuer(DateTimeOffset now)
    {
        var expectedSha256 = NormalizeSha256(_options.IssuerCertificateSha256);
        if (string.IsNullOrWhiteSpace(_options.IssuerCertificateSubject) || expectedSha256.Length != 64 || !expectedSha256.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Agent enrollment issuer subject and SHA-256 fingerprint must both be configured.");
        using var store = new X509Store(_options.IssuerStoreName, _options.IssuerStoreLocation);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var issuer = store.Certificates.Find(X509FindType.FindBySubjectName, _options.IssuerCertificateSubject, validOnly: false)
            .OfType<X509Certificate2>().Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > now.UtcDateTime.AddDays(7) &&
                string.Equals(Convert.ToHexString(SHA256.HashData(item.RawData)), expectedSha256, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.NotAfter).FirstOrDefault();
        return issuer is null ? throw new InvalidOperationException("Agent enrollment issuer certificate was not found or has no private key.") : new X509Certificate2(issuer);
    }

    private static string NormalizeSha256(string? value) => (value ?? "").Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal).ToUpperInvariant();

    private static bool FixedTimeHashEquals(string expectedHash, string suppliedToken)
    {
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(expectedHash), Convert.FromBase64String(HashToken(suppliedToken))); }
        catch (FormatException) { return false; }
    }

    private static string NormalizeCsrPem(string value)
    {
        var trimmed = value.Trim().Replace("NEW CERTIFICATE REQUEST", "CERTIFICATE REQUEST", StringComparison.Ordinal);
        if (trimmed.Contains("-----BEGIN CERTIFICATE REQUEST-----", StringComparison.Ordinal)) return trimmed;
        try
        {
            var base64 = string.Concat(trimmed.Where(character => !char.IsWhiteSpace(character)));
            _ = Convert.FromBase64String(base64);
            return $"-----BEGIN CERTIFICATE REQUEST-----\n{base64}\n-----END CERTIFICATE REQUEST-----";
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("CSR 必须为有效的 PEM 或 Base64 编码。", exception);
        }
    }
}
