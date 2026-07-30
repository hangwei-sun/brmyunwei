using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var configuredConnection = builder.Configuration.GetConnectionString("Monitoring");
var databasePath = Path.Combine(builder.Environment.ContentRootPath, "Data", "monitoring.db");
Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
builder.Services.AddDbContext<MonitoringDbContext>(options =>
    options.UseSqlite(configuredConnection ?? $"Data Source={databasePath}"));

var keyPath = builder.Configuration["Authentication:DataProtectionKeysPath"];
if (string.IsNullOrWhiteSpace(keyPath))
{
    var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    keyPath = Path.Combine(string.IsNullOrWhiteSpace(localData) ? builder.Environment.ContentRootPath : localData,
        "MonitoringPlatform", "DataProtectionKeys");
}
Directory.CreateDirectory(keyPath);
var dataProtection = builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyPath));
if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = BearerTokenDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = BearerTokenDefaults.AuthenticationScheme;
    })
    .AddBearerToken(BearerTokenDefaults.AuthenticationScheme, options =>
    {
        options.BearerTokenExpiration = TimeSpan.FromHours(8);
        options.RefreshTokenExpiration = TimeSpan.FromDays(7);
    })
    .AddScheme<AuthenticationSchemeOptions, AgentKeyAuthenticationHandler>(AgentKeyAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(SecurityPolicies.Configure);
builder.Services.AddScoped<IPasswordHasher<LocalUser>, PasswordHasher<LocalUser>>();
builder.Services.Configure<SmsOptions>(builder.Configuration.GetSection("TencentCloudSms"));
builder.Services.AddScoped<SmsSender>();
builder.Services.AddRateLimiter(options => options.AddFixedWindowLimiter("login", limiter =>
{
    limiter.PermitLimit = 10;
    limiter.Window = TimeSpan.FromMinutes(1);
    limiter.QueueLimit = 0;
    limiter.AutoReplenishment = true;
}));
builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins("http://127.0.0.1:5173", "http://localhost:5173")
    .AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true &&
        context.User.Identity.AuthenticationType == BearerTokenDefaults.AuthenticationScheme)
    {
        var idValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var tokenRole = context.User.FindFirstValue(ClaimTypes.Role);
        var tokenStamp = context.User.FindFirstValue(SecurityClaims.SecurityStamp);
        var db = context.RequestServices.GetRequiredService<MonitoringDbContext>();
        var user = int.TryParse(idValue, out var id) ? await db.LocalUsers.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id) : null;
        if (user is null || !user.Enabled || user.Role != tokenRole || user.SecurityStamp != tokenStamp)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }
    }
    await next();
});
app.UseAuthorization();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
    await db.Database.EnsureCreatedAsync();
    await SecuritySchema.EnsureAsync(db);
    await SeedData.EnsureAsync(db);
    await LocalUserBootstrap.EnsureAsync(scope.ServiceProvider, builder.Configuration, app.Environment);
}

app.MapGet("/api/health", () => Results.Ok(new { status = "healthy", utc = DateTimeOffset.UtcNow }));

app.MapPost("/api/auth/login", async (LoginRequest request, MonitoringDbContext db, IPasswordHasher<LocalUser> hasher) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || request.Username.Length > 64 || string.IsNullOrEmpty(request.Password) || request.Password.Length > 256)
        return Results.Problem("用户名或密码错误。", statusCode: StatusCodes.Status401Unauthorized);
    var normalized = LocalUser.Normalize(request.Username);
    var user = await db.LocalUsers.SingleOrDefaultAsync(item => item.NormalizedUserName == normalized);
    if (user is null || !user.Enabled || (user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow))
        return Results.Problem("用户名或密码错误。", statusCode: StatusCodes.Status401Unauthorized);

    var verification = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
    if (verification == PasswordVerificationResult.Failed)
    {
        user.FailedLoginCount++;
        if (user.FailedLoginCount >= 5)
        {
            user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
            user.FailedLoginCount = 0;
        }
        await db.SaveChangesAsync();
        return Results.Problem("用户名或密码错误。", statusCode: StatusCodes.Status401Unauthorized);
    }

    user.FailedLoginCount = 0;
    user.LockoutEnd = null;
    user.LastLoginAt = DateTimeOffset.UtcNow;
    if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        user.PasswordHash = hasher.HashPassword(user, request.Password);
    db.AuditLogs.Add(new AuditLog { Actor = user.UserName, Action = "本地账号登录", Detail = "登录成功", CreatedAt = DateTimeOffset.UtcNow });
    await db.SaveChangesAsync();
    return Results.SignIn(SecurityPrincipal.ForUser(user), authenticationScheme: BearerTokenDefaults.AuthenticationScheme);
}).RequireRateLimiting("login");

app.MapGet("/api/auth/me", (ClaimsPrincipal principal) => Results.Ok(new
{
    username = principal.Identity?.Name,
    role = principal.FindFirstValue(ClaimTypes.Role)
})).RequireAuthorization(SecurityPolicies.Viewer);

app.MapGet("/api/users", async (MonitoringDbContext db) => Results.Ok(await db.LocalUsers
    .OrderBy(user => user.UserName)
    .Select(user => new UserDto(user.UserName, user.Role, user.Enabled, user.LastLoginAt, user.CreatedAt))
    .ToListAsync())).RequireAuthorization(SecurityPolicies.Admin);

app.MapPost("/api/users", async (CreateUserRequest request, ClaimsPrincipal principal,
    MonitoringDbContext db, IPasswordHasher<LocalUser> hasher) =>
{
    var validation = SecurityValidation.ValidateUser(request.Username, request.Password, request.Role);
    if (validation is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["user"] = [validation] });
    var normalized = LocalUser.Normalize(request.Username!);
    if (await db.LocalUsers.AnyAsync(item => item.NormalizedUserName == normalized))
        return Results.Conflict(new { error = "用户名已存在。" });
    var user = new LocalUser
    {
        UserName = request.Username!.Trim(),
        NormalizedUserName = normalized,
        Role = request.Role!,
        PasswordHash = "",
        SecurityStamp = Guid.NewGuid().ToString("N"),
        Enabled = true,
        CreatedAt = DateTimeOffset.UtcNow
    };
    user.PasswordHash = hasher.HashPassword(user, request.Password!);
    db.LocalUsers.Add(user);
    await Audit.AddAsync(db, principal, "创建本地账号", $"{user.UserName} ({user.Role})");
    await db.SaveChangesAsync();
    return Results.Created($"/api/users/{Uri.EscapeDataString(user.UserName)}",
        new UserDto(user.UserName, user.Role, user.Enabled, user.LastLoginAt, user.CreatedAt));
}).RequireAuthorization(SecurityPolicies.Admin);

app.MapPut("/api/users/{username}", async (string username, UpdateUserRequest request, ClaimsPrincipal principal,
    MonitoringDbContext db, IPasswordHasher<LocalUser> hasher) =>
{
    if (request.Role is null || !SecurityRoles.All.Contains(request.Role))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["role"] = ["角色必须为 Admin、Operator 或 Viewer。"] });
    if (request.Password is not null && SecurityValidation.ValidatePassword(request.Password) is { } passwordError)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["password"] = [passwordError] });
    var user = await db.LocalUsers.SingleOrDefaultAsync(item => item.NormalizedUserName == LocalUser.Normalize(username));
    if (user is null) return Results.NotFound();
    if (user.Role == SecurityRoles.Admin && (!request.Enabled || request.Role != SecurityRoles.Admin) &&
        await db.LocalUsers.CountAsync(item => item.Enabled && item.Role == SecurityRoles.Admin) <= 1)
        return Results.Conflict(new { error = "不能停用或降级最后一个管理员账号。" });
    user.Role = request.Role;
    user.Enabled = request.Enabled;
    if (request.Password is not null) user.PasswordHash = hasher.HashPassword(user, request.Password);
    user.SecurityStamp = Guid.NewGuid().ToString("N");
    await Audit.AddAsync(db, principal, "更新本地账号", $"{user.UserName} ({user.Role}, enabled={user.Enabled})");
    await db.SaveChangesAsync();
    return Results.Ok(new UserDto(user.UserName, user.Role, user.Enabled, user.LastLoginAt, user.CreatedAt));
}).RequireAuthorization(SecurityPolicies.Admin);

var read = app.MapGroup("/api").RequireAuthorization(SecurityPolicies.Viewer);
read.MapGet("/dashboard", async (MonitoringDbContext db) =>
{
    var hosts = (await db.Hosts.OrderBy(host => host.Name).ToListAsync()).Select(HostDto.From);
    var incidents = (await db.Incidents.Include(incident => incident.Host)
        .Where(incident => incident.State == IncidentState.Open).ToListAsync())
        .OrderByDescending(incident => incident.Severity == "严重").ThenByDescending(incident => incident.StartedAt)
        .Select(IncidentDto.From);
    return Results.Ok(new { hosts, incidents, ha = HaCapability.Current });
});
read.MapGet("/hosts", async (MonitoringDbContext db) =>
    Results.Ok((await db.Hosts.OrderBy(host => host.Name).ToListAsync()).Select(HostDto.From)));
read.MapGet("/hosts/{name}", async (string name, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    return host is null ? Results.NotFound() : Results.Ok(HostDto.From(host));
});
read.MapGet("/hosts/{name}/metrics", async (string name, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var samples = (await db.MetricSamples.Where(sample => sample.HostId == host.Id).ToListAsync())
        .OrderByDescending(sample => sample.CollectedAt).Take(288).OrderBy(sample => sample.CollectedAt)
        .Select(sample => new { sample.CollectedAt, sample.Cpu, sample.Memory, sample.Disk, sample.Latency });
    return Results.Ok(samples);
});
read.MapGet("/incidents", async (MonitoringDbContext db) => Results.Ok(
    (await db.Incidents.Include(item => item.Host).ToListAsync())
    .OrderByDescending(item => item.StartedAt).Select(IncidentDto.From)));
read.MapGet("/rules", async (MonitoringDbContext db) => Results.Ok(await db.AlertRules.OrderBy(item => item.Id).ToListAsync()));
read.MapGet("/notification-policies", async (MonitoringDbContext db) => Results.Ok(await db.NotificationPolicies.OrderBy(item => item.Id).ToListAsync()));
read.MapGet("/ha", () => Results.Ok(HaCapability.Current));
var operations = app.MapGroup("/api").RequireAuthorization(SecurityPolicies.Operator);
operations.MapGet("/audit", async (MonitoringDbContext db) => Results.Ok(
    (await db.AuditLogs.ToListAsync()).OrderByDescending(item => item.CreatedAt).Take(100)));
operations.MapPost("/incidents/{id:guid}/acknowledge", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Acknowledged, "确认事件", request.Note, principal, db));
operations.MapPost("/incidents/{id:guid}/silence", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Silenced, "临时静默", request.Note, principal, db));
operations.MapPost("/incidents/{id:guid}/maintenance", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Maintenance, "进入维护", request.Note, principal, db));

var administration = app.MapGroup("/api").RequireAuthorization(SecurityPolicies.Admin);
administration.MapPost("/hosts", async (HostRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateHost(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["host"] = [error] });
    var name = request.Name.Trim().ToUpperInvariant();
    if (await db.Hosts.AnyAsync(host => host.Name == name)) return Results.Conflict(new { error = "服务器名称已存在。" });
    var host = new Host { Name = name, Ip = request.Ip.Trim(), Room = request.Room.Trim(), Service = request.Service.Trim(), Status = "未知", LastHeartbeatAt = DateTimeOffset.UtcNow };
    db.Hosts.Add(host);
    await Audit.AddAsync(db, principal, "添加资产", $"{host.Name} ({host.Ip})");
    await db.SaveChangesAsync();
    return Results.Created($"/api/hosts/{Uri.EscapeDataString(host.Name)}", HostDto.From(host));
});
administration.MapPut("/hosts/{name}", async (string name, HostRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateHost(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["host"] = [error] });
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var nextName = request.Name.Trim().ToUpperInvariant();
    if (nextName != host.Name && await db.Hosts.AnyAsync(item => item.Name == nextName)) return Results.Conflict(new { error = "服务器名称已存在。" });
    host.Name = nextName; host.Ip = request.Ip.Trim(); host.Room = request.Room.Trim(); host.Service = request.Service.Trim();
    await Audit.AddAsync(db, principal, "修改资产", $"{host.Name} ({host.Ip})");
    await db.SaveChangesAsync();
    return Results.Ok(HostDto.From(host));
});
administration.MapDelete("/hosts/{name}", async (string name, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    if (await db.Incidents.AnyAsync(item => item.HostId == host.Id)) return Results.Conflict(new { error = "该服务器有关联事件，不能删除。请先停用资产以保留审计记录。" });
    db.MetricSamples.RemoveRange(await db.MetricSamples.Where(item => item.HostId == host.Id).ToListAsync());
    var credential = await db.AgentCredentials.FindAsync(host.Id);
    if (credential is not null) db.AgentCredentials.Remove(credential);
    db.Hosts.Remove(host);
    await Audit.AddAsync(db, principal, "删除资产", $"{host.Name} ({host.Ip})");
    await db.SaveChangesAsync();
    return Results.NoContent();
});
administration.MapPost("/hosts/{name}/agent-key", async (string name, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var plainTextKey = AgentKeyAuthenticationHandler.CreateKey();
    var credential = await db.AgentCredentials.FindAsync(host.Id);
    if (credential is null)
    {
        credential = new AgentCredential { HostId = host.Id, KeyHash = AgentKeyAuthenticationHandler.Hash(plainTextKey), RotatedAt = DateTimeOffset.UtcNow };
        db.AgentCredentials.Add(credential);
    }
    else
    {
        credential.KeyHash = AgentKeyAuthenticationHandler.Hash(plainTextKey);
        credential.RotatedAt = DateTimeOffset.UtcNow;
    }
    await Audit.AddAsync(db, principal, "轮换 Agent Key", host.Name);
    await db.SaveChangesAsync();
    return Results.Ok(new AgentKeyResponse(host.Name, plainTextKey, credential.RotatedAt));
});
administration.MapPut("/rules/{id:int}", async (int id, AlertRuleUpdate request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var rule = await db.AlertRules.FindAsync(id);
    if (rule is null) return Results.NotFound();
    rule.Enabled = request.Enabled; rule.WarningThreshold = request.WarningThreshold; rule.CriticalThreshold = request.CriticalThreshold; rule.UpdatedAt = DateTimeOffset.UtcNow;
    await Audit.AddAsync(db, principal, "更新告警规则", rule.Name);
    await db.SaveChangesAsync();
    return Results.Ok(rule);
});
administration.MapPut("/notification-policies/{id:int}", async (int id, NotificationPolicyUpdate request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var policy = await db.NotificationPolicies.FindAsync(id);
    if (policy is null) return Results.NotFound();
    policy.Enabled = request.Enabled; policy.RepeatMinutes = request.RepeatMinutes; policy.UpdatedAt = DateTimeOffset.UtcNow;
    await Audit.AddAsync(db, principal, "更新通知策略", policy.Name);
    await db.SaveChangesAsync();
    return Results.Ok(policy);
});
administration.MapPost("/notifications/test-sms", async (SmsTestRequest request, SmsSender sender) =>
{
    var result = await sender.SendAsync(request.PhoneNumbers, request.TemplateParameters);
    return result.Sent ? Results.Ok(result) : Results.Problem(result.Error, statusCode: StatusCodes.Status503ServiceUnavailable);
});

// Deliberately no failover mutation endpoint: this process currently has no real HA coordinator.
app.MapPost("/api/v1/agents/ingest", async (AgentIngestRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var authenticatedHost = principal.FindFirstValue(SecurityClaims.AgentHost);
    if (!string.Equals(authenticatedHost, request.HostName, StringComparison.OrdinalIgnoreCase)) return Results.Forbid();
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == request.HostName.ToUpperInvariant());
    if (host is null) return Results.NotFound(new { error = "Unknown host" });
    if (request.Sequence <= host.LastSequence) return Results.Conflict(new { error = "Duplicate or out-of-order sequence" });
    if (request.CollectedAt < DateTimeOffset.UtcNow.AddMinutes(-10) || request.CollectedAt > DateTimeOffset.UtcNow.AddMinutes(2))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["collectedAt"] = ["采集时间超出允许窗口。"] });
    if (!Validation.ValidMetric(request.Cpu) || !Validation.ValidMetric(request.Memory) || !Validation.ValidMetric(request.Disk) || request.Latency < 0 || request.Latency > 120000)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["metrics"] = ["指标值超出允许范围。"] });
    host.Cpu = request.Cpu; host.Memory = request.Memory; host.Disk = request.Disk; host.Latency = request.Latency;
    host.LastHeartbeatAt = DateTimeOffset.UtcNow; host.LastSequence = request.Sequence; host.Status = "健康";
    db.MetricSamples.Add(new MetricSample { HostId = host.Id, CollectedAt = request.CollectedAt, Cpu = request.Cpu, Memory = request.Memory, Disk = request.Disk, Latency = request.Latency });
    await db.SaveChangesAsync();
    return Results.Accepted();
}).RequireAuthorization(SecurityPolicies.Agent);

app.Run();

public partial class Program;
