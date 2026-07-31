using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

if (args is ["--verify-sqlite", var sqlitePath])
{
    var fullPath = Path.GetFullPath(sqlitePath);
    if (!File.Exists(fullPath)) throw new FileNotFoundException("SQLite database was not found.", fullPath);
    await using var verification = new SqliteConnection($"Data Source={fullPath};Mode=ReadOnly;Pooling=False");
    await verification.OpenAsync();
    await using var command = verification.CreateCommand();
    command.CommandText = "PRAGMA integrity_check;";
    var integrity = (string?)await command.ExecuteScalarAsync();
    if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"SQLite integrity check failed: {integrity}");
    Console.WriteLine("SQLite integrity check passed.");
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(options => options.ServiceName = "MonitoringPlatform");
builder.WebHost.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https => https.ClientCertificateMode = ClientCertificateMode.AllowCertificate));

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
    .AddScheme<AuthenticationSchemeOptions, AgentCertificateAuthenticationHandler>(AgentCertificateAuthenticationHandler.SchemeName, _ => { })
    .AddScheme<AuthenticationSchemeOptions, AgentKeyAuthenticationHandler>(AgentKeyAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(SecurityPolicies.Configure);
builder.Services.AddScoped<IPasswordHasher<LocalUser>, PasswordHasher<LocalUser>>();
builder.Services.Configure<ProbeWorkerOptions>(builder.Configuration.GetSection(ProbeWorkerOptions.SectionName));
builder.Services.Configure<DataMaintenanceOptions>(builder.Configuration.GetSection(DataMaintenanceOptions.SectionName));
builder.Services.Configure<AgentHealthOptions>(builder.Configuration.GetSection(AgentHealthOptions.SectionName));
builder.Services.Configure<NotificationContactOptions>(builder.Configuration.GetSection(NotificationContactOptions.SectionName));
builder.Services.Configure<NotificationWorkerOptions>(builder.Configuration.GetSection(NotificationWorkerOptions.SectionName));
builder.Services.Configure<HaOptions>(builder.Configuration.GetSection(HaOptions.SectionName));
builder.Services.Configure<AgentEnrollmentOptions>(builder.Configuration.GetSection(AgentEnrollmentOptions.SectionName));
builder.Services.AddHttpClient("probe", client => client.Timeout = Timeout.InfiniteTimeSpan)
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpClient("ha-witness", client => client.Timeout = Timeout.InfiniteTimeSpan);
builder.Services.AddSingleton<IProbeExecutor, NetworkProbeExecutor>();
builder.Services.AddSingleton<IHaLeaseClient, HttpWitnessLeaseClient>();
builder.Services.AddSingleton<HaLeaseState>();
builder.Services.AddHostedService<ProbeWorker>();
builder.Services.AddHostedService<DataMaintenanceWorker>();
builder.Services.AddHostedService<AgentHealthWorker>();
builder.Services.AddHostedService<NotificationWorker>();
builder.Services.AddHostedService<HaLeaseWorker>();
builder.Services.AddHostedService<HaReplicationWorker>();
builder.Services.AddScoped<RuntimeSettingsStore>();
builder.Services.AddScoped<SmsSender>();
builder.Services.AddScoped<AgentEnrollmentService>();
builder.Services.AddRateLimiter(options => options.AddFixedWindowLimiter("login", limiter =>
{
    limiter.PermitLimit = 10;
    limiter.Window = TimeSpan.FromMinutes(1);
    limiter.QueueLimit = 0;
    limiter.AutoReplenishment = true;
}).AddFixedWindowLimiter("enroll", limiter =>
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
app.UseDefaultFiles();
app.UseStaticFiles();
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
app.Use(async (context, next) =>
{
    var isSafeMethod = HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method) || HttpMethods.IsOptions(context.Request.Method);
    var lease = context.RequestServices.GetRequiredService<HaLeaseState>();
    if (!isSafeMethod && !lease.CanMutate(DateTimeOffset.UtcNow))
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = Math.Clamp(lease.Options.LeaseTtlSeconds, 5, 300).ToString();
        await context.Response.WriteAsJsonAsync(new { error = "当前节点未持有有效 witness 租约，写入已被隔离。" });
        return;
    }
    await next();
});

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
    await db.Database.EnsureCreatedAsync();
    await SecuritySchema.EnsureAsync(db);
    await SeedData.EnsureAsync(db, app.Environment.IsDevelopment());
    await LocalUserBootstrap.EnsureAsync(scope.ServiceProvider, builder.Configuration, app.Environment);
}

app.MapGet("/api/health", async (MonitoringDbContext db, CancellationToken cancellationToken) =>
{
    try
    {
        var connected = await db.Database.CanConnectAsync(cancellationToken);
        return connected
            ? Results.Ok(new { status = "healthy", database = "connected", utc = DateTimeOffset.UtcNow })
            : Results.Json(new { status = "unhealthy", database = "unavailable", utc = DateTimeOffset.UtcNow }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch
    {
        return Results.Json(new { status = "unhealthy", database = "unavailable", utc = DateTimeOffset.UtcNow }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

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
    return Results.Ok(new { hosts, incidents, ha = app.Services.GetRequiredService<HaLeaseState>().Status(DateTimeOffset.UtcNow) });
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
read.MapGet("/hosts/{name}/services", async (string name, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    return host is null ? Results.NotFound() : Results.Ok(await db.HostServiceStatuses.Where(item => item.HostId == host.Id)
        .OrderBy(item => item.Name).Select(item => new HostServiceStatusDto(item.Name, item.Status, item.UpdatedAt)).ToListAsync());
});
read.MapGet("/incidents", async (MonitoringDbContext db) => Results.Ok(
    (await db.Incidents.Include(item => item.Host).ToListAsync())
    .OrderByDescending(item => item.StartedAt).Select(IncidentDto.From)));
read.MapGet("/rules", async (MonitoringDbContext db) => Results.Ok(await db.AlertRules.OrderBy(item => item.Id).ToListAsync()));
read.MapGet("/notification-policies", async (MonitoringDbContext db) => Results.Ok(await db.NotificationPolicies.OrderBy(item => item.Id).ToListAsync()));
read.MapGet("/notification-deliveries", async (MonitoringDbContext db) => Results.Ok(await db.NotificationDeliveryStates
    .OrderByDescending(item => item.LastAttemptAt).Take(200)
    .Select(item => new NotificationDeliveryDto(item.IncidentId, item.NotificationPolicyId, item.Status, item.Attempts, item.LastAttemptAt, item.LastSentAt, item.NextAttemptAt, item.LastError)).ToListAsync()));
read.MapGet("/probes", async (MonitoringDbContext db) => Results.Ok((await db.ProbeDefinitions.Include(probe => probe.Host).OrderBy(probe => probe.Host!.Name).ThenBy(probe => probe.Name).ToListAsync()).Select(ProbeDto.From)));
read.MapGet("/hosts/{name}/probes", async (string name, MonitoringDbContext db) => Results.Ok((await db.ProbeDefinitions.Include(probe => probe.Host).Where(probe => probe.Host!.Name == name.ToUpperInvariant()).OrderBy(probe => probe.Name).ToListAsync()).Select(ProbeDto.From)));
read.MapGet("/ha", (HaLeaseState haLease) => Results.Ok(haLease.Status(DateTimeOffset.UtcNow)));
read.MapGet("/sms-status", async (RuntimeSettingsStore settingsStore) =>
{
    var settings = await settingsStore.GetDtoAsync();
    return Results.Ok(new
    {
        enabled = settings.Sms.Enabled,
        rolloutMode = settings.Sms.RolloutMode,
        configured = settings.Sms.SecretIdConfigured && settings.Sms.SecretKeyConfigured && !string.IsNullOrWhiteSpace(settings.Sms.SdkAppId) && !string.IsNullOrWhiteSpace(settings.Sms.SignName) && !string.IsNullOrWhiteSpace(settings.Sms.TemplateId),
        testPhoneCount = settings.Sms.TestPhoneNumbers.Length
    });
});
var operations = app.MapGroup("/api").RequireAuthorization(SecurityPolicies.Operator);
operations.MapGet("/audit", async (MonitoringDbContext db) => Results.Ok(
    (await db.AuditLogs.ToListAsync()).OrderByDescending(item => item.CreatedAt).Take(100)));
operations.MapPost("/incidents/{id:guid}/acknowledge", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Acknowledged, "确认事件", request.Note, principal, db));
operations.MapPost("/incidents/{id:guid}/silence", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Silenced, "临时静默", request.Note, principal, db));
operations.MapPost("/incidents/{id:guid}/maintenance", async (Guid id, IncidentActionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
    await IncidentOperations.UpdateAsync(id, IncidentState.Maintenance, "进入维护", request.Note, principal, db));
operations.MapPost("/notification-deliveries/{incidentId:guid}/{policyId:int}/resolve", async (Guid incidentId, int policyId, NotificationDeliveryResolutionRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var state = await db.NotificationDeliveryStates.FindAsync(incidentId, policyId);
    if (state is null) return Results.NotFound();
    if (state.Status != "发送中") return Results.Conflict(new { error = "只有发送结果不明确的记录可以人工处置。" });
    var action = request.Action?.Trim().ToLowerInvariant();
    if (action == "retry")
    {
        state.Status = "待发送";
        state.NextAttemptAt = DateTimeOffset.UtcNow;
        state.LastError = "运维已确认可能重复风险并批准重试。";
    }
    else if (action == "mark-sent")
    {
        var policy = await db.NotificationPolicies.FindAsync(policyId);
        state.Status = "已发送";
        state.LastSentAt = DateTimeOffset.UtcNow;
        state.NextAttemptAt = policy is null ? DateTimeOffset.MaxValue : DateTimeOffset.UtcNow.AddMinutes(Math.Clamp(policy.RepeatMinutes, 5, 1440));
        state.LastError = null;
    }
    else if (action == "stop")
    {
        state.Status = "已停止";
        state.NextAttemptAt = DateTimeOffset.MaxValue;
        state.LastError = "运维人工停止不明确投递。";
    }
    else return Results.ValidationProblem(new Dictionary<string, string[]> { ["action"] = ["action 必须为 retry、mark-sent 或 stop。"] });
    await Audit.AddAsync(db, principal, "处置不明确短信投递", $"incident={incidentId}; policy={policyId}; action={action}");
    await db.SaveChangesAsync();
    return Results.Ok(new NotificationDeliveryDto(state.IncidentId, state.NotificationPolicyId, state.Status, state.Attempts, state.LastAttemptAt, state.LastSentAt, state.NextAttemptAt, state.LastError));
});

var administration = app.MapGroup("/api").RequireAuthorization(SecurityPolicies.Admin);
administration.MapPost("/hosts", async (HostRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateHost(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["host"] = [error] });
    var name = request.Name.Trim().ToUpperInvariant();
    if (await db.Hosts.AnyAsync(host => host.Name == name)) return Results.Conflict(new { error = "服务器名称已存在。" });
    var host = new Host { Name = name, Ip = request.Ip.Trim(), Room = request.Room.Trim(), Service = request.Service.Trim(), Group = string.IsNullOrWhiteSpace(request.Group) ? "默认组" : request.Group.Trim(), Status = "未知", LastHeartbeatAt = DateTimeOffset.UtcNow };
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
    host.Name = nextName; host.Ip = request.Ip.Trim(); host.Room = request.Room.Trim(); host.Service = request.Service.Trim(); host.Group = string.IsNullOrWhiteSpace(request.Group) ? host.Group : request.Group.Trim();
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
    if (credential?.RequireCertificate == true)
        return Results.Conflict(new { error = "该资产已强制使用 mTLS；请签发一次性注册令牌轮换证书，不允许降级为共享 Key。" });
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
administration.MapDelete("/hosts/{name}/agent-certificate", async (string name, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var credential = await db.AgentCredentials.FindAsync(host.Id);
    if (credential is null || !credential.RequireCertificate) return Results.NotFound();
    credential.CertificateSha256 = null;
    credential.CertificateNotAfter = null;
    credential.PreviousCertificateSha256 = null;
    credential.PreviousCertificateValidUntil = null;
    credential.RotatedAt = DateTimeOffset.UtcNow;
    await Audit.AddAsync(db, principal, "撤销 Agent 客户端证书", host.Name);
    await db.SaveChangesAsync();
    return Results.NoContent();
});
administration.MapPost("/hosts/{name}/enrollment-token", async (string name, ClaimsPrincipal principal, MonitoringDbContext db, Microsoft.Extensions.Options.IOptions<AgentEnrollmentOptions> configured) =>
{
    if (!configured.Value.Enabled) return Results.Conflict(new { error = "Agent mTLS enrollment is disabled." });
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var plainTextToken = AgentEnrollmentService.CreateToken();
    var now = DateTimeOffset.UtcNow;
    var expiresAt = now.AddMinutes(Math.Clamp(configured.Value.TokenMinutes, 5, 60));
    var token = await db.AgentEnrollmentTokens.FindAsync(host.Id);
    if (token is null)
    {
        token = new AgentEnrollmentToken { HostId = host.Id, TokenHash = AgentEnrollmentService.HashToken(plainTextToken), CreatedAt = now, ExpiresAt = expiresAt };
        db.AgentEnrollmentTokens.Add(token);
    }
    else
    {
        token.TokenHash = AgentEnrollmentService.HashToken(plainTextToken);
        token.CreatedAt = now;
        token.ExpiresAt = expiresAt;
        token.UsedAt = null;
    }
    await Audit.AddAsync(db, principal, "签发 Agent 一次性注册令牌", $"{host.Name}: expires={expiresAt:O}");
    await db.SaveChangesAsync();
    return Results.Ok(new AgentEnrollmentTokenResponse(host.Name, plainTextToken, expiresAt));
});
administration.MapPost("/hosts/{name}/probes", async (string name, ProbeRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateProbe(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["probe"] = [error] });
    var host = await db.Hosts.SingleOrDefaultAsync(item => item.Name == name.ToUpperInvariant());
    if (host is null) return Results.NotFound();
    var fingerprint = ProbeFingerprint.Create(request);
    if (await db.ProbeDefinitions.AnyAsync(item => item.HostId == host.Id && item.Fingerprint == fingerprint))
        return Results.Conflict(new { error = "该服务器已存在相同目标的探测定义。" });
    var now = DateTimeOffset.UtcNow;
    var probe = new ProbeDefinition
    {
        HostId = host.Id,
        Name = request.Name.Trim(),
        Type = request.Type.Trim().ToLowerInvariant(),
        Target = request.Target.Trim(),
        Port = request.Port,
        ExpectedStatus = request.ExpectedStatus,
        Fingerprint = fingerprint,
        Enabled = request.Enabled,
        IntervalSeconds = request.IntervalSeconds,
        TimeoutMilliseconds = request.TimeoutMilliseconds,
        FailureThreshold = request.FailureThreshold,
        RecoveryThreshold = request.RecoveryThreshold,
        NextRunAt = request.Enabled ? now : null,
        CreatedAt = now,
        UpdatedAt = now
    };
    db.ProbeDefinitions.Add(probe);
    await Audit.AddAsync(db, principal, "添加网络探测", $"{host.Name}: {probe.Name} ({probe.Type})");
    await db.SaveChangesAsync();
    probe.Host = host;
    return Results.Created($"/api/probes/{probe.Id}", ProbeDto.From(probe));
});
administration.MapPut("/probes/{id:int}", async (int id, ProbeRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateProbe(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["probe"] = [error] });
    var probe = await db.ProbeDefinitions.Include(item => item.Host).SingleOrDefaultAsync(item => item.Id == id);
    if (probe is null) return Results.NotFound();
    var fingerprint = ProbeFingerprint.Create(request);
    if (await db.ProbeDefinitions.AnyAsync(item => item.HostId == probe.HostId && item.Id != id && item.Fingerprint == fingerprint))
        return Results.Conflict(new { error = "该服务器已存在相同目标的探测定义。" });
    var now = DateTimeOffset.UtcNow;
    if (!string.Equals(probe.Fingerprint, fingerprint, StringComparison.Ordinal))
        await ProbeIncidentService.ResolveForConfigurationChangeAsync(db, probe, "探测目标已修改，自动关闭原事件。", now);
    probe.Name = request.Name.Trim(); probe.Type = request.Type.Trim().ToLowerInvariant(); probe.Target = request.Target.Trim(); probe.Port = request.Port;
    probe.ExpectedStatus = request.ExpectedStatus; probe.Fingerprint = fingerprint; probe.Enabled = request.Enabled; probe.IntervalSeconds = request.IntervalSeconds;
    probe.TimeoutMilliseconds = request.TimeoutMilliseconds; probe.FailureThreshold = request.FailureThreshold; probe.RecoveryThreshold = request.RecoveryThreshold;
    probe.ConsecutiveFailures = 0; probe.ConsecutiveSuccesses = 0; probe.BackoffLevel = 0; probe.Status = ProbeStatus.Unknown; probe.LastError = null;
    probe.NextRunAt = request.Enabled ? now : null; probe.UpdatedAt = now;
    await Audit.AddAsync(db, principal, "更新网络探测", $"{probe.Host?.Name}: {probe.Name} ({probe.Type})");
    await db.SaveChangesAsync();
    return Results.Ok(ProbeDto.From(probe));
});
administration.MapDelete("/probes/{id:int}", async (int id, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var probe = await db.ProbeDefinitions.Include(item => item.Host).SingleOrDefaultAsync(item => item.Id == id);
    if (probe is null) return Results.NotFound();
    await ProbeIncidentService.ResolveForConfigurationChangeAsync(db, probe, "探测定义已删除，自动关闭原事件。", DateTimeOffset.UtcNow);
    db.ProbeDefinitions.Remove(probe);
    await Audit.AddAsync(db, principal, "删除网络探测", $"{probe.Host?.Name}: {probe.Name}");
    await db.SaveChangesAsync();
    return Results.NoContent();
});
administration.MapPut("/rules/{id:int}", async (int id, AlertRuleUpdate request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var rule = await db.AlertRules.FindAsync(id);
    if (rule is null) return Results.NotFound();
    if (!double.IsFinite(request.WarningThreshold) || !double.IsFinite(request.CriticalThreshold) || request.WarningThreshold < 0 || request.CriticalThreshold < 0 || request.TriggerCount is < 1 or > 60 || request.RecoveryCount is < 1 or > 60)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["rule"] = ["阈值必须为非负数，连续触发/恢复次数必须在 1 到 60 之间。"] });
    rule.Enabled = request.Enabled; rule.WarningThreshold = request.WarningThreshold; rule.CriticalThreshold = request.CriticalThreshold; rule.TriggerCount = request.TriggerCount; rule.RecoveryCount = request.RecoveryCount; rule.UpdatedAt = DateTimeOffset.UtcNow;
    await Audit.AddAsync(db, principal, "更新告警规则", rule.Name);
    await db.SaveChangesAsync();
    return Results.Ok(rule);
});
administration.MapPost("/notification-policies", async (NotificationPolicyRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateNotificationPolicy(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["policy"] = [error] });
    var policy = new NotificationPolicy { Name = request.Name.Trim(), ServerGroup = request.ServerGroup.Trim(), Severity = request.Severity, ContactGroup = request.ContactGroup.Trim(), Enabled = request.Enabled, RepeatMinutes = request.RepeatMinutes, UpdatedAt = DateTimeOffset.UtcNow };
    db.NotificationPolicies.Add(policy);
    await Audit.AddAsync(db, principal, "创建通知策略", policy.Name);
    await db.SaveChangesAsync();
    return Results.Created($"/api/notification-policies/{policy.Id}", policy);
});
administration.MapPut("/notification-policies/{id:int}", async (int id, NotificationPolicyRequest request, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var error = Validation.ValidateNotificationPolicy(request);
    if (error is not null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["policy"] = [error] });
    var policy = await db.NotificationPolicies.FindAsync(id);
    if (policy is null) return Results.NotFound();
    policy.Name = request.Name.Trim(); policy.ServerGroup = request.ServerGroup.Trim(); policy.Severity = request.Severity; policy.ContactGroup = request.ContactGroup.Trim(); policy.Enabled = request.Enabled; policy.RepeatMinutes = request.RepeatMinutes; policy.UpdatedAt = DateTimeOffset.UtcNow;
    await Audit.AddAsync(db, principal, "更新通知策略", policy.Name);
    await db.SaveChangesAsync();
    return Results.Ok(policy);
});
administration.MapDelete("/notification-policies/{id:int}", async (int id, ClaimsPrincipal principal, MonitoringDbContext db) =>
{
    var policy = await db.NotificationPolicies.FindAsync(id);
    if (policy is null) return Results.NotFound();
    db.NotificationPolicies.Remove(policy);
    await Audit.AddAsync(db, principal, "删除通知策略", policy.Name);
    await db.SaveChangesAsync();
    return Results.NoContent();
});
administration.MapGet("/settings", async (RuntimeSettingsStore settingsStore, CancellationToken cancellationToken) =>
    Results.Ok(await settingsStore.GetDtoAsync(cancellationToken)));
administration.MapPut("/settings", async (SystemSettingsUpdateRequest request, ClaimsPrincipal principal, MonitoringDbContext db, RuntimeSettingsStore settingsStore, CancellationToken cancellationToken) =>
{
    try
    {
        var saved = await settingsStore.UpdateAsync(request, cancellationToken);
        await Audit.AddAsync(db, principal, "更新全局设置", "已更新站点信息与腾讯云短信运行配置。");
        await db.SaveChangesAsync(cancellationToken);
        return Results.Ok(saved);
    }
    catch (ArgumentException exception)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["settings"] = [exception.Message] });
    }
});
administration.MapGet("/settings/server-groups", async (MonitoringDbContext db, CancellationToken cancellationToken) =>
{
    var groups = await db.Hosts.GroupBy(host => host.Group)
        .Select(group => new { Name = group.Key, HostCount = group.Count() })
        .OrderBy(group => group.Name)
        .ToListAsync(cancellationToken);
    return Results.Ok(groups.Select(group => new ServerGroupDto(string.IsNullOrWhiteSpace(group.Name) ? "默认组" : group.Name, group.HostCount)));
});
administration.MapPost("/notifications/test-sms", async (SmsTestRequest request, SmsSender sender) =>
{
    var result = await sender.SendAsync(request.PhoneNumbers, request.TemplateParameters);
    return result.Sent ? Results.Ok(result) : Results.Problem(result.Error, statusCode: StatusCodes.Status503ServiceUnavailable);
});
administration.MapPost("/maintenance/backup", async (MonitoringDbContext db, Microsoft.Extensions.Options.IOptions<DataMaintenanceOptions> options, IWebHostEnvironment environment, ILogger<DataMaintenanceWorker> logger, CancellationToken cancellationToken) =>
{
    var result = await DataMaintenanceWorker.BackupNowAsync(db, options.Value, environment, logger, cancellationToken);
    return Results.Ok(result);
});

app.MapPost("/api/v1/agents/enroll", async (AgentEnrollmentRequest request, HttpContext context, AgentEnrollmentService enrollment, CancellationToken cancellationToken) =>
{
    var suppliedToken = context.Request.Headers["X-Enrollment-Token"].ToString();
    try
    {
        var result = await enrollment.EnrollAsync(request, suppliedToken, cancellationToken);
        return result is null ? Results.Unauthorized() : Results.Ok(result);
    }
    catch (CryptographicException exception)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["csr"] = [exception.Message] });
    }
}).AllowAnonymous().RequireRateLimiting("enroll");

app.MapPost("/api/v1/agents/ingest", async (AgentIngestRequest request, ClaimsPrincipal principal, MonitoringDbContext db, CancellationToken cancellationToken) =>
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
    if (AgentTelemetry.Validate(request) is { } telemetryError)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["telemetry"] = [telemetryError] });
    await AgentTelemetry.ApplyAsync(db, host, request, DateTimeOffset.UtcNow, cancellationToken);
    db.MetricSamples.Add(new MetricSample { HostId = host.Id, CollectedAt = request.CollectedAt, Cpu = request.Cpu, Memory = request.Memory, Disk = request.Disk, Latency = request.Latency });
    await db.SaveChangesAsync();
    return Results.Accepted();
}).RequireAuthorization(SecurityPolicies.Agent);

app.MapFallback((HttpContext context, IWebHostEnvironment environment) =>
{
    if (context.Request.Path.StartsWithSegments("/api")) return Results.NotFound();
    var indexPath = Path.Combine(environment.ContentRootPath, "wwwroot", "index.html");
    return File.Exists(indexPath) ? Results.File(indexPath, "text/html; charset=utf-8") : Results.NotFound();
}).AllowAnonymous();

app.Run();

public partial class Program;
