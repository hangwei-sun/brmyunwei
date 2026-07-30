using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

sealed class MonitoringDbContext(DbContextOptions<MonitoringDbContext> options) : DbContext(options)
{
    public DbSet<Host> Hosts => Set<Host>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<MetricSample> MetricSamples => Set<MetricSample>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<NotificationPolicy> NotificationPolicies => Set<NotificationPolicy>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<LocalUser> LocalUsers => Set<LocalUser>();
    public DbSet<AgentCredential> AgentCredentials => Set<AgentCredential>();
    public DbSet<ProbeDefinition> ProbeDefinitions => Set<ProbeDefinition>();
    public DbSet<HostServiceStatus> HostServiceStatuses => Set<HostServiceStatus>();
    public DbSet<MetricRuleState> MetricRuleStates => Set<MetricRuleState>();
    public DbSet<NotificationDeliveryState> NotificationDeliveryStates => Set<NotificationDeliveryState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<LocalUser>().HasIndex(user => user.NormalizedUserName).IsUnique();
        modelBuilder.Entity<AgentCredential>().HasKey(credential => credential.HostId);
        modelBuilder.Entity<AgentCredential>().HasOne<Host>().WithOne().HasForeignKey<AgentCredential>(credential => credential.HostId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<ProbeDefinition>().HasIndex(probe => new { probe.HostId, probe.Fingerprint }).IsUnique();
        modelBuilder.Entity<ProbeDefinition>().HasOne(probe => probe.Host).WithMany().HasForeignKey(probe => probe.HostId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<Incident>().HasIndex(incident => new { incident.HostId, incident.Fingerprint });
        modelBuilder.Entity<HostServiceStatus>().HasKey(item => new { item.HostId, item.Name });
        modelBuilder.Entity<HostServiceStatus>().HasOne<Host>().WithMany().HasForeignKey(item => item.HostId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<MetricRuleState>().HasKey(item => new { item.HostId, item.AlertRuleId });
        modelBuilder.Entity<MetricRuleState>().HasOne<Host>().WithMany().HasForeignKey(item => item.HostId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<MetricRuleState>().HasOne<AlertRule>().WithMany().HasForeignKey(item => item.AlertRuleId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<NotificationDeliveryState>().HasKey(item => new { item.IncidentId, item.NotificationPolicyId });
        modelBuilder.Entity<NotificationDeliveryState>().HasOne<Incident>().WithMany().HasForeignKey(item => item.IncidentId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<NotificationDeliveryState>().HasOne<NotificationPolicy>().WithMany().HasForeignKey(item => item.NotificationPolicyId).OnDelete(DeleteBehavior.Cascade);
    }
}

sealed class Host { public int Id { get; set; } public required string Name { get; set; } public required string Ip { get; set; } public required string Room { get; set; } public required string Service { get; set; } public string Group { get; set; } = "默认组"; public required string Status { get; set; } public double? Cpu { get; set; } public double? Memory { get; set; } public double? Disk { get; set; } public double? Latency { get; set; } public double? NetworkBytesPerSecond { get; set; } public DateTimeOffset? BootTime { get; set; } public string? AgentVersion { get; set; } public DateTimeOffset LastHeartbeatAt { get; set; } public long LastSequence { get; set; } }
sealed class Incident { public Guid Id { get; set; } = Guid.NewGuid(); public int HostId { get; set; } public Host? Host { get; set; } public required string Title { get; set; } public required string Severity { get; set; } public required string Signal { get; set; } public required string Value { get; set; } public string Fingerprint { get; set; } = ""; public string State { get; set; } = IncidentState.Open; public DateTimeOffset StartedAt { get; set; } public DateTimeOffset UpdatedAt { get; set; } public DateTimeOffset? ResolvedAt { get; set; } public string? Note { get; set; } }
sealed class MetricSample { public long Id { get; set; } public int HostId { get; set; } public DateTimeOffset CollectedAt { get; set; } public double Cpu { get; set; } public double Memory { get; set; } public double Disk { get; set; } public double Latency { get; set; } }
sealed class AlertRule { public int Id { get; set; } public required string Name { get; set; } public required string CheckItem { get; set; } public required string Severity { get; set; } public bool Enabled { get; set; } public double WarningThreshold { get; set; } public double CriticalThreshold { get; set; } public int TriggerCount { get; set; } = 1; public int RecoveryCount { get; set; } = 2; public DateTimeOffset UpdatedAt { get; set; } }
sealed class NotificationPolicy { public int Id { get; set; } public required string Name { get; set; } public required string ServerGroup { get; set; } public required string Severity { get; set; } public required string ContactGroup { get; set; } public bool Enabled { get; set; } public int RepeatMinutes { get; set; } public DateTimeOffset UpdatedAt { get; set; } }
sealed class AuditLog { public long Id { get; set; } public required string Actor { get; set; } public required string Action { get; set; } public required string Detail { get; set; } public DateTimeOffset CreatedAt { get; set; } }
sealed class LocalUser { public int Id { get; set; } public required string UserName { get; set; } public required string NormalizedUserName { get; set; } public required string PasswordHash { get; set; } public required string Role { get; set; } public required string SecurityStamp { get; set; } public bool Enabled { get; set; } public int FailedLoginCount { get; set; } public DateTimeOffset? LockoutEnd { get; set; } public DateTimeOffset? LastLoginAt { get; set; } public DateTimeOffset CreatedAt { get; set; } public static string Normalize(string value) => value.Trim().ToUpperInvariant(); }
sealed class AgentCredential { public int HostId { get; set; } public required string KeyHash { get; set; } public DateTimeOffset RotatedAt { get; set; } }
sealed class ProbeDefinition
{
    public int Id { get; set; }
    public int HostId { get; set; }
    public Host? Host { get; set; }
    public required string Name { get; set; }
    public required string Type { get; set; }
    public required string Target { get; set; }
    public int? Port { get; set; }
    public int? ExpectedStatus { get; set; }
    public required string Fingerprint { get; set; }
    public bool Enabled { get; set; }
    public int IntervalSeconds { get; set; }
    public int TimeoutMilliseconds { get; set; }
    public int FailureThreshold { get; set; }
    public int RecoveryThreshold { get; set; }
    public string Status { get; set; } = ProbeStatus.Unknown;
    public int ConsecutiveFailures { get; set; }
    public int ConsecutiveSuccesses { get; set; }
    public int BackoffLevel { get; set; }
    public DateTimeOffset? LastCheckedAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public DateTimeOffset? NextRunAt { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
sealed class HostServiceStatus { public int HostId { get; set; } public required string Name { get; set; } public required string Status { get; set; } public DateTimeOffset UpdatedAt { get; set; } }
sealed class MetricRuleState { public int HostId { get; set; } public int AlertRuleId { get; set; } public int ConsecutiveFailures { get; set; } public int ConsecutiveSuccesses { get; set; } public bool Firing { get; set; } public DateTimeOffset UpdatedAt { get; set; } }
sealed class NotificationDeliveryState { public Guid IncidentId { get; set; } public int NotificationPolicyId { get; set; } public string Status { get; set; } = "待发送"; public int Attempts { get; set; } public DateTimeOffset? LastAttemptAt { get; set; } public DateTimeOffset? LastSentAt { get; set; } public DateTimeOffset NextAttemptAt { get; set; } public string? RequestId { get; set; } public string? LastError { get; set; } }

static class SecuritySchema
{
    public static async Task EnsureAsync(MonitoringDbContext db)
    {
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "LocalUsers" (
              "Id" INTEGER NOT NULL CONSTRAINT "PK_LocalUsers" PRIMARY KEY AUTOINCREMENT,
              "UserName" TEXT NOT NULL,
              "NormalizedUserName" TEXT NOT NULL,
              "PasswordHash" TEXT NOT NULL,
              "Role" TEXT NOT NULL,
              "SecurityStamp" TEXT NOT NULL,
              "Enabled" INTEGER NOT NULL,
              "FailedLoginCount" INTEGER NOT NULL,
              "LockoutEnd" TEXT NULL,
              "LastLoginAt" TEXT NULL,
              "CreatedAt" TEXT NOT NULL
            );
            """);
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open) await connection.OpenAsync();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info('LocalUsers');";
            await using var reader = await command.ExecuteReaderAsync();
            var hasSecurityStamp = false;
            while (await reader.ReadAsync())
                if (string.Equals(reader.GetString(1), "SecurityStamp", StringComparison.OrdinalIgnoreCase)) hasSecurityStamp = true;
            if (!hasSecurityStamp)
            {
                await reader.DisposeAsync();
                await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"LocalUsers\" ADD COLUMN \"SecurityStamp\" TEXT NOT NULL DEFAULT '';");
            }
        }
        await db.Database.ExecuteSqlRawAsync("UPDATE \"LocalUsers\" SET \"SecurityStamp\" = lower(hex(randomblob(16))) WHERE \"SecurityStamp\" = '';");
        await db.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX IF NOT EXISTS \"IX_LocalUsers_NormalizedUserName\" ON \"LocalUsers\" (\"NormalizedUserName\");");
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "AgentCredentials" (
              "HostId" INTEGER NOT NULL CONSTRAINT "PK_AgentCredentials" PRIMARY KEY,
              "KeyHash" TEXT NOT NULL,
              "RotatedAt" TEXT NOT NULL,
              CONSTRAINT "FK_AgentCredentials_Hosts_HostId" FOREIGN KEY ("HostId") REFERENCES "Hosts" ("Id") ON DELETE CASCADE
            );
            """);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "ProbeDefinitions" (
              "Id" INTEGER NOT NULL CONSTRAINT "PK_ProbeDefinitions" PRIMARY KEY AUTOINCREMENT,
              "HostId" INTEGER NOT NULL,
              "Name" TEXT NOT NULL,
              "Type" TEXT NOT NULL,
              "Target" TEXT NOT NULL,
              "Port" INTEGER NULL,
              "ExpectedStatus" INTEGER NULL,
              "Fingerprint" TEXT NOT NULL,
              "Enabled" INTEGER NOT NULL,
              "IntervalSeconds" INTEGER NOT NULL,
              "TimeoutMilliseconds" INTEGER NOT NULL,
              "FailureThreshold" INTEGER NOT NULL,
              "RecoveryThreshold" INTEGER NOT NULL,
              "Status" TEXT NOT NULL,
              "ConsecutiveFailures" INTEGER NOT NULL,
              "ConsecutiveSuccesses" INTEGER NOT NULL,
              "BackoffLevel" INTEGER NOT NULL,
              "LastCheckedAt" TEXT NULL,
              "LastSuccessAt" TEXT NULL,
              "NextRunAt" TEXT NULL,
              "LastError" TEXT NULL,
              "CreatedAt" TEXT NOT NULL,
              "UpdatedAt" TEXT NOT NULL,
              CONSTRAINT "FK_ProbeDefinitions_Hosts_HostId" FOREIGN KEY ("HostId") REFERENCES "Hosts" ("Id") ON DELETE CASCADE
            );
            """);
        await db.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX IF NOT EXISTS \"IX_ProbeDefinitions_HostId_Fingerprint\" ON \"ProbeDefinitions\" (\"HostId\", \"Fingerprint\");");
        await EnsureIncidentColumnsAsync(db);
        await EnsureHostAndRuleColumnsAsync(db);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "HostServiceStatuses" (
              "HostId" INTEGER NOT NULL, "Name" TEXT NOT NULL, "Status" TEXT NOT NULL, "UpdatedAt" TEXT NOT NULL,
              CONSTRAINT "PK_HostServiceStatuses" PRIMARY KEY ("HostId", "Name"),
              CONSTRAINT "FK_HostServiceStatuses_Hosts_HostId" FOREIGN KEY ("HostId") REFERENCES "Hosts" ("Id") ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS "MetricRuleStates" (
              "HostId" INTEGER NOT NULL, "AlertRuleId" INTEGER NOT NULL, "ConsecutiveFailures" INTEGER NOT NULL,
              "ConsecutiveSuccesses" INTEGER NOT NULL, "Firing" INTEGER NOT NULL, "UpdatedAt" TEXT NOT NULL,
              CONSTRAINT "PK_MetricRuleStates" PRIMARY KEY ("HostId", "AlertRuleId"),
              CONSTRAINT "FK_MetricRuleStates_Hosts_HostId" FOREIGN KEY ("HostId") REFERENCES "Hosts" ("Id") ON DELETE CASCADE,
              CONSTRAINT "FK_MetricRuleStates_AlertRules_AlertRuleId" FOREIGN KEY ("AlertRuleId") REFERENCES "AlertRules" ("Id") ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS "NotificationDeliveryStates" (
              "IncidentId" TEXT NOT NULL, "NotificationPolicyId" INTEGER NOT NULL, "Status" TEXT NOT NULL, "Attempts" INTEGER NOT NULL,
              "LastAttemptAt" TEXT NULL, "LastSentAt" TEXT NULL, "NextAttemptAt" TEXT NOT NULL, "RequestId" TEXT NULL, "LastError" TEXT NULL,
              CONSTRAINT "PK_NotificationDeliveryStates" PRIMARY KEY ("IncidentId", "NotificationPolicyId"),
              CONSTRAINT "FK_NotificationDeliveryStates_Incidents_IncidentId" FOREIGN KEY ("IncidentId") REFERENCES "Incidents" ("Id") ON DELETE CASCADE,
              CONSTRAINT "FK_NotificationDeliveryStates_NotificationPolicies_NotificationPolicyId" FOREIGN KEY ("NotificationPolicyId") REFERENCES "NotificationPolicies" ("Id") ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS "IX_MetricRuleStates_AlertRuleId" ON "MetricRuleStates" ("AlertRuleId");
            CREATE INDEX IF NOT EXISTS "IX_NotificationDeliveryStates_NotificationPolicyId" ON "NotificationDeliveryStates" ("NotificationPolicyId");
            """);
    }

    private static async Task EnsureIncidentColumnsAsync(MonitoringDbContext db)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var connection = db.Database.GetDbConnection();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info('Incidents');";
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync()) columns.Add(reader.GetString(1));
        }
        if (!columns.Contains("Fingerprint"))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Incidents\" ADD COLUMN \"Fingerprint\" TEXT NOT NULL DEFAULT ''; ");
        if (!columns.Contains("ResolvedAt"))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Incidents\" ADD COLUMN \"ResolvedAt\" TEXT NULL;");
        await db.Database.ExecuteSqlRawAsync("CREATE INDEX IF NOT EXISTS \"IX_Incidents_HostId_Fingerprint\" ON \"Incidents\" (\"HostId\", \"Fingerprint\");");
    }

    private static async Task EnsureHostAndRuleColumnsAsync(MonitoringDbContext db)
    {
        var hostColumns = await ColumnsAsync(db, "Hosts");
        if (!hostColumns.Contains("Group")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Hosts\" ADD COLUMN \"Group\" TEXT NOT NULL DEFAULT '默认组';");
        if (!hostColumns.Contains("NetworkBytesPerSecond")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Hosts\" ADD COLUMN \"NetworkBytesPerSecond\" REAL NULL;");
        if (!hostColumns.Contains("BootTime")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Hosts\" ADD COLUMN \"BootTime\" TEXT NULL;");
        if (!hostColumns.Contains("AgentVersion")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Hosts\" ADD COLUMN \"AgentVersion\" TEXT NULL;");
        var ruleColumns = await ColumnsAsync(db, "AlertRules");
        if (!ruleColumns.Contains("TriggerCount")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AlertRules\" ADD COLUMN \"TriggerCount\" INTEGER NOT NULL DEFAULT 1;");
        if (!ruleColumns.Contains("RecoveryCount")) await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AlertRules\" ADD COLUMN \"RecoveryCount\" INTEGER NOT NULL DEFAULT 2;");
        await db.Database.ExecuteSqlRawAsync("UPDATE \"AlertRules\" SET \"TriggerCount\" = 5 WHERE \"CheckItem\" = 'CPU 使用率' AND \"TriggerCount\" = 1;");
    }

    private static async Task<HashSet<string>> ColumnsAsync(MonitoringDbContext db, string table)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var connection = db.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info('{table}');";
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) columns.Add(reader.GetString(1));
        return columns;
    }
}

static class Audit
{
    public static Task AddAsync(MonitoringDbContext db, ClaimsPrincipal principal, string action, string detail)
    {
        db.AuditLogs.Add(new AuditLog { Action = action, Detail = detail, Actor = principal.Identity?.Name ?? "unknown", CreatedAt = DateTimeOffset.UtcNow });
        return Task.CompletedTask;
    }
}

static class IncidentOperations
{
    public static async Task<IResult> UpdateAsync(Guid id, string nextState, string action, string? note, ClaimsPrincipal principal, MonitoringDbContext db)
    {
        var incident = await db.Incidents.Include(item => item.Host).SingleOrDefaultAsync(item => item.Id == id);
        if (incident is null) return Results.NotFound();
        incident.State = nextState; incident.Note = note?.Trim(); incident.UpdatedAt = DateTimeOffset.UtcNow;
        if (nextState == IncidentState.Maintenance && incident.Host is not null) incident.Host.Status = "维护中";
        await Audit.AddAsync(db, principal, action, $"{incident.Host?.Name}: {incident.Title}");
        await db.SaveChangesAsync();
        return Results.Ok(IncidentDto.From(incident));
    }
}

static class SeedData
{
    public static async Task EnsureAsync(MonitoringDbContext db, bool includeDemoData)
    {
        var now = DateTimeOffset.UtcNow;
        if (!await db.AlertRules.AnyAsync())
        {
            db.AlertRules.AddRange(new[] { new AlertRule { Name = "CPU 使用率 >90% 持续 5 分钟", CheckItem = "CPU 使用率", Severity = "严重", Enabled = true, WarningThreshold = 85, CriticalThreshold = 90, TriggerCount = 5, RecoveryCount = 2, UpdatedAt = now }, new AlertRule { Name = "磁盘可用空间 <8%（严重）", CheckItem = "磁盘可用空间", Severity = "严重", Enabled = true, WarningThreshold = 15, CriticalThreshold = 8, TriggerCount = 1, RecoveryCount = 2, UpdatedAt = now } });
            await db.SaveChangesAsync();
        }
        if (!includeDemoData || await db.Hosts.AnyAsync()) return;
        var hosts = new[]
        {
            Host("WEB-01", "10.10.1.11", "WEB", "健康", 23, 45, 38, 12), Host("WEB-02", "10.10.1.12", "WEB", "健康", 19, 41, 35, 11), Host("APP-01", "10.10.2.21", "APP", "健康", 34, 57, 42, 14), Host("APP-02", "10.10.2.22", "APP", "健康", 28, 53, 47, 12), Host("APP-07", "10.10.2.27", "APP", "性能降级", 91, 62, 58, 14), Host("DB-02", "10.10.3.12", "数据库", "业务异常", 44, 68, 93, 15), Host("DB-03", "10.10.3.13", "数据库", "健康", 26, 49, 41, 16), Host("ERP-01", "10.10.4.11", "ERP", "确认离线", null, null, null, null), Host("CACHE-01", "10.10.5.11", "缓存", "维护中", 12, 38, 28, 12), Host("MQ-01", "10.10.5.21", "中间件", "健康", 17, 38, 33, 12),
        };
        db.Hosts.AddRange(hosts);
        await db.SaveChangesAsync();
        var lookup = hosts.ToDictionary(host => host.Name);
        db.Incidents.AddRange(
            Incident(lookup["DB-02"], "磁盘空间不足 (93%)", "严重", "磁盘使用率", "93%", 2), Incident(lookup["APP-07"], "CPU 使用率过高 (91%)", "警告", "CPU 使用率", "91%", 3), Incident(lookup["APP-01"], "内存使用率过高 (86%)", "警告", "内存使用率", "86%", 5), Incident(lookup["ERP-01"], "主机确认离线", "严重", "代理、ICMP、业务探针", "失联", 7));
        db.NotificationPolicies.Add(new NotificationPolicy { Name = "生产严重告警短信", ServerGroup = "生产服务器组", Severity = "严重", ContactGroup = "一线运维值班组", Enabled = true, RepeatMinutes = 15, UpdatedAt = now });
        foreach (var host in hosts.Where(host => host.Cpu.HasValue)) for (var i = 0; i < 24; i++) db.MetricSamples.Add(new MetricSample { HostId = host.Id, CollectedAt = now.AddHours(-24 + i), Cpu = host.Cpu!.Value + Math.Sin(i) * 4, Memory = host.Memory!.Value + Math.Cos(i) * 3, Disk = host.Disk!.Value, Latency = host.Latency!.Value + Math.Abs(Math.Sin(i)) * 2 });
        db.AuditLogs.Add(new AuditLog { Action = "初始化系统", Detail = "已创建本地中心端示例数据", Actor = "system", CreatedAt = now });
        await db.SaveChangesAsync();
    }
    private static Host Host(string name, string ip, string service, string status, double? cpu, double? memory, double? disk, double? latency) => new() { Name = name, Ip = ip, Room = "生产机房 A", Service = service, Group = "生产服务器组", Status = status, Cpu = cpu, Memory = memory, Disk = disk, Latency = latency, LastHeartbeatAt = DateTimeOffset.UtcNow.AddSeconds(-6) };
    private static Incident Incident(Host host, string title, string severity, string signal, string value, int minutes) => new() { HostId = host.Id, Title = title, Severity = severity, Signal = signal, Value = value, StartedAt = DateTimeOffset.UtcNow.AddMinutes(-minutes), UpdatedAt = DateTimeOffset.UtcNow };
}
