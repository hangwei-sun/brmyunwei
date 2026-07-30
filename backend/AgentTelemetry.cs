using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

static class AgentTelemetry
{
    private static readonly HashSet<string> ValidServiceStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Running", "Stopped", "Paused", "StartPending", "StopPending", "ContinuePending", "PausePending", "NotFoundOrUnavailable"
    };

    public static string? Validate(AgentIngestRequest request)
    {
        if (request.NetworkBytesPerSecond is < 0 or > 1_000_000_000_000) return "网络速率超出允许范围。";
        if (request.BootTime is { } boot && (boot > DateTimeOffset.UtcNow.AddMinutes(2) || boot < DateTimeOffset.UtcNow.AddYears(-30))) return "启动时间超出允许范围。";
        if (request.AgentVersion is { Length: > 32 }) return "Agent 版本号过长。";
        if (request.Services is { Length: > 32 }) return "监控服务数量超过 32 个。";
        if (request.Services is not null && request.Services.Any(item => string.IsNullOrWhiteSpace(item.Name) || item.Name.Trim().Length > 128 || !ValidServiceStatuses.Contains(item.Status)))
            return "服务状态数据无效。";
        return null;
    }

    public static async Task ApplyAsync(MonitoringDbContext db, Host host, AgentIngestRequest request, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var previousBootTime = host.BootTime;
        host.Cpu = request.Cpu;
        host.Memory = request.Memory;
        host.Disk = request.Disk;
        host.Latency = request.Latency;
        host.NetworkBytesPerSecond = request.NetworkBytesPerSecond;
        host.BootTime = request.BootTime;
        host.AgentVersion = string.IsNullOrWhiteSpace(request.AgentVersion) ? host.AgentVersion : request.AgentVersion.Trim();
        host.LastHeartbeatAt = now;
        host.LastSequence = request.Sequence;

        if (previousBootTime is not null && request.BootTime is not null && request.BootTime > previousBootTime.Value.AddMinutes(1))
        {
            await OpenIncidentAsync(db, host, $"agent:reboot:{request.BootTime.Value.UtcTicks}", "检测到服务器重启", "严重", "系统启动时间", request.BootTime.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), now, cancellationToken);
        }

        if (request.Services is not null) await ApplyServicesAsync(db, host, request.Services, now, cancellationToken);
        await ApplyMetricRulesAsync(db, host, request, now, cancellationToken);
        await ResolveIncidentAsync(db, host.Id, "agent:offline", "Agent 已恢复上报。", now, cancellationToken);
        var persisted = await db.Incidents.Where(item => item.HostId == host.Id).ToListAsync(cancellationToken);
        var addedActive = db.ChangeTracker.Entries<Incident>().Any(entry => entry.State == EntityState.Added && entry.Entity.HostId == host.Id && entry.Entity.ResolvedAt == null && entry.Entity.State == IncidentState.Open);
        host.Status = addedActive || persisted.Any(item => item.ResolvedAt == null && item.State == IncidentState.Open) ? "异常" : "健康";
    }

    private static async Task ApplyServicesAsync(MonitoringDbContext db, Host host, AgentServiceStatusRequest[] services, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var normalized = services.GroupBy(item => item.Name.Trim(), StringComparer.OrdinalIgnoreCase).Select(group => group.Last()).ToArray();
        var names = normalized.Select(item => item.Name.Trim()).ToArray();
        var existing = await db.HostServiceStatuses.Where(item => item.HostId == host.Id && names.Contains(item.Name)).ToDictionaryAsync(item => item.Name, StringComparer.OrdinalIgnoreCase, cancellationToken);
        foreach (var report in normalized)
        {
            var name = report.Name.Trim();
            if (!existing.TryGetValue(name, out var state))
            {
                state = new HostServiceStatus { HostId = host.Id, Name = name, Status = report.Status, UpdatedAt = now };
                db.HostServiceStatuses.Add(state);
            }
            else
            {
                state.Status = report.Status;
                state.UpdatedAt = now;
            }

            var fingerprint = $"service:{name.ToUpperInvariant()}";
            if (!string.Equals(report.Status, "Running", StringComparison.OrdinalIgnoreCase))
                await OpenIncidentAsync(db, host, fingerprint, $"Windows 服务 {name} 未运行", "严重", "服务状态", report.Status, now, cancellationToken);
            else
                await ResolveIncidentAsync(db, host.Id, fingerprint, "Windows 服务已恢复运行。", now, cancellationToken);
        }
    }

    private static async Task ApplyMetricRulesAsync(MonitoringDbContext db, Host host, AgentIngestRequest request, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var rules = await db.AlertRules.Where(item => item.Enabled).ToListAsync(cancellationToken);
        var states = await db.MetricRuleStates.Where(item => item.HostId == host.Id).ToDictionaryAsync(item => item.AlertRuleId, cancellationToken);
        foreach (var rule in rules)
        {
            var evaluation = Evaluate(rule, request);
            if (evaluation is null) continue;
            if (!states.TryGetValue(rule.Id, out var state))
            {
                state = new MetricRuleState { HostId = host.Id, AlertRuleId = rule.Id, UpdatedAt = now };
                db.MetricRuleStates.Add(state);
                states[rule.Id] = state;
            }
            state.UpdatedAt = now;
            if (evaluation.Value.Failed)
            {
                state.ConsecutiveFailures++;
                state.ConsecutiveSuccesses = 0;
                if (!state.Firing && state.ConsecutiveFailures >= Math.Clamp(rule.TriggerCount, 1, 60))
                {
                    state.Firing = true;
                    await OpenIncidentAsync(db, host, $"metric:{rule.Id}", rule.Name, rule.Severity, rule.CheckItem, evaluation.Value.DisplayValue, now, cancellationToken);
                }
            }
            else if (evaluation.Value.Recovered)
            {
                state.ConsecutiveFailures = 0;
                state.ConsecutiveSuccesses++;
                if (state.Firing && state.ConsecutiveSuccesses >= Math.Clamp(rule.RecoveryCount, 1, 60))
                {
                    state.Firing = false;
                    await ResolveIncidentAsync(db, host.Id, $"metric:{rule.Id}", "指标已连续恢复到安全阈值。", now, cancellationToken);
                }
            }
            else
            {
                state.ConsecutiveFailures = 0;
                state.ConsecutiveSuccesses = 0;
            }
        }
    }

    private static (bool Failed, bool Recovered, string DisplayValue)? Evaluate(AlertRule rule, AgentIngestRequest request) => rule.CheckItem switch
    {
        "CPU 使用率" => (request.Cpu >= rule.CriticalThreshold, request.Cpu < rule.WarningThreshold, $"{request.Cpu:F1}%"),
        "内存使用率" => (request.Memory >= rule.CriticalThreshold, request.Memory < rule.WarningThreshold, $"{request.Memory:F1}%"),
        "磁盘可用空间" => (100 - request.Disk <= rule.CriticalThreshold, 100 - request.Disk > rule.WarningThreshold, $"{100 - request.Disk:F1}% 可用"),
        "网络延迟" => (request.Latency >= rule.CriticalThreshold, request.Latency < rule.WarningThreshold, $"{request.Latency:F1} ms"),
        _ => null
    };

    internal static async Task<Incident?> OpenIncidentAsync(MonitoringDbContext db, Host host, string fingerprint, string title, string severity, string signal, string value, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.HostId == host.Id && item.Fingerprint == fingerprint && item.ResolvedAt == null, cancellationToken);
        if (incident is not null)
        {
            incident.Value = value;
            incident.UpdatedAt = now;
            return incident;
        }
        incident = new Incident { HostId = host.Id, Host = host, Fingerprint = fingerprint, Title = title, Severity = severity, Signal = signal, Value = value, StartedAt = now, UpdatedAt = now };
        db.Incidents.Add(incident);
        db.AuditLogs.Add(new AuditLog { Actor = "monitor-worker", Action = "触发告警", Detail = $"{host.Name}: {title}", CreatedAt = now });
        return incident;
    }

    internal static async Task ResolveIncidentAsync(MonitoringDbContext db, int hostId, string fingerprint, string note, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.HostId == hostId && item.Fingerprint == fingerprint && item.ResolvedAt == null, cancellationToken);
        if (incident is null) return;
        incident.ResolvedAt = now;
        incident.UpdatedAt = now;
        incident.State = "已恢复";
        incident.Note = note;
    }
}

sealed class AgentHealthOptions
{
    public const string SectionName = "AgentHealth";
    public bool Enabled { get; set; } = true;
    public int ScanSeconds { get; set; } = 15;
    public int OfflineSeconds { get; set; } = 180;
}

sealed class AgentHealthWorker(IServiceScopeFactory scopeFactory, IOptions<AgentHealthOptions> configured, ILogger<AgentHealthWorker> logger) : BackgroundService
{
    private readonly AgentHealthOptions _options = configured.Value;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
                var now = DateTimeOffset.UtcNow;
                var cutoff = now.AddSeconds(-Math.Clamp(_options.OfflineSeconds, 60, 3600));
                var monitoredHostIds = await db.AgentCredentials.Select(item => item.HostId).ToListAsync(stoppingToken);
                var hosts = await db.Hosts.Where(item => monitoredHostIds.Contains(item.Id)).ToListAsync(stoppingToken);
                foreach (var host in hosts)
                {
                    if (host.LastHeartbeatAt < cutoff)
                    {
                        await AgentTelemetry.OpenIncidentAsync(db, host, "agent:offline", "Agent 上报中断", "严重", "Agent 心跳", $"超过 {_options.OfflineSeconds} 秒未上报", now, stoppingToken);
                        host.Status = "失联";
                    }
                }
                await db.SaveChangesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Agent health scan failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(_options.ScanSeconds, 5, 300)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
