using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

sealed class NotificationContactOptions
{
    public const string SectionName = "NotificationContacts";
    public Dictionary<string, string[]> Groups { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

sealed class NotificationWorkerOptions
{
    public const string SectionName = "NotificationWorker";
    public bool Enabled { get; set; } = true;
    public int ScanSeconds { get; set; } = 5;
    public int MaxAttempts { get; set; } = 10;
}

sealed class NotificationWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<NotificationContactOptions> configuredContacts,
    IOptions<NotificationWorkerOptions> configuredWorker,
    ILogger<NotificationWorker> logger) : BackgroundService
{
    private readonly NotificationContactOptions _contacts = configuredContacts.Value;
    private readonly NotificationWorkerOptions _options = configuredWorker.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using (var scope = scopeFactory.CreateAsyncScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
                    await NotificationPlanner.EnsureStatesAsync(db, DateTimeOffset.UtcNow, stoppingToken);
                }
                await SendDueAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Notification worker iteration failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(_options.ScanSeconds, 2, 300)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task SendDueAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
        var sender = scope.ServiceProvider.GetRequiredService<SmsSender>();
        var now = DateTimeOffset.UtcNow;
        var due = await db.NotificationDeliveryStates
            .Where(item => item.NextAttemptAt <= now && item.Attempts < Math.Clamp(_options.MaxAttempts, 1, 100))
            .OrderBy(item => item.NextAttemptAt).Take(20).ToListAsync(cancellationToken);
        foreach (var state in due)
        {
            var incident = await db.Incidents.Include(item => item.Host).SingleOrDefaultAsync(item => item.Id == state.IncidentId, cancellationToken);
            var policy = await db.NotificationPolicies.FindAsync([state.NotificationPolicyId], cancellationToken);
            if (incident?.Host is null || policy is null || !policy.Enabled || incident.ResolvedAt is not null || incident.State != IncidentState.Open)
            {
                state.Status = "已停止";
                state.NextAttemptAt = DateTimeOffset.MaxValue;
                continue;
            }

            state.Attempts++;
            state.LastAttemptAt = now;
            if (!_contacts.Groups.TryGetValue(policy.ContactGroup, out var phoneNumbers) || phoneNumbers.Length == 0)
            {
                state.Status = "发送失败";
                state.LastError = "联系人组未配置。";
                state.NextAttemptAt = now.AddMinutes(15);
                continue;
            }

            var parameters = new[] { incident.Host.Name, incident.Title, incident.Value, incident.StartedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") };
            var result = await sender.SendAsync(phoneNumbers, parameters);
            if (result.Sent)
            {
                state.Status = "已发送";
                state.LastSentAt = now;
                state.RequestId = result.RequestId;
                state.LastError = null;
                state.NextAttemptAt = now.AddMinutes(Math.Clamp(policy.RepeatMinutes, 5, 1440));
                db.AuditLogs.Add(new AuditLog { Actor = "notification-worker", Action = "发送告警短信", Detail = $"{incident.Host.Name}: {incident.Title} -> {policy.ContactGroup}", CreatedAt = now });
            }
            else
            {
                state.Status = "发送失败";
                state.LastError = result.Error is { Length: > 500 } ? result.Error[..500] : result.Error;
                state.NextAttemptAt = now.AddMinutes(Math.Min(15, 1 << Math.Min(state.Attempts - 1, 4)));
            }
        }
        await db.SaveChangesAsync(cancellationToken);
    }

}

static class NotificationPlanner
{
    public static async Task EnsureStatesAsync(MonitoringDbContext db, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var incidents = await db.Incidents.Include(item => item.Host)
            .Where(item => item.ResolvedAt == null && item.State == IncidentState.Open).ToListAsync(cancellationToken);
        var policies = await db.NotificationPolicies.Where(item => item.Enabled).ToListAsync(cancellationToken);
        var existing = (await db.NotificationDeliveryStates.Select(item => new { item.IncidentId, item.NotificationPolicyId }).ToListAsync(cancellationToken))
            .Select(item => (item.IncidentId, item.NotificationPolicyId)).ToHashSet();
        foreach (var incident in incidents)
        {
            foreach (var policy in policies.Where(policy => Matches(policy, incident)))
            {
                if (!existing.Add((incident.Id, policy.Id))) continue;
                db.NotificationDeliveryStates.Add(new NotificationDeliveryState
                {
                    IncidentId = incident.Id,
                    NotificationPolicyId = policy.Id,
                    NextAttemptAt = now
                });
            }
        }
        await db.SaveChangesAsync(cancellationToken);
    }

    internal static bool Matches(NotificationPolicy policy, Incident incident)
    {
        if (!string.Equals(policy.Severity, incident.Severity, StringComparison.OrdinalIgnoreCase)) return false;
        var group = policy.ServerGroup.Trim();
        return group is "*" or "全部服务器" or "所有服务器" || string.Equals(group, incident.Host?.Group, StringComparison.OrdinalIgnoreCase);
    }
}
