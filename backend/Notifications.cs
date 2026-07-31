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
    HaLeaseState haLease,
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
                if (haLease.Options.Enabled && !haLease.HoldsValidLease(DateTimeOffset.UtcNow))
                {
                    logger.LogDebug("Notification worker is paused because this node does not hold a valid witness lease.");
                    await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(_options.ScanSeconds, 2, 300)), stoppingToken);
                    continue;
                }
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
        var leaseEpoch = haLease.Options.Enabled ? haLease.CurrentEpoch(now) : null;
        if (haLease.Options.Enabled && leaseEpoch is null) return;
        var maxAttempts = Math.Clamp(_options.MaxAttempts, 1, 100);
        var candidates = await db.NotificationDeliveryStates
            .Where(item => item.Attempts < maxAttempts)
            .ToListAsync(cancellationToken);
        var due = candidates
            .Where(item => item.NextAttemptAt <= now)
            .OrderBy(item => item.NextAttemptAt)
            .Take(20)
            .ToList();
        foreach (var state in due)
        {
            if (haLease.Options.Enabled && (leaseEpoch is null || !haLease.CanWrite(leaseEpoch.Value, DateTimeOffset.UtcNow) || !haLease.CanCommit(DateTimeOffset.UtcNow)))
                throw new InvalidOperationException("Witness lease was lost before notification dispatch.");
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
            // Persist an ambiguous in-flight state before the external side effect. On lease loss or crash,
            // operators reconcile this state instead of automatically risking a duplicate SMS.
            state.Status = "发送中";
            state.NextAttemptAt = DateTimeOffset.MaxValue;
            await db.SaveChangesAsync(cancellationToken);
            var result = await sender.SendAsync(phoneNumbers, parameters);
            if (haLease.Options.Enabled && (leaseEpoch is null || !haLease.CanWrite(leaseEpoch.Value, DateTimeOffset.UtcNow) || !haLease.CanCommit(DateTimeOffset.UtcNow)))
                throw new InvalidOperationException("Witness lease was lost while notification delivery was in flight; delivery remains ambiguous and will not be retried automatically.");
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
        var inAppPolicies = policies.Where(item => item.Channel == NotificationChannel.InApp).ToList();
        var recipients = await db.LocalUsers.Where(item => item.Enabled && (item.Role == SecurityRoles.Admin || item.Role == SecurityRoles.Operator))
            .Select(item => new { item.Id }).ToListAsync(cancellationToken);
        var inAppExisting = (await db.InAppNotifications.Select(item => new { item.IncidentId, item.NotificationPolicyId, item.UserId }).ToListAsync(cancellationToken))
            .Select(item => (item.IncidentId, item.NotificationPolicyId, item.UserId)).ToHashSet();
        foreach (var incident in incidents)
        {
            foreach (var policy in policies.Where(policy => policy.Channel == NotificationChannel.Sms && Matches(policy, incident)))
            {
                if (!existing.Add((incident.Id, policy.Id))) continue;
                db.NotificationDeliveryStates.Add(new NotificationDeliveryState
                {
                    IncidentId = incident.Id,
                    NotificationPolicyId = policy.Id,
                    NextAttemptAt = now
                });
            }
            foreach (var policy in inAppPolicies.Where(policy => Matches(policy, incident)))
            foreach (var recipient in recipients)
            {
                if (!inAppExisting.Add((incident.Id, policy.Id, recipient.Id))) continue;
                var hostName = incident.Host?.Name ?? "未知主机";
                db.InAppNotifications.Add(new InAppNotification
                {
                    IncidentId = incident.Id,
                    NotificationPolicyId = policy.Id,
                    UserId = recipient.Id,
                    PolicyName = policy.Name,
                    HostName = hostName,
                    Title = $"{hostName}: {incident.Title}",
                    Content = $"{incident.Severity}告警，信号：{incident.Signal}，当前值：{incident.Value}。",
                    Severity = incident.Severity,
                    CreatedAt = now
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
