using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

sealed class ProbeWorkerOptions
{
    public const string SectionName = "ProbeWorker";
    public bool Enabled { get; set; } = true;
    public int MaxConcurrency { get; set; } = 8;
    public int LoopDelaySeconds { get; set; } = 1;
    public int MaxBackoffSeconds { get; set; } = 900;
    public int JitterMilliseconds { get; set; } = 500;
}

sealed record ProbeRunResult(bool Succeeded, string? Error)
{
    public static ProbeRunResult Success() => new(true, null);
    public static ProbeRunResult Failure(string error) => new(false, error.Length > 500 ? error[..500] : error);
}

interface IProbeExecutor
{
    Task<ProbeRunResult> ExecuteAsync(ProbeDefinition probe, CancellationToken cancellationToken);
}

sealed class NetworkProbeExecutor(IHttpClientFactory httpClientFactory) : IProbeExecutor
{
    public async Task<ProbeRunResult> ExecuteAsync(ProbeDefinition probe, CancellationToken cancellationToken)
    {
        try
        {
            return probe.Type switch
            {
                ProbeType.Icmp => await IcmpAsync(probe, cancellationToken),
                ProbeType.Tcp => await TcpAsync(probe, cancellationToken),
                ProbeType.Http => await HttpAsync(probe, cancellationToken),
                _ => ProbeRunResult.Failure("不支持的探测类型。")
            };
        }
        catch (OperationCanceledException)
        {
            return ProbeRunResult.Failure("探测超时或已取消。");
        }
        catch (Exception exception)
        {
            return ProbeRunResult.Failure(exception.Message);
        }
    }

    private static async Task<ProbeRunResult> IcmpAsync(ProbeDefinition probe, CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        var reply = await ping.SendPingAsync(probe.Target, probe.TimeoutMilliseconds).WaitAsync(cancellationToken);
        return reply.Status == IPStatus.Success ? ProbeRunResult.Success() : ProbeRunResult.Failure($"ICMP {reply.Status}");
    }

    private static async Task<ProbeRunResult> TcpAsync(ProbeDefinition probe, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(probe.Target, probe.Port!.Value, cancellationToken);
        return ProbeRunResult.Success();
    }

    private async Task<ProbeRunResult> HttpAsync(ProbeDefinition probe, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, probe.Target);
        using var response = await httpClientFactory.CreateClient("probe").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var expected = probe.ExpectedStatus ?? 200;
        return (int)response.StatusCode == expected
            ? ProbeRunResult.Success()
            : ProbeRunResult.Failure($"HTTP {(int)response.StatusCode}，期望 {expected}");
    }
}

enum ProbeTransition { None, Opened, Recovered }

static class ProbeStateMachine
{
    public static ProbeTransition Apply(ProbeDefinition probe, ProbeRunResult result, DateTimeOffset now)
    {
        probe.LastCheckedAt = now;
        probe.UpdatedAt = now;
        if (result.Succeeded)
        {
            probe.LastSuccessAt = now;
            probe.LastError = null;
            probe.ConsecutiveFailures = 0;
            probe.BackoffLevel = 0;
            probe.ConsecutiveSuccesses++;
            if (probe.Status == ProbeStatus.Failing && probe.ConsecutiveSuccesses >= probe.RecoveryThreshold)
            {
                probe.Status = ProbeStatus.Healthy;
                return ProbeTransition.Recovered;
            }
            if (probe.Status == ProbeStatus.Unknown) probe.Status = ProbeStatus.Healthy;
            return ProbeTransition.None;
        }

        probe.LastError = result.Error;
        probe.ConsecutiveSuccesses = 0;
        probe.ConsecutiveFailures++;
        probe.BackoffLevel = Math.Min(probe.BackoffLevel + 1, 10);
        if (probe.Status != ProbeStatus.Failing && probe.ConsecutiveFailures >= probe.FailureThreshold)
        {
            probe.Status = ProbeStatus.Failing;
            return ProbeTransition.Opened;
        }
        return ProbeTransition.None;
    }

    public static DateTimeOffset NextRunAt(ProbeDefinition probe, ProbeWorkerOptions options, DateTimeOffset now)
    {
        var multiplier = probe.Status == ProbeStatus.Failing ? 1 << Math.Min(probe.BackoffLevel, 10) : 1;
        var seconds = Math.Min(options.MaxBackoffSeconds, probe.IntervalSeconds * multiplier);
        var jitter = options.JitterMilliseconds <= 0 ? 0 : Random.Shared.Next(0, options.JitterMilliseconds + 1);
        return now.AddSeconds(seconds).AddMilliseconds(jitter);
    }
}

static class ProbeFingerprint
{
    public static string Create(ProbeRequest request)
    {
        var type = request.Type.Trim().ToLowerInvariant();
        var target = type == ProbeType.Http ? request.Target.Trim() : request.Target.Trim().ToUpperInvariant();
        return $"probe:{type}:{target}:{request.Port?.ToString() ?? "-"}:{request.ExpectedStatus?.ToString() ?? "-"}";
    }
}

sealed class ProbeIncidentService
{
    public static async Task ResolveForConfigurationChangeAsync(MonitoringDbContext db, ProbeDefinition probe, string note, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var incidents = await db.Incidents.Where(item => item.HostId == probe.HostId && item.Fingerprint == probe.Fingerprint && item.ResolvedAt == null).ToListAsync(cancellationToken);
        foreach (var incident in incidents)
        {
            incident.ResolvedAt = now;
            incident.UpdatedAt = now;
            incident.State = "已关闭";
            incident.Note = note;
        }
    }

    public static async Task ApplyTransitionAsync(MonitoringDbContext db, ProbeDefinition probe, ProbeTransition transition, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (transition == ProbeTransition.None) return;
        var host = probe.Host ?? await db.Hosts.FindAsync([probe.HostId], cancellationToken);
        if (host is null) return;
        if (transition == ProbeTransition.Opened)
        {
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.HostId == probe.HostId && item.Fingerprint == probe.Fingerprint && item.ResolvedAt == null, cancellationToken);
            if (incident is null)
            {
                incident = new Incident
                {
                    HostId = host.Id,
                    Fingerprint = probe.Fingerprint,
                    Title = $"{probe.Name} 探测失败",
                    Severity = "严重",
                    Signal = $"{probe.Type.ToUpperInvariant()} 探测",
                    Value = probe.LastError ?? "探测失败",
                    StartedAt = now,
                    UpdatedAt = now
                };
                db.Incidents.Add(incident);
                db.AuditLogs.Add(new AuditLog { Actor = "probe-worker", Action = "探测触发告警", Detail = $"{host.Name}: {probe.Name} ({probe.LastError})", CreatedAt = now });
            }
            if (host.Status != IncidentState.Maintenance) host.Status = "网络异常";
        }
        else
        {
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.HostId == probe.HostId && item.Fingerprint == probe.Fingerprint && item.ResolvedAt == null, cancellationToken);
            if (incident is not null)
            {
                incident.ResolvedAt = now;
                incident.UpdatedAt = now;
                incident.State = "已恢复";
                incident.Note = "探测连续成功，系统自动恢复。";
                db.AuditLogs.Add(new AuditLog { Actor = "probe-worker", Action = "探测恢复", Detail = $"{host.Name}: {probe.Name}", CreatedAt = now });
            }
            var anotherProbeFailing = await db.ProbeDefinitions.AnyAsync(item => item.HostId == host.Id && item.Id != probe.Id && item.Enabled && item.Status == ProbeStatus.Failing, cancellationToken);
            if (host.Status == "网络异常" && !anotherProbeFailing) host.Status = "健康";
        }
    }
}

sealed class ProbeWorker(IServiceScopeFactory scopeFactory, IProbeExecutor executor, IOptions<ProbeWorkerOptions> options, ILogger<ProbeWorker> logger) : BackgroundService
{
    private readonly ProbeWorkerOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            logger.LogInformation("Probe worker is disabled by configuration.");
            return;
        }
        var concurrency = Math.Clamp(_options.MaxConcurrency, 1, 64);
        using var limiter = new SemaphoreSlim(concurrency, concurrency);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var due = await GetDueAsync(stoppingToken);
                await Task.WhenAll(due.Select(async id =>
                {
                    await limiter.WaitAsync(stoppingToken);
                    try { await RunProbeAsync(id, stoppingToken); }
                    finally { limiter.Release(); }
                }));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Probe worker iteration failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(_options.LoopDelaySeconds, 1, 30)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    private async Task<List<int>> GetDueAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var now = DateTimeOffset.UtcNow;
        return await scope.ServiceProvider.GetRequiredService<MonitoringDbContext>().ProbeDefinitions.AsNoTracking()
            .Where(probe => probe.Enabled && (probe.NextRunAt == null || probe.NextRunAt <= now))
            .OrderBy(probe => probe.NextRunAt).Select(probe => probe.Id).Take(256).ToListAsync(cancellationToken);
    }

    private async Task RunProbeAsync(int probeId, CancellationToken stoppingToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
        var probe = await db.ProbeDefinitions.Include(item => item.Host).SingleOrDefaultAsync(item => item.Id == probeId, stoppingToken);
        if (probe is null || !probe.Enabled || (probe.NextRunAt is not null && probe.NextRunAt > DateTimeOffset.UtcNow)) return;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeout.CancelAfter(probe.TimeoutMilliseconds);
        var result = await executor.ExecuteAsync(probe, timeout.Token);
        var now = DateTimeOffset.UtcNow;
        var transition = ProbeStateMachine.Apply(probe, result, now);
        probe.NextRunAt = ProbeStateMachine.NextRunAt(probe, _options, now);
        await ProbeIncidentService.ApplyTransitionAsync(db, probe, transition, now, stoppingToken);
        await db.SaveChangesAsync(stoppingToken);
    }
}
