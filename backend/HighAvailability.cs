using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

sealed class HaOptions
{
    public const string SectionName = "HighAvailability";
    public bool Enabled { get; set; }
    public string ClusterId { get; set; } = "monitoring-platform";
    public string NodeId { get; set; } = Environment.MachineName;
    public string ConfiguredRole { get; set; } = "passive";
    public string WitnessUrl { get; set; } = "";
    public string? WitnessBearerToken { get; set; }
    public string? PublicUrl { get; set; }
    public string? PeerNodeId { get; set; }
    public string? PeerPublicUrl { get; set; }
    public string? PeerReadyUrl { get; set; }
    public int LeaseTtlSeconds { get; set; } = 30;
    public int RenewSeconds { get; set; } = 10;
    public int WitnessTimeoutSeconds { get; set; } = 5;
    public int LeaseSafetySeconds { get; set; } = 2;
    public string? ReplicationDirectory { get; set; }
    public string? StandbyReplicaPath { get; set; }
    public int ReplicationSeconds { get; set; } = 300;
}

sealed record WitnessLeaseRequest(string ClusterId, string Owner, int TtlSeconds, long? PreviousEpoch);
sealed record WitnessLeaseResponse(string Owner, long Epoch, DateTimeOffset ExpiresAt);
sealed record HaLeaseGrant(string Owner, long Epoch, DateTimeOffset ExpiresAt);

interface IHaLeaseClient
{
    Task<HaLeaseGrant?> AcquireOrRenewAsync(HaOptions options, long? previousEpoch, CancellationToken cancellationToken);
}

sealed class HttpWitnessLeaseClient(IHttpClientFactory httpClientFactory) : IHaLeaseClient
{
    public async Task<HaLeaseGrant?> AcquireOrRenewAsync(HaOptions options, long? previousEpoch, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(options.WitnessUrl, UriKind.Absolute, out var baseUri) || baseUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("WitnessUrl 必须配置为 HTTPS 地址。");
        var endpoint = new Uri(new Uri($"{baseUri.AbsoluteUri.TrimEnd('/')}/"), $"v1/leases/{Uri.EscapeDataString(options.ClusterId)}");
        using var request = new HttpRequestMessage(HttpMethod.Put, endpoint)
        {
            Content = JsonContent.Create(new WitnessLeaseRequest(options.ClusterId, options.NodeId, Math.Clamp(options.LeaseTtlSeconds, 5, 300), previousEpoch))
        };
        if (!string.IsNullOrWhiteSpace(options.WitnessBearerToken))
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", options.WitnessBearerToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(options.WitnessTimeoutSeconds, 1, 30)));
        using var response = await httpClientFactory.CreateClient("ha-witness").SendAsync(request, timeout.Token);
        if (!response.IsSuccessStatusCode) return null;
        var lease = await response.Content.ReadFromJsonAsync<WitnessLeaseResponse>(timeout.Token);
        return lease is null ? null : new HaLeaseGrant(lease.Owner, lease.Epoch, lease.ExpiresAt);
    }
}

sealed class HaLeaseState
{
    private readonly object _gate = new();
    private readonly HaOptions _options;
    private long _highestEpoch;
    private HaLeaseGrant? _grant;
    private string _message = "HA 未启用，按单节点运行。";

    public HaLeaseState(IOptions<HaOptions> configuredOptions)
    {
        _options = configuredOptions.Value;
        if (string.IsNullOrWhiteSpace(_options.NodeId)) _options.NodeId = Environment.MachineName;
        _options.ConfiguredRole = string.Equals(_options.ConfiguredRole, "active", StringComparison.OrdinalIgnoreCase) ? "active" : "passive";
    }

    public HaOptions Options => _options;

    public bool TryApply(HaLeaseGrant grant, DateTimeOffset now)
    {
        lock (_gate)
        {
            // Never let an untrusted or clock-skewed witness response extend a local lease beyond the requested TTL.
            var localExpiry = now.AddSeconds(Math.Clamp(_options.LeaseTtlSeconds, 5, 300));
            if (grant.ExpiresAt > localExpiry) grant = grant with { ExpiresAt = localExpiry };
            if (!_options.Enabled || !string.Equals(grant.Owner, _options.NodeId, StringComparison.Ordinal) || grant.Epoch <= 0 || grant.ExpiresAt <= now)
            {
                _highestEpoch = Math.Max(_highestEpoch, grant.Epoch);
                _grant = null;
                _message = "witness 未向本节点授予有效租约。";
                return false;
            }
            if (grant.Epoch < _highestEpoch)
            {
                _grant = null;
                _message = "拒绝过期 fencing token。";
                return false;
            }
            _highestEpoch = grant.Epoch;
            _grant = grant;
            _message = "持有 witness 租约，允许通知与复制发布。";
            return true;
        }
    }

    public void LoseLease(string message)
    {
        lock (_gate)
        {
            _grant = null;
            _message = message;
        }
    }

    public bool CanWrite(long epoch, DateTimeOffset now)
    {
        lock (_gate)
            return _options.Enabled && _grant is { } grant && grant.Epoch == epoch && grant.ExpiresAt > now && string.Equals(grant.Owner, _options.NodeId, StringComparison.Ordinal);
    }

    public bool HoldsValidLease(DateTimeOffset now)
    {
        lock (_gate) return _grant is { } grant && CanWriteUnsafe(grant.Epoch, now);
    }

    public bool CanMutate(DateTimeOffset now)
    {
        lock (_gate) return !_options.Enabled || (_grant is { } grant && CanWriteUnsafe(grant.Epoch, now.AddSeconds(SafetySeconds())));
    }

    public bool CanCommit(DateTimeOffset now) => CanMutate(now);

    public long? CurrentEpoch(DateTimeOffset now)
    {
        lock (_gate) return _grant is { } grant && CanWriteUnsafe(grant.Epoch, now) ? grant.Epoch : null;
    }

    public HaStatusDto Status(DateTimeOffset now)
    {
        lock (_gate)
        {
            var active = _grant is { } grant && CanWriteUnsafe(grant.Epoch, now);
            return new HaStatusDto(_options.Enabled, _options.Enabled ? (active ? "active" : "passive") : "single-node", _options.NodeId,
                _options.ConfiguredRole, active, active ? _grant!.Epoch : null, active ? _grant!.ExpiresAt : null,
                _options.WitnessUrl, _message);
        }
    }

    private bool CanWriteUnsafe(long epoch, DateTimeOffset now) => _options.Enabled && _grant is { } grant && grant.Epoch == epoch && grant.ExpiresAt > now && string.Equals(grant.Owner, _options.NodeId, StringComparison.Ordinal);

    private int SafetySeconds() => Math.Clamp(_options.LeaseSafetySeconds, 1, Math.Max(1, Math.Clamp(_options.LeaseTtlSeconds, 5, 300) / 3));
}

sealed class HaLeaseWorker(IHaLeaseClient client, HaLeaseState state, ILogger<HaLeaseWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = state.Options;
        if (!options.Enabled) return;
        if (!string.Equals(options.ConfiguredRole, "active", StringComparison.OrdinalIgnoreCase))
        {
            state.LoseLease("节点配置为 passive，不参与 witness 租约竞争。");
            return;
        }
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var grant = await client.AcquireOrRenewAsync(options, state.CurrentEpoch(DateTimeOffset.UtcNow), stoppingToken);
                if (grant is null) state.LoseLease("witness 拒绝租约或不可达，已停止通知与复制发布。");
                else state.TryApply(grant, DateTimeOffset.UtcNow);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                state.LoseLease("witness 请求失败，已停止通知与复制发布。");
                logger.LogWarning(exception, "HA witness lease request failed.");
            }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(options.RenewSeconds, 2, Math.Clamp(options.LeaseTtlSeconds, 5, 300) - 1)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
        state.LoseLease("节点停止，租约不再用于写入。");
    }
}

sealed record ReplicationManifest(long Sequence, long Epoch, string PreviousHash, string ArtifactFileName, string ArtifactSha256, DateTimeOffset CreatedAt, string Hash)
{
    public static string CalculateHash(long sequence, long epoch, string previousHash, string artifactFileName, string artifactSha256, DateTimeOffset createdAt)
    {
        var canonical = $"{sequence}|{epoch}|{previousHash}|{artifactFileName}|{artifactSha256}|{createdAt:O}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public bool IsValid() => string.Equals(Hash, CalculateHash(Sequence, Epoch, PreviousHash, ArtifactFileName, ArtifactSha256, CreatedAt), StringComparison.OrdinalIgnoreCase);
}

sealed record ReplicationCheckpoint(long Sequence, long Epoch, string Hash);

static class HaReplication
{
    private const string ManifestsDirectory = "manifests";
    private const string ArtifactsDirectory = "artifacts";
    private const string CheckpointFile = "ha-replication-checkpoint.json";

    public static async Task<ReplicationManifest?> PublishAsync(MonitoringDbContext db, DataMaintenanceOptions maintenance, HaLeaseState lease, IWebHostEnvironment environment, ILogger logger, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var epoch = lease.CurrentEpoch(now);
        if (epoch is null || !lease.CanWrite(epoch.Value, now)) return null;
        var root = ReplicationRoot(lease.Options, environment);
        if (root is null) return null;
        var backup = await DataMaintenanceWorker.BackupNowAsync(db, maintenance, environment, logger, cancellationToken);
        if (!lease.CanWrite(epoch.Value, DateTimeOffset.UtcNow)) return null;
        var source = Path.Combine(DataMaintenanceWorker.ResolveBackupDirectory(maintenance, environment), backup.FileName);
        var manifests = await ReadManifestsAsync(root, cancellationToken);
        var previous = manifests.LastOrDefault();
        var sequence = previous is null ? 1 : previous.Sequence + 1;
        var artifactName = $"snapshot-e{epoch.Value}-s{sequence:D20}.db";
        var artifactDirectory = Path.Combine(root, ArtifactsDirectory);
        Directory.CreateDirectory(artifactDirectory);
        var artifactPath = Path.Combine(artifactDirectory, artifactName);
        var temporaryPath = $"{artifactPath}.{Guid.NewGuid():N}.tmp";
        await using (var input = File.OpenRead(source))
        await using (var output = File.Create(temporaryPath)) await input.CopyToAsync(output, cancellationToken);
        if (!lease.CanWrite(epoch.Value, DateTimeOffset.UtcNow)) { File.Delete(temporaryPath); return null; }
        File.Move(temporaryPath, artifactPath);
        var createdAt = DateTimeOffset.UtcNow;
        var hash = ReplicationManifest.CalculateHash(sequence, epoch.Value, previous?.Hash ?? "", artifactName, backup.Sha256, createdAt);
        var manifest = new ReplicationManifest(sequence, epoch.Value, previous?.Hash ?? "", artifactName, backup.Sha256, createdAt, hash);
        if (!lease.CanWrite(epoch.Value, DateTimeOffset.UtcNow)) return null;
        var manifestDirectory = Path.Combine(root, ManifestsDirectory);
        Directory.CreateDirectory(manifestDirectory);
        var manifestPath = Path.Combine(manifestDirectory, $"{sequence:D20}.json");
        await WriteJsonAtomicallyAsync(manifestPath, manifest, cancellationToken, overwrite: false);
        return manifest;
    }

    public static async Task<ReplicationManifest?> StageLatestAsync(HaLeaseState lease, IWebHostEnvironment environment, CancellationToken cancellationToken)
    {
        if (lease.HoldsValidLease(DateTimeOffset.UtcNow)) return null;
        var root = ReplicationRoot(lease.Options, environment);
        if (root is null) return null;
        var manifests = await ReadManifestsAsync(root, cancellationToken);
        ValidateChain(manifests);
        var checkpoint = await ReadCheckpointAsync(environment, cancellationToken) ?? new ReplicationCheckpoint(0, 0, "");
        if (checkpoint.Sequence > 0)
        {
            var checkpointManifest = manifests.SingleOrDefault(item => item.Sequence == checkpoint.Sequence);
            if (checkpointManifest is null || checkpointManifest.Epoch != checkpoint.Epoch || !string.Equals(checkpointManifest.Hash, checkpoint.Hash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("本地复制检查点与已验证清单链不一致。");
        }
        var next = manifests.LastOrDefault(item => item.Sequence > checkpoint.Sequence && item.Epoch >= checkpoint.Epoch);
        if (next is null) return null;
        var artifactPath = Path.Combine(root, ArtifactsDirectory, next.ArtifactFileName);
        if (!File.Exists(artifactPath) || !string.Equals(await Sha256Async(artifactPath, cancellationToken), next.ArtifactSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("复制快照校验失败。");
        var destination = ResolveStandbyReplicaPath(lease.Options, environment);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = $"{destination}.{Guid.NewGuid():N}.tmp";
        await using (var input = File.OpenRead(artifactPath))
        await using (var output = File.Create(temporary)) await input.CopyToAsync(output, cancellationToken);
        if (lease.HoldsValidLease(DateTimeOffset.UtcNow)) { File.Delete(temporary); return null; }
        File.Move(temporary, destination, true);
        await WriteJsonAtomicallyAsync(Path.Combine(environment.ContentRootPath, "Data", CheckpointFile), new ReplicationCheckpoint(next.Sequence, next.Epoch, next.Hash), cancellationToken);
        return next;
    }

    public static void ValidateChain(IReadOnlyList<ReplicationManifest> manifests)
    {
        long sequence = 0;
        long epoch = 0;
        var previousHash = "";
        foreach (var manifest in manifests)
        {
            if (manifest.Sequence != sequence + 1 || manifest.Epoch < epoch || !manifest.IsValid() || !string.Equals(manifest.PreviousHash, previousHash, StringComparison.Ordinal) || Path.GetFileName(manifest.ArtifactFileName) != manifest.ArtifactFileName)
                throw new InvalidDataException("复制清单链无效或出现旧 epoch。");
            sequence = manifest.Sequence;
            epoch = manifest.Epoch;
            previousHash = manifest.Hash;
        }
    }

    internal static string? ReplicationRoot(HaOptions options, IWebHostEnvironment environment) => string.IsNullOrWhiteSpace(options.ReplicationDirectory) ? null : Path.GetFullPath(options.ReplicationDirectory);
    internal static string ResolveStandbyReplicaPath(HaOptions options, IWebHostEnvironment environment) => Path.GetFullPath(string.IsNullOrWhiteSpace(options.StandbyReplicaPath) ? Path.Combine(environment.ContentRootPath, "Data", "standby-replica.db") : options.StandbyReplicaPath);

    private static async Task<List<ReplicationManifest>> ReadManifestsAsync(string root, CancellationToken cancellationToken)
    {
        var directory = Path.Combine(root, ManifestsDirectory);
        if (!Directory.Exists(directory)) return [];
        var manifests = new List<ReplicationManifest>();
        foreach (var path in Directory.EnumerateFiles(directory, "*.json").OrderBy(path => path, StringComparer.Ordinal))
        {
            await using var stream = File.OpenRead(path);
            manifests.Add((await JsonSerializer.DeserializeAsync<ReplicationManifest>(stream, cancellationToken: cancellationToken)) ?? throw new InvalidDataException("复制清单为空。"));
        }
        return manifests;
    }

    private static async Task<ReplicationCheckpoint?> ReadCheckpointAsync(IWebHostEnvironment environment, CancellationToken cancellationToken)
    {
        var path = Path.Combine(environment.ContentRootPath, "Data", CheckpointFile);
        if (!File.Exists(path)) return null;
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<ReplicationCheckpoint>(stream, cancellationToken: cancellationToken);
    }

    private static async Task WriteJsonAtomicallyAsync<T>(string path, T value, CancellationToken cancellationToken, bool overwrite = true)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        await using (var stream = File.Create(temporary)) await JsonSerializer.SerializeAsync(stream, value, cancellationToken: cancellationToken);
        File.Move(temporary, path, overwrite);
    }

    private static async Task<string> Sha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
    }
}

sealed class HaReplicationWorker(IServiceScopeFactory scopeFactory, IOptions<DataMaintenanceOptions> maintenance, HaLeaseState lease, IWebHostEnvironment environment, ILogger<HaReplicationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!lease.Options.Enabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
                if (lease.HoldsValidLease(DateTimeOffset.UtcNow)) await HaReplication.PublishAsync(db, maintenance.Value, lease, environment, logger, stoppingToken);
                else await HaReplication.StageLatestAsync(lease, environment, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogWarning(exception, "HA replication iteration failed."); }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(lease.Options.ReplicationSeconds, 30, 86400)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
