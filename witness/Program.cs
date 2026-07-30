using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(options => options.ServiceName = "MonitoringPlatformWitness");
builder.Services.Configure<WitnessOptions>(builder.Configuration.GetSection(WitnessOptions.SectionName));
builder.Services.AddSingleton<LeaseStore>();

var app = builder.Build();
app.UseHttpsRedirection();

app.MapGet("/health", () => Results.Ok(new { status = "healthy", utc = DateTimeOffset.UtcNow }));
app.MapPut("/v1/leases/{clusterId}", async (string clusterId, WitnessLeaseRequest request, HttpContext context,
    LeaseStore store, IOptions<WitnessOptions> configured, CancellationToken cancellationToken) =>
{
    var options = configured.Value;
    if (!WitnessValidation.ValidIdentifier(clusterId) || !string.Equals(clusterId, request.ClusterId, StringComparison.Ordinal) ||
        !WitnessValidation.ValidIdentifier(request.Owner) || request.TtlSeconds is < 5 or > 300)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["lease"] = ["租约参数无效。"] });
    if (!options.NodeTokens.TryGetValue(request.Owner, out var expectedToken) ||
        !WitnessValidation.ValidBearer(context.Request.Headers.Authorization.ToString(), expectedToken))
        return Results.Unauthorized();

    var result = await store.AcquireOrRenewAsync(request, DateTimeOffset.UtcNow, cancellationToken);
    return result.Granted
        ? Results.Ok(new WitnessLeaseResponse(result.Lease!.Owner, result.Lease.Epoch, result.Lease.ExpiresAt))
        : Results.Conflict(new { error = result.Error, owner = result.Lease?.Owner, epoch = result.Lease?.Epoch, expiresAt = result.Lease?.ExpiresAt });
});

app.Run();

public partial class Program;

sealed class WitnessOptions
{
    public const string SectionName = "Witness";
    public string DataPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "Data", "leases.json");
    public Dictionary<string, string> NodeTokens { get; set; } = new(StringComparer.Ordinal);
}

sealed record WitnessLeaseRequest(string ClusterId, string Owner, int TtlSeconds, long? PreviousEpoch);
sealed record WitnessLeaseResponse(string Owner, long Epoch, DateTimeOffset ExpiresAt);
sealed record StoredLease(string Owner, long Epoch, DateTimeOffset ExpiresAt);
sealed record LeaseDecision(bool Granted, StoredLease? Lease, string? Error);

static class WitnessValidation
{
    public static bool ValidIdentifier(string? value) => value is { Length: >= 1 and <= 64 } && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    public static bool ValidBearer(string authorization, string expectedToken)
    {
        if (string.IsNullOrWhiteSpace(expectedToken) || expectedToken.Length < 32 || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        var supplied = authorization[7..].Trim();
        if (supplied.Length is < 32 or > 256) return false;
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expectedToken));
        var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(supplied));
        return CryptographicOperations.FixedTimeEquals(expectedHash, suppliedHash);
    }
}

sealed class LeaseStore(IOptions<WitnessOptions> configured)
{
    private readonly string _path = Path.GetFullPath(configured.Value.DataPath);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<LeaseDecision> AcquireOrRenewAsync(WitnessLeaseRequest request, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var leases = await ReadAsync(cancellationToken);
            leases.TryGetValue(request.ClusterId, out var current);
            if (current is not null && current.ExpiresAt > now)
            {
                if (!string.Equals(current.Owner, request.Owner, StringComparison.Ordinal))
                    return new LeaseDecision(false, current, "租约仍由其他节点持有。");
                if (request.PreviousEpoch is not null && request.PreviousEpoch != current.Epoch)
                    return new LeaseDecision(false, current, "previousEpoch 与当前 fencing epoch 不一致。");
                var renewed = current with { ExpiresAt = now.AddSeconds(request.TtlSeconds) };
                leases[request.ClusterId] = renewed;
                await WriteAsync(leases, cancellationToken);
                return new LeaseDecision(true, renewed, null);
            }

            var nextEpoch = checked((current?.Epoch ?? 0) + 1);
            var granted = new StoredLease(request.Owner, nextEpoch, now.AddSeconds(request.TtlSeconds));
            leases[request.ClusterId] = granted;
            await WriteAsync(leases, cancellationToken);
            return new LeaseDecision(true, granted, null);
        }
        finally { _gate.Release(); }
    }

    private async Task<Dictionary<string, StoredLease>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return new Dictionary<string, StoredLease>(StringComparer.Ordinal);
        await using var stream = File.OpenRead(_path);
        return await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, StoredLease>>(stream, cancellationToken: cancellationToken)
            ?? new Dictionary<string, StoredLease>(StringComparer.Ordinal);
    }

    private async Task WriteAsync(Dictionary<string, StoredLease> leases, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            await System.Text.Json.JsonSerializer.SerializeAsync(stream, leases, cancellationToken: cancellationToken);
            await stream.FlushAsync(cancellationToken);
            stream.Flush(true);
        }
        File.Move(temporary, _path, true);
    }
}
