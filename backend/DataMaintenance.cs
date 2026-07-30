using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

sealed class DataMaintenanceOptions
{
    public const string SectionName = "DataMaintenance";
    public bool Enabled { get; set; } = true;
    public int MetricDays { get; set; } = 30;
    public int ResolvedIncidentDays { get; set; } = 365;
    public int AuditDays { get; set; } = 730;
    public int RunHourLocal { get; set; } = 2;
    public string? BackupDirectory { get; set; }
    public int BackupKeepDays { get; set; } = 30;
}

sealed class DataMaintenanceWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<DataMaintenanceOptions> configuredOptions,
    IWebHostEnvironment environment,
    HaLeaseState haLease,
    ILogger<DataMaintenanceWorker> logger) : BackgroundService
{
    private const int DeleteBatchSize = 5_000;
    private readonly DataMaintenanceOptions _options = configuredOptions.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            logger.LogInformation("Data maintenance is disabled by configuration.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = NextRunDelay(DateTimeOffset.Now, Math.Clamp(_options.RunHourLocal, 0, 23));
            try { await Task.Delay(delay, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            try
            {
                if (!haLease.CanMutate(DateTimeOffset.UtcNow)) continue;
                await CleanupAsync(stoppingToken);
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
                await BackupNowAsync(db, _options, environment, logger, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                logger.LogError(exception, "Scheduled data maintenance failed.");
            }
        }
    }

    internal static TimeSpan NextRunDelay(DateTimeOffset localNow, int hour)
    {
        var next = new DateTimeOffset(localNow.Year, localNow.Month, localNow.Day, hour, 0, 0, localNow.Offset);
        if (next <= localNow) next = next.AddDays(1);
        return next - localNow;
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
        var now = DateTimeOffset.UtcNow;
        var metrics = await DeleteInBatchesAsync(
            () => db.MetricSamples.Where(item => item.CollectedAt < now.AddDays(-Math.Clamp(_options.MetricDays, 1, 365)))
                .OrderBy(item => item.Id).Take(DeleteBatchSize).ExecuteDeleteAsync(cancellationToken), cancellationToken);
        var incidents = await DeleteInBatchesAsync(
            () => db.Incidents.Where(item => item.ResolvedAt != null && item.ResolvedAt < now.AddDays(-Math.Clamp(_options.ResolvedIncidentDays, 30, 3650)))
                .OrderBy(item => item.UpdatedAt).Take(DeleteBatchSize).ExecuteDeleteAsync(cancellationToken), cancellationToken);
        var audits = await DeleteInBatchesAsync(
            () => db.AuditLogs.Where(item => item.CreatedAt < now.AddDays(-Math.Clamp(_options.AuditDays, 90, 3650)))
                .OrderBy(item => item.Id).Take(DeleteBatchSize).ExecuteDeleteAsync(cancellationToken), cancellationToken);
        logger.LogInformation("Data retention completed. Metrics={Metrics}, incidents={Incidents}, audits={Audits}.", metrics, incidents, audits);
    }

    private async Task<int> DeleteInBatchesAsync(Func<Task<int>> deleteBatch, CancellationToken cancellationToken)
    {
        var total = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            if (!haLease.CanCommit(DateTimeOffset.UtcNow)) throw new InvalidOperationException("Witness lease was lost during data retention.");
            var deleted = await deleteBatch();
            total += deleted;
            if (deleted < DeleteBatchSize) break;
            await Task.Delay(25, cancellationToken);
        }
        return total;
    }

    internal static async Task<BackupResult> BackupNowAsync(MonitoringDbContext db, DataMaintenanceOptions options, IWebHostEnvironment environment, ILogger logger, CancellationToken cancellationToken)
    {
        var backupDirectory = ResolveBackupDirectory(options, environment);
        Directory.CreateDirectory(backupDirectory);

        var targetPath = Path.Combine(backupDirectory, $"monitoring-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.db");
        if (db.Database.GetDbConnection() is not SqliteConnection source)
            throw new InvalidOperationException("Online backup requires the SQLite provider.");

        await source.OpenAsync(cancellationToken);
        await using (var target = new SqliteConnection($"Data Source={targetPath};Mode=ReadWriteCreate;Pooling=False"))
        {
            await target.OpenAsync(cancellationToken);
            source.BackupDatabase(target);
            await using var integrityCommand = target.CreateCommand();
            integrityCommand.CommandText = "PRAGMA integrity_check;";
            var integrity = (string?)await integrityCommand.ExecuteScalarAsync(cancellationToken);
            if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("SQLite backup integrity check failed.");
        }

        string hash;
        await using (var stream = File.OpenRead(targetPath))
        {
            hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            await File.WriteAllTextAsync($"{targetPath}.sha256", $"{hash}  {Path.GetFileName(targetPath)}{Environment.NewLine}", cancellationToken);
        }
        PruneBackups(backupDirectory, DateTimeOffset.Now.AddDays(-Math.Clamp(options.BackupKeepDays, 2, 365)), logger);
        logger.LogInformation("Verified SQLite online backup created at {BackupPath}.", targetPath);
        return new BackupResult(Path.GetFileName(targetPath), hash);
    }

    internal static string ResolveBackupDirectory(DataMaintenanceOptions options, IWebHostEnvironment environment)
    {
        var backupDirectory = options.BackupDirectory;
        if (string.IsNullOrWhiteSpace(backupDirectory)) backupDirectory = Path.Combine(environment.ContentRootPath, "Data", "Backups");
        return Path.GetFullPath(backupDirectory);
    }

    private static void PruneBackups(string backupDirectory, DateTimeOffset cutoff, ILogger logger)
    {
        foreach (var backupPath in Directory.EnumerateFiles(backupDirectory, "monitoring-*.db"))
        {
            if (File.GetLastWriteTimeUtc(backupPath) >= cutoff.UtcDateTime) continue;
            try
            {
                File.Delete(backupPath);
                var checksumPath = $"{backupPath}.sha256";
                if (File.Exists(checksumPath)) File.Delete(checksumPath);
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Could not prune expired backup {BackupPath}.", backupPath);
            }
        }
    }
}

sealed record BackupResult(string FileName, string Sha256);
