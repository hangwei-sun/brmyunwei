using Xunit;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class DataMaintenanceTests
{
    [Fact]
    public void NextRunDelay_UsesTodayBeforeScheduledHour()
    {
        var now = new DateTimeOffset(2026, 7, 30, 1, 15, 0, TimeSpan.FromHours(8));

        var delay = DataMaintenanceWorker.NextRunDelay(now, 2);

        Assert.Equal(TimeSpan.FromMinutes(45), delay);
    }

    [Fact]
    public void NextRunDelay_UsesNextDayAfterScheduledHour()
    {
        var now = new DateTimeOffset(2026, 7, 30, 2, 15, 0, TimeSpan.FromHours(8));

        var delay = DataMaintenanceWorker.NextRunDelay(now, 2);

        Assert.Equal(TimeSpan.FromHours(23.75), delay);
    }

    [Fact]
    public async Task OnlineBackup_HasValidChecksum_AndCanBeOpenedForRestore()
    {
        await using var factory = new ApiFactory();
        _ = factory.CreateClient();
        var directory = Path.Combine(Path.GetTempPath(), $"monitoring-backup-tests-{Guid.NewGuid():N}");
        try
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<MonitoringDbContext>();
            var environment = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
            var result = await DataMaintenanceWorker.BackupNowAsync(db, new DataMaintenanceOptions { BackupDirectory = directory, BackupKeepDays = 30 }, environment, NullLogger.Instance, TestContext.Current.CancellationToken);
            var backupPath = Path.Combine(directory, result.FileName);
            Assert.True(File.Exists(backupPath));
            Assert.True(File.Exists($"{backupPath}.sha256"));
            Assert.Contains(result.Sha256, await File.ReadAllTextAsync($"{backupPath}.sha256", TestContext.Current.CancellationToken));

            await using var restored = new SqliteConnection($"Data Source={backupPath};Mode=ReadOnly;Pooling=False");
            await restored.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = restored.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM Hosts;";
            Assert.True(Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)) > 0);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task ProductionSeed_CreatesRulesWithoutDemoAssetsOrIncidents()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var options = new DbContextOptionsBuilder<MonitoringDbContext>().UseSqlite(connection).Options;
        await using var db = new MonitoringDbContext(options);
        await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        await SecuritySchema.EnsureAsync(db);

        await SeedData.EnsureAsync(db, includeDemoData: false);

        Assert.Equal(2, await db.AlertRules.CountAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await db.Hosts.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await db.Incidents.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await db.NotificationPolicies.ToListAsync(TestContext.Current.CancellationToken));
    }
}
