using Microsoft.Extensions.Options;
using Xunit;

public sealed class LeaseStoreTests
{
    [Fact]
    public async Task Lease_IsExclusive_RenewsSameEpoch_AndTransfersAfterExpiry()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"monitoring-witness-tests-{Guid.NewGuid():N}");
        try
        {
            var store = new LeaseStore(Options.Create(new WitnessOptions { DataPath = Path.Combine(directory, "leases.json") }));
            var now = new DateTimeOffset(2026, 7, 30, 12, 0, 0, TimeSpan.Zero);

            var first = await store.AcquireOrRenewAsync(new WitnessLeaseRequest("cluster-a", "node-a", 30, null), now, TestContext.Current.CancellationToken);
            Assert.True(first.Granted);
            Assert.Equal(1, first.Lease!.Epoch);

            var conflict = await store.AcquireOrRenewAsync(new WitnessLeaseRequest("cluster-a", "node-b", 30, null), now.AddSeconds(1), TestContext.Current.CancellationToken);
            Assert.False(conflict.Granted);
            Assert.Equal("node-a", conflict.Lease!.Owner);

            var renewed = await store.AcquireOrRenewAsync(new WitnessLeaseRequest("cluster-a", "node-a", 30, 1), now.AddSeconds(2), TestContext.Current.CancellationToken);
            Assert.True(renewed.Granted);
            Assert.Equal(1, renewed.Lease!.Epoch);

            var stale = await store.AcquireOrRenewAsync(new WitnessLeaseRequest("cluster-a", "node-a", 30, 99), now.AddSeconds(3), TestContext.Current.CancellationToken);
            Assert.False(stale.Granted);

            var transferred = await store.AcquireOrRenewAsync(new WitnessLeaseRequest("cluster-a", "node-b", 30, null), now.AddSeconds(40), TestContext.Current.CancellationToken);
            Assert.True(transferred.Granted);
            Assert.Equal(2, transferred.Lease!.Epoch);
            Assert.Equal("node-b", transferred.Lease.Owner);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }
}
