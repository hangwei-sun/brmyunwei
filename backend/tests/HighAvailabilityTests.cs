using Microsoft.Extensions.Options;
using Xunit;

public sealed class HighAvailabilityTests
{
    [Fact]
    public void WitnessLease_RejectsOldEpoch_AndImmediatelyStopsWritesWhenLost()
    {
        var state = new HaLeaseState(Options.Create(new HaOptions { Enabled = true, NodeId = "node-a", ConfiguredRole = "active", WitnessUrl = "https://witness.example/" }));
        var now = DateTimeOffset.UtcNow;

        Assert.True(state.TryApply(new HaLeaseGrant("node-a", 7, now.AddSeconds(30)), now));
        Assert.True(state.HoldsValidLease(now));
        Assert.True(state.CanMutate(now));
        Assert.True(state.CanWrite(7, now));
        Assert.Equal(7, state.Status(now).Epoch);

        state.LoseLease("witness unavailable");
        Assert.False(state.HoldsValidLease(now));
        Assert.False(state.CanMutate(now));
        Assert.False(state.CanWrite(7, now));
        Assert.False(state.TryApply(new HaLeaseGrant("node-a", 6, now.AddSeconds(30)), now));
        Assert.False(state.TryApply(new HaLeaseGrant("node-b", 8, now.AddSeconds(30)), now));
        Assert.False(state.TryApply(new HaLeaseGrant("node-a", 7, now.AddSeconds(30)), now));
    }

    [Fact]
    public void WitnessLease_CapsRemoteExpiryToLocalTtl()
    {
        var state = new HaLeaseState(Options.Create(new HaOptions { Enabled = true, NodeId = "node-a", LeaseTtlSeconds = 30 }));
        var now = DateTimeOffset.UtcNow;

        Assert.True(state.TryApply(new HaLeaseGrant("node-a", 3, now.AddDays(1)), now));
        Assert.InRange(state.Status(now).LeaseExpiresAt!.Value, now.AddSeconds(29), now.AddSeconds(30));
    }

    [Fact]
    public void SingleNode_CanMutateWithoutWitness()
    {
        var state = new HaLeaseState(Options.Create(new HaOptions { Enabled = false }));

        Assert.True(state.CanMutate(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ReplicationManifest_ValidatesHashChainAndRejectsOldEpoch()
    {
        var created = DateTimeOffset.UtcNow;
        var firstHash = ReplicationManifest.CalculateHash(1, 3, "", "snapshot-e3-s00000000000000000001.db", "abc", created);
        var first = new ReplicationManifest(1, 3, "", "snapshot-e3-s00000000000000000001.db", "abc", created, firstHash);
        var secondAt = created.AddSeconds(1);
        var secondHash = ReplicationManifest.CalculateHash(2, 4, first.Hash, "snapshot-e4-s00000000000000000002.db", "def", secondAt);
        var second = new ReplicationManifest(2, 4, first.Hash, "snapshot-e4-s00000000000000000002.db", "def", secondAt, secondHash);

        HaReplication.ValidateChain([first, second]);

        var staleHash = ReplicationManifest.CalculateHash(3, 3, second.Hash, "snapshot-e3-s00000000000000000003.db", "ghi", secondAt.AddSeconds(1));
        var stale = new ReplicationManifest(3, 3, second.Hash, "snapshot-e3-s00000000000000000003.db", "ghi", secondAt.AddSeconds(1), staleHash);
        Assert.Throws<InvalidDataException>(() => HaReplication.ValidateChain([first, second, stale]));
    }
}
