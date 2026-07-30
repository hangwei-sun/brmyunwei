using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace MonitoringPlatform.Agent
{
    [DataContract]
    internal sealed class TelemetrySample
    {
        [DataMember(Name = "hostName")] public string HostName { get; set; }
        [DataMember(Name = "sequence")] public long Sequence { get; set; }
        [DataMember(Name = "collectedAt")] public DateTimeOffset CollectedAt { get; set; }
        [DataMember(Name = "cpu")] public double Cpu { get; set; }
        [DataMember(Name = "memory")] public double Memory { get; set; }
        [DataMember(Name = "disk")] public double Disk { get; set; }
        [DataMember(Name = "latency")] public double Latency { get; set; }
        // Extra fields are intentionally forward-compatible; the current server ignores unknown JSON fields.
        [DataMember(Name = "networkBytesPerSecond")] public double NetworkBytesPerSecond { get; set; }
        [DataMember(Name = "bootTime")] public DateTimeOffset? BootTime { get; set; }
        [DataMember(Name = "services")] public List<ServiceTelemetry> Services { get; set; }
        [DataMember(Name = "agentVersion")] public string AgentVersion { get; set; }
    }

    [DataContract]
    internal sealed class ServiceTelemetry
    {
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "status")] public string Status { get; set; }
    }

    internal static class TelemetryMath
    {
        public static double Percent(double used, double total)
        {
            if (total <= 0) return 0;
            return Math.Max(0, Math.Min(100, Math.Round(used * 100 / total, 2)));
        }

        public static double Rate(long currentBytes, long previousBytes, TimeSpan elapsed)
        {
            if (previousBytes < 0 || currentBytes < previousBytes || elapsed.TotalSeconds <= 0) return 0;
            return Math.Round((currentBytes - previousBytes) / elapsed.TotalSeconds, 2);
        }
    }
}
