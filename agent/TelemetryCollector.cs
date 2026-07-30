using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace MonitoringPlatform.Agent
{
    internal sealed class TelemetryCollector : IDisposable
    {
        private readonly PerformanceCounter _cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total", true);
        private readonly PerformanceCounter _memory = new PerformanceCounter("Memory", "% Committed Bytes In Use", true);
        private readonly DateTimeOffset? _bootTime;
        private long _previousNetworkBytes = -1;
        private DateTimeOffset _previousNetworkAt = DateTimeOffset.MinValue;

        public TelemetryCollector()
        {
            // Prime the counter once. Subsequent samples use the normal low-cost NextValue call.
            _cpu.NextValue();
            _memory.NextValue();
            _bootTime = GetBootTime();
        }

        public TelemetrySample Collect(AgentSettings settings, long sequence)
        {
            var now = DateTimeOffset.UtcNow;
            var networkBytes = GetNetworkBytes();
            var sample = new TelemetrySample
            {
                HostName = settings.AgentName,
                Sequence = sequence,
                CollectedAt = now,
                Cpu = Clamp(_cpu.NextValue()),
                Memory = Clamp(_memory.NextValue()),
                Disk = GetDiskPercent(),
                Latency = 0,
                NetworkBytesPerSecond = TelemetryMath.Rate(networkBytes, _previousNetworkBytes, now - _previousNetworkAt),
                BootTime = _bootTime,
                Services = GetServices(settings.WatchedServices),
                AgentVersion = typeof(TelemetryCollector).Assembly.GetName().Version.ToString()
            };
            _previousNetworkBytes = networkBytes;
            _previousNetworkAt = now;
            return sample;
        }

        private static double GetDiskPercent()
        {
            try
            {
                var disks = DriveInfo.GetDrives().Where(drive => drive.IsReady && drive.DriveType == DriveType.Fixed).ToArray();
                return disks.Length == 0 ? 0 : disks.Max(drive => TelemetryMath.Percent(drive.TotalSize - drive.AvailableFreeSpace, drive.TotalSize));
            }
            catch { return 0; }
        }

        private static long GetNetworkBytes()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces().Where(item => item.OperationalStatus == OperationalStatus.Up && item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Sum(item => item.GetIPv4Statistics().BytesReceived + item.GetIPv4Statistics().BytesSent);
            }
            catch { return 0; }
        }

        private static DateTimeOffset? GetBootTime()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                using (var results = searcher.Get())
                {
                    var value = results.Cast<ManagementObject>().FirstOrDefault();
                    var raw = value == null ? null : value["LastBootUpTime"] as string;
                    return string.IsNullOrWhiteSpace(raw) ? (DateTimeOffset?)null : new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(raw));
                }
            }
            catch { return null; }
        }

        private static List<ServiceTelemetry> GetServices(IEnumerable<string> serviceNames)
        {
            var output = new List<ServiceTelemetry>();
            foreach (var name in serviceNames)
            {
                try
                {
                    using (var service = new ServiceController(name)) output.Add(new ServiceTelemetry { Name = name, Status = service.Status.ToString() });
                }
                catch { output.Add(new ServiceTelemetry { Name = name, Status = "NotFoundOrUnavailable" }); }
            }
            return output;
        }

        private static double Clamp(float value) => Math.Max(0, Math.Min(100, Math.Round(value, 2)));
        public void Dispose() { _cpu.Dispose(); _memory.Dispose(); }
    }
}
