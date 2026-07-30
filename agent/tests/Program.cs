using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MonitoringPlatform.Agent.SelfTests
{
    internal static class Program
    {
        private static int Main()
        {
            try
            {
                AssertEqual(50d, TelemetryMath.Percent(5, 10), "percentage");
                AssertEqual(0d, TelemetryMath.Percent(1, 0), "zero denominator");
                AssertEqual(250d, TelemetryMath.Rate(350, 100, TimeSpan.FromSeconds(1)), "network rate");
                AssertEqual(0d, TelemetryMath.Rate(50, 100, TimeSpan.FromSeconds(1)), "counter reset");
                VerifyBoundedQueue();
                VerifyPayloadBudget();
                VerifyCertificateNormalization();
                Console.WriteLine("Agent self-tests passed.");
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(error.Message);
                return 1;
            }
        }

        private static void VerifyCertificateNormalization()
        {
            var normalized = CertificateLoader.NormalizeThumbprint(" aa:bb cc-dd ");
            if (normalized != "AABBCCDD") throw new InvalidOperationException("certificate thumbprint normalization failed.");
            if (CertificateLoader.NormalizeThumbprints("aa, AA;bb").Length != 2) throw new InvalidOperationException("certificate pin de-duplication failed.");
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=agent-self-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
                {
                    var thumbprint = CertificateLoader.Sha256Thumbprint(certificate);
                    if (!CertificateLoader.IsPinnedServerCertificateValid(certificate, System.Net.Security.SslPolicyErrors.None, new[] { thumbprint }))
                        throw new InvalidOperationException("matching certificate pin was rejected.");
                    if (CertificateLoader.IsPinnedServerCertificateValid(certificate, System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch, new[] { thumbprint }))
                        throw new InvalidOperationException("TLS validation error was accepted by pinning.");
                }
            }
        }

        private static void VerifyPayloadBudget()
        {
            var services = Enumerable.Range(1, 32).Select(index => new ServiceTelemetry { Name = "SERVICE-" + index, Status = "Running" }).ToList();
            var sample = new TelemetrySample
            {
                HostName = "WINDOWS-SERVER-2012",
                Sequence = long.MaxValue - 1,
                CollectedAt = DateTimeOffset.UtcNow,
                Cpu = 100,
                Memory = 100,
                Disk = 100,
                Latency = 120000,
                NetworkBytesPerSecond = 1000000000,
                BootTime = DateTimeOffset.UtcNow.AddDays(-365),
                Services = services
            };
            using (var stream = new MemoryStream())
            {
                new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(TelemetrySample)).WriteObject(stream, sample);
                if (stream.Length > 16 * 1024) throw new InvalidOperationException("telemetry payload exceeded the 16 KiB budget.");
            }
        }

        private static void VerifyBoundedQueue()
        {
            var directory = Path.Combine(Path.GetTempPath(), "monitoring-agent-selftest-" + Guid.NewGuid().ToString("N"));
            try
            {
                var store = new PendingStore(directory, 2);
                for (var index = 0; index < 3; index++)
                {
                    var sample = new TelemetrySample { HostName = "TEST", Sequence = store.NextSequence(), CollectedAt = DateTimeOffset.UtcNow, Services = new System.Collections.Generic.List<ServiceTelemetry>() };
                    store.Enqueue(sample);
                }
                var queued = store.Take(10).ToArray();
                if (queued.Length != 2 || queued[0].Sample.Sequence != 2 || queued[1].Sample.Sequence != 3)
                    throw new InvalidOperationException("bounded queue did not retain the newest samples.");
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }

        private static void AssertEqual(double expected, double actual, string name)
        {
            if (Math.Abs(expected - actual) > 0.001) throw new InvalidOperationException(name + " assertion failed.");
        }
    }
}
