using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace MonitoringPlatform.Agent
{
    internal sealed class AgentSettings
    {
        public string AgentName { get; private set; }
        public string AgentKey { get; private set; }
        public Uri PrimaryEndpoint { get; private set; }
        public Uri SecondaryEndpoint { get; private set; }
        public bool RequireClientCertificate { get; private set; }
        public StoreLocation ClientCertificateStoreLocation { get; private set; }
        public StoreName ClientCertificateStoreName { get; private set; }
        public string ClientCertificateThumbprint { get; private set; }
        public string[] PinnedServerCertificateThumbprints { get; private set; }
        public int SampleIntervalSeconds { get; private set; }
        public int InitialJitterSeconds { get; private set; }
        public int HttpTimeoutMilliseconds { get; private set; }
        public int MaxPendingSamples { get; private set; }
        public int MaxUploadBatch { get; private set; }
        public string DataDirectory { get; private set; }
        public string[] WatchedServices { get; private set; }

        public static AgentSettings Load()
        {
            var configuredDataDirectory = Read("DataDirectory", "");
            var dataDirectory = string.IsNullOrWhiteSpace(configuredDataDirectory)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MonitoringPlatform", "Agent")
                : Environment.ExpandEnvironmentVariables(configuredDataDirectory.Trim());
            var settings = new AgentSettings
            {
                AgentName = Read("AgentName", "").Trim(),
                AgentKey = Read("AgentKey", "").Trim(),
                PrimaryEndpoint = ReadEndpoint("PrimaryEndpoint", true),
                SecondaryEndpoint = ReadEndpoint("SecondaryEndpoint", false),
                RequireClientCertificate = ReadBool("RequireClientCertificate", false),
                ClientCertificateStoreLocation = ReadEnum("ClientCertificateStoreLocation", StoreLocation.LocalMachine),
                ClientCertificateStoreName = ReadEnum("ClientCertificateStoreName", StoreName.My),
                ClientCertificateThumbprint = CertificateLoader.NormalizeThumbprint(Read("ClientCertificateThumbprint", "")),
                PinnedServerCertificateThumbprints = CertificateLoader.NormalizeThumbprints(Read("PinnedServerCertificateThumbprints", "")),
                SampleIntervalSeconds = ReadInt("SampleIntervalSeconds", 60, 15, 3600),
                InitialJitterSeconds = ReadInt("InitialJitterSeconds", 5, 0, 60),
                HttpTimeoutMilliseconds = ReadInt("HttpTimeoutMilliseconds", 5000, 1000, 30000),
                MaxPendingSamples = ReadInt("MaxPendingSamples", 256, 1, 2048),
                MaxUploadBatch = ReadInt("MaxUploadBatch", 16, 1, 64),
                DataDirectory = dataDirectory,
                WatchedServices = Read("WatchedServices", "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(value => value.Trim()).Where(value => value.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToArray()
            };
            if (settings.AgentName.Length == 0 || settings.AgentName.Length > 64) throw new ConfigurationErrorsException("AgentName is required and must not exceed 64 characters.");
            if (!settings.RequireClientCertificate && settings.AgentKey.Length < 32)
                throw new ConfigurationErrorsException("AgentKey is missing or too short, and mTLS enrollment is not enabled.");
            if (settings.RequireClientCertificate && settings.ClientCertificateThumbprint.Length != 64)
                throw new ConfigurationErrorsException("ClientCertificateThumbprint must be a SHA-256 thumbprint when RequireClientCertificate is true.");
            Directory.CreateDirectory(settings.DataDirectory);
            return settings;
        }

        private static string Read(string key, string fallback) => ConfigurationManager.AppSettings[key] ?? fallback;
        private static int ReadInt(string key, int fallback, int minimum, int maximum)
        {
            int value;
            return int.TryParse(Read(key, fallback.ToString()), out value) && value >= minimum && value <= maximum ? value : fallback;
        }
        private static bool ReadBool(string key, bool fallback)
        {
            bool value;
            return bool.TryParse(Read(key, fallback.ToString()), out value) ? value : fallback;
        }
        private static T ReadEnum<T>(string key, T fallback) where T : struct
        {
            T value;
            return Enum.TryParse(Read(key, fallback.ToString()), true, out value) ? value : fallback;
        }
        private static Uri ReadEndpoint(string key, bool required)
        {
            var value = Read(key, "").Trim();
            if (value.Length == 0 && !required) return null;
            Uri endpoint;
            if (!Uri.TryCreate(value, UriKind.Absolute, out endpoint) || endpoint.Scheme != Uri.UriSchemeHttps)
                throw new ConfigurationErrorsException(key + " must be an absolute HTTPS URL.");
            return endpoint;
        }
    }
}
