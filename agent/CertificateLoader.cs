using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace MonitoringPlatform.Agent
{
    internal static class CertificateLoader
    {
        public static X509Certificate2 LoadClientCertificate(AgentSettings settings)
        {
            if (!settings.RequireClientCertificate) return null;
            using (var store = new X509Store(settings.ClientCertificateStoreName, settings.ClientCertificateStoreLocation))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var certificate = store.Certificates.Cast<X509Certificate2>().SingleOrDefault(item =>
                    string.Equals(Sha256Thumbprint(item), settings.ClientCertificateThumbprint, StringComparison.OrdinalIgnoreCase));
                if (certificate == null) throw new InvalidOperationException("Configured client certificate was not found in the certificate store.");
                if (!certificate.HasPrivateKey) throw new InvalidOperationException("Configured client certificate has no accessible private key.");
                if (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
                    throw new InvalidOperationException("Configured client certificate is not currently valid.");
                return certificate;
            }
        }

        public static bool IsPinnedServerCertificateValid(X509Certificate certificate, SslPolicyErrors errors, IEnumerable<string> pins)
        {
            var allowed = (pins ?? Enumerable.Empty<string>()).Where(item => item.Length == 64).ToArray();
            if (allowed.Length == 0) return errors == SslPolicyErrors.None;
            if (errors != SslPolicyErrors.None || certificate == null) return false;
            return allowed.Contains(Sha256Thumbprint(new X509Certificate2(certificate)), StringComparer.OrdinalIgnoreCase);
        }

        public static string[] NormalizeThumbprints(string raw)
        {
            return (raw ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(NormalizeThumbprint).Where(value => value.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        public static string NormalizeThumbprint(string value)
        {
            return new string((value ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        }

        public static string Sha256Thumbprint(X509Certificate2 certificate)
        {
            using (var hash = System.Security.Cryptography.SHA256.Create())
                return BitConverter.ToString(hash.ComputeHash(certificate.RawData)).Replace("-", "");
        }
    }
}
