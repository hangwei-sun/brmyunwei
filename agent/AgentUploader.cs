using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.Serialization.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MonitoringPlatform.Agent
{
    internal sealed class AgentUploader : IDisposable
    {
        private readonly AgentSettings _settings;
        private readonly HttpClient _client;

        public AgentUploader(AgentSettings settings)
        {
            _settings = settings;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var handler = new HttpClientHandler();
            var clientCertificate = CertificateLoader.LoadClientCertificate(settings);
            if (clientCertificate != null) handler.ClientCertificates.Add(clientCertificate);
            if (settings.PinnedServerCertificateThumbprints.Length > 0)
            {
                handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) =>
                    CertificateLoader.IsPinnedServerCertificateValid(certificate, errors, settings.PinnedServerCertificateThumbprints);
            }
            _client = new HttpClient(handler, true) { Timeout = TimeSpan.FromMilliseconds(settings.HttpTimeoutMilliseconds) };
        }

        public async Task<bool> UploadAsync(TelemetrySample sample, CancellationToken cancellationToken)
        {
            if (await SendAsync(_settings.PrimaryEndpoint, sample, cancellationToken).ConfigureAwait(false)) return true;
            return _settings.SecondaryEndpoint != null && await SendAsync(_settings.SecondaryEndpoint, sample, cancellationToken).ConfigureAwait(false);
        }

        private async Task<bool> SendAsync(Uri endpoint, TelemetrySample sample, CancellationToken cancellationToken)
        {
            try
            {
                using (var payload = new MemoryStream())
                {
                    new DataContractJsonSerializer(typeof(TelemetrySample)).WriteObject(payload, sample);
                    payload.Position = 0;
                    using (var request = new HttpRequestMessage(HttpMethod.Post, endpoint))
                    {
                        request.Headers.Add("X-Agent-Name", _settings.AgentName);
                        if (!string.IsNullOrWhiteSpace(_settings.AgentKey)) request.Headers.Add("X-Agent-Key", _settings.AgentKey);
                        request.Content = new StreamContent(payload);
                        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                        using (var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false))
                            return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Conflict;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested) throw;
                return false; // HttpClient timeout
            }
            catch (HttpRequestException) { return false; }
        }

        public void Dispose() { _client.Dispose(); }
    }
}
