using System;
using System.IO;
using System.Net;
using System.Net.Http;
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
            _client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(settings.HttpTimeoutMilliseconds) };
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
                        request.Headers.Add("X-Agent-Key", _settings.AgentKey);
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
