using System;
using System.Threading;
using System.Threading.Tasks;

namespace MonitoringPlatform.Agent
{
    internal sealed class AgentWorker : IDisposable
    {
        private readonly AgentSettings _settings;
        private readonly TelemetryCollector _collector;
        private readonly PendingStore _pending;
        private readonly AgentUploader _uploader;
        private readonly RollingLog _log;
        private CancellationTokenSource _stopping;
        private Task _loop;
        private int _running;

        public AgentWorker(AgentSettings settings)
        {
            _settings = settings;
            _collector = new TelemetryCollector();
            _pending = new PendingStore(settings.DataDirectory, settings.MaxPendingSamples);
            _uploader = new AgentUploader(settings);
            _log = new RollingLog(settings.DataDirectory);
        }

        public void Start()
        {
            if (Interlocked.Exchange(ref _running, 1) != 0) return;
            _stopping = new CancellationTokenSource();
            _loop = Task.Run(() => RunLoopAsync(_stopping.Token));
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _running, 0) == 0) return;
            _stopping.Cancel();
            try { _loop.Wait(TimeSpan.FromSeconds(15)); } catch { }
            _stopping.Dispose();
            _stopping = null;
        }

        public void RunOnce()
        {
            RunCycleAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        private async Task RunLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                var jitter = new Random(unchecked(Environment.TickCount * 31 + _settings.AgentName.GetHashCode())).Next(_settings.InitialJitterSeconds + 1);
                if (jitter > 0) await Task.Delay(TimeSpan.FromSeconds(jitter), cancellationToken).ConfigureAwait(false);
                while (!cancellationToken.IsCancellationRequested)
                {
                    await RunCycleAsync(cancellationToken).ConfigureAwait(false);
                    await Task.Delay(TimeSpan.FromSeconds(_settings.SampleIntervalSeconds), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception error) { _log.Error("worker stopped: " + error.GetType().Name); }
        }

        private async Task RunCycleAsync(CancellationToken cancellationToken)
        {
            try
            {
                var sample = _collector.Collect(_settings, _pending.NextSequence());
                _pending.Enqueue(sample);
                // Current v1 ingestion accepts one sample per request. Reusing one client drains a bounded batch without opening listeners.
                foreach (var item in _pending.Take(_settings.MaxUploadBatch))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!await _uploader.UploadAsync(item.Sample, cancellationToken).ConfigureAwait(false)) break;
                    PendingStore.TryDelete(item.Path);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) { _log.Error("collection/upload failed: " + error.GetType().Name); }
        }

        public void Dispose()
        {
            Stop();
            _uploader.Dispose();
            _collector.Dispose();
        }
    }
}
