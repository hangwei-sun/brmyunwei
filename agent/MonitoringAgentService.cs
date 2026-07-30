using System.ServiceProcess;

namespace MonitoringPlatform.Agent
{
    internal sealed class MonitoringAgentService : ServiceBase
    {
        private AgentWorker _worker;

        public MonitoringAgentService()
        {
            ServiceName = "MonitoringPlatformAgent";
            CanStop = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            _worker = new AgentWorker(AgentSettings.Load());
            _worker.Start();
        }

        protected override void OnStop()
        {
            if (_worker == null) return;
            _worker.Stop();
            _worker.Dispose();
            _worker = null;
        }
    }
}
