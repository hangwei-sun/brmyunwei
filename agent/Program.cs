using System;
using System.ServiceProcess;
using System.Threading;

namespace MonitoringPlatform.Agent
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (Array.Exists(args, value => string.Equals(value, "--console", StringComparison.OrdinalIgnoreCase)))
            {
                using (var worker = new AgentWorker(AgentSettings.Load()))
                {
                    worker.Start();
                    Console.WriteLine("Monitoring agent is running. Press Ctrl+C to stop.");
                    using (var stopped = new ManualResetEvent(false))
                    {
                        Console.CancelKeyPress += (sender, eventArgs) => { eventArgs.Cancel = true; stopped.Set(); };
                        stopped.WaitOne();
                    }
                    worker.Stop();
                }
                return;
            }

            if (Array.Exists(args, value => string.Equals(value, "--sample-once", StringComparison.OrdinalIgnoreCase)))
            {
                using (var worker = new AgentWorker(AgentSettings.Load())) worker.RunOnce();
                return;
            }

            ServiceBase.Run(new MonitoringAgentService());
        }
    }
}
