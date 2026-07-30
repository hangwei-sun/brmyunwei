using System;
using System.IO;
using System.Text;

namespace MonitoringPlatform.Agent
{
    internal sealed class RollingLog
    {
        private const long MaximumBytes = 1024 * 1024;
        private readonly string _path;
        public RollingLog(string dataDirectory) { _path = Path.Combine(dataDirectory, "agent.log"); }

        public void Error(string message)
        {
            try
            {
                if (File.Exists(_path) && new FileInfo(_path).Length >= MaximumBytes)
                {
                    var archived = _path + ".1";
                    if (File.Exists(archived)) File.Delete(archived);
                    File.Move(_path, archived);
                }
                File.AppendAllText(_path, DateTimeOffset.UtcNow.ToString("O") + " ERROR " + message + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }
    }
}
