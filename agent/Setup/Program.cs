using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace MonitoringPlatform.Agent.Setup
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new AgentSetupForm());
        }
    }

    internal sealed class AgentSetupForm : Form
    {
        private readonly TextBox _agentName = new TextBox { Text = Environment.MachineName, Dock = DockStyle.Fill };
        private readonly TextBox _primaryUrl = new TextBox { Dock = DockStyle.Fill };
        private readonly TextBox _secondaryUrl = new TextBox { Dock = DockStyle.Fill };
        private readonly TextBox _token = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true };
        private readonly TextBox _services = new TextBox { Dock = DockStyle.Fill };
        private readonly Button _activate = new Button { Text = "Connect and start Agent", AutoSize = true };
        private readonly Label _status = new Label { AutoSize = true, ForeColor = System.Drawing.Color.DimGray };

        public AgentSetupForm()
        {
            Text = "Monitoring Platform Agent Setup";
            Width = 670;
            Height = 365;
            MinimizeBox = false;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 2, RowCount = 8 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 155));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            AddRow(layout, 0, "Server name", _agentName);
            AddRow(layout, 1, "Primary control URL", _primaryUrl);
            AddRow(layout, 2, "Secondary control URL", _secondaryUrl);
            AddRow(layout, 3, "One-time install code", _token);
            AddRow(layout, 4, "Services to watch", _services);
            layout.Controls.Add(new Label
            {
                Text = "The code is used once and is not stored in the Agent configuration.",
                AutoSize = true,
                ForeColor = System.Drawing.Color.DimGray
            }, 1, 5);
            var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
            actions.Controls.Add(_activate);
            actions.Controls.Add(new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel });
            layout.Controls.Add(actions, 1, 6);
            layout.Controls.Add(_status, 1, 7);
            Controls.Add(layout);
            _activate.Click += Activate;
        }

        private static void AddRow(TableLayoutPanel layout, int row, string label, Control control)
        {
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
            layout.Controls.Add(control, 1, row);
        }

        private void Activate(object sender, EventArgs args)
        {
            try
            {
                var agentName = _agentName.Text.Trim();
                if (!Regex.IsMatch(agentName, "^[A-Za-z0-9._-]{1,64}$")) throw new InvalidOperationException("Server name may contain only letters, numbers, dot, underscore, and hyphen.");
                var primary = BuildEndpoint(_primaryUrl.Text, "Primary control URL");
                var secondary = string.IsNullOrWhiteSpace(_secondaryUrl.Text) ? null : BuildEndpoint(_secondaryUrl.Text, "Secondary control URL");
                if (string.IsNullOrWhiteSpace(_token.Text) || _token.Text.Trim().Length < 32) throw new InvalidOperationException("Enter the one-time install code from the control console.");

                var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var enrollmentScript = Path.Combine(baseDirectory, "Enroll-Agent.ps1");
                var signerPath = Path.Combine(baseDirectory, "SIGNER-SHA1.txt");
                if (!File.Exists(enrollmentScript) || !File.Exists(signerPath)) throw new InvalidOperationException("The Agent package is incomplete. Reinstall a signed MSI.");
                var signer = File.ReadAllText(signerPath).Trim();
                if (!Regex.IsMatch(signer, "^[A-Fa-f0-9]{40}$")) throw new InvalidOperationException("The package signer metadata is invalid.");

                var tokenPath = WriteProtectedToken(_token.Text.Trim());
                var pins = new[] { GetServerCertificateSha256(primary), secondary == null ? null : GetServerCertificateSha256(secondary) }
                    .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                _token.Clear();
                _activate.Enabled = false;
                _status.Text = "Opening the protected enrollment step...";
                var arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(enrollmentScript) +
                    " -AgentName " + Quote(agentName) +
                    " -EnrollmentEndpoint " + Quote(primary + "/api/v1/agents/enroll") +
                    " -IngestEndpoint " + Quote(primary + "/api/v1/agents/ingest") +
                    " -TokenProtectedFile " + Quote(tokenPath) +
                    " -ApprovedSignerThumbprint " + Quote(signer) +
                    " -PinnedServerCertificateThumbprints " + Quote(string.Join(",", pins)) +
                    " -WatchedServices " + Quote(_services.Text.Trim());
                if (secondary != null) arguments += " -SecondaryIngestEndpoint " + Quote(secondary + "/api/v1/agents/ingest");

                var process = Process.Start(new ProcessStartInfo("powershell.exe", arguments) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Normal });
                if (process == null) throw new InvalidOperationException("Could not start the enrollment step.");
                process.WaitForExit();
                if (process.ExitCode != 0) throw new InvalidOperationException("Enrollment did not finish. Review the displayed administrator window and correct the settings before trying again.");
                using (var service = new ServiceController("MonitoringPlatformAgent"))
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running) throw new InvalidOperationException("Enrollment finished but the Agent service is not running.");
                }
                _status.ForeColor = System.Drawing.Color.ForestGreen;
                _status.Text = "Agent connected and running. Confirm the heartbeat in the control console.";
            }
            catch (Exception exception)
            {
                _status.ForeColor = System.Drawing.Color.Firebrick;
                _status.Text = exception.Message;
            }
            finally
            {
                _activate.Enabled = true;
            }
        }

        private static string BuildEndpoint(string value, string field)
        {
            if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(uri.Host) || uri.AbsolutePath != "/")
                throw new InvalidOperationException(field + " must be an HTTPS address without a path.");
            return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }

        private static string GetServerCertificateSha256(string endpoint)
        {
            var uri = new Uri(endpoint);
            using (var client = new TcpClient())
            {
                client.Connect(uri.Host, uri.Port);
                using (var stream = new SslStream(client.GetStream(), false, (_, _, _, _) => true))
                {
                    stream.AuthenticateAsClient(uri.Host);
                    using (var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(stream.RemoteCertificate))
                        return BitConverter.ToString(SHA256.Create().ComputeHash(certificate.RawData)).Replace("-", "");
                }
            }
        }

        private static string WriteProtectedToken(string token)
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MonitoringPlatform", "AgentSetup");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".bin");
            File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser));
            return path;
        }

        private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}
