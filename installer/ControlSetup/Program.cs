using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MonitoringPlatform.Control.Setup;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(args.Any(arg => string.Equals(arg, "--witness", StringComparison.OrdinalIgnoreCase))
            ? new WitnessSetupForm()
            : new ControlSetupForm());
    }
}

internal sealed class CertificateItem(X509Certificate2 certificate)
{
    public X509Certificate2 Certificate { get; } = certificate;
    public override string ToString() => $"{Certificate.GetNameInfo(X509NameType.SimpleName, false)} | expires {Certificate.NotAfter:yyyy-MM-dd} | {Certificate.Thumbprint}";
}

internal sealed class ControlSetupForm : Form
{
    private readonly TextBox _nodeId = new() { Text = Environment.MachineName };
    private readonly ComboBox _role = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _publicUrl = new();
    private readonly TextBox _peerNodeId = new();
    private readonly TextBox _peerUrl = new();
    private readonly TextBox _witnessUrl = new();
    private readonly TextBox _replicationDirectory = new();
    private readonly TextBox _keyDirectory = new();
    private readonly ComboBox _certificate = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ComboBox _agentIssuer = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _adminUser = new() { Text = "admin" };
    private readonly TextBox _adminPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox _adminPasswordRepeat = new() { UseSystemPasswordChar = true };
    private readonly TextBox _witnessToken = new() { UseSystemPasswordChar = true };
    private readonly Button _install = new() { Text = "完成配置并启动", AutoSize = true };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Color.DimGray };

    public ControlSetupForm()
    {
        Text = "机房运维监控 - 控制端配置";
        Width = 780;
        Height = 680;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;

        _role.Items.AddRange(["主用节点 (A)", "备用节点 (B)"]);
        _role.SelectedIndex = 0;
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(22), ColumnCount = 2, RowCount = 17 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Add(panel, 0, "本机节点名称", _nodeId);
        Add(panel, 1, "节点角色", _role);
        Add(panel, 2, "本机 HTTPS 地址", _publicUrl);
        Add(panel, 3, "对端节点名称", _peerNodeId);
        Add(panel, 4, "对端 HTTPS 地址", _peerUrl);
        Add(panel, 5, "见证服务 HTTPS 地址", _witnessUrl);
        Add(panel, 6, "共享快照目录", _replicationDirectory);
        Add(panel, 7, "共享密钥目录", _keyDirectory);
        Add(panel, 8, "HTTPS 与密钥证书", _certificate);
        Add(panel, 9, "Agent 注册 CA 证书", _agentIssuer);
        Add(panel, 10, "首次管理员账号", _adminUser);
        Add(panel, 11, "首次管理员密码", _adminPassword);
        Add(panel, 12, "再次输入密码", _adminPasswordRepeat);
        Add(panel, 13, "本节点 Witness 密钥", _witnessToken);
        panel.Controls.Add(new Label
        {
            Text = "请在两台控制端导入同一张包含私钥的内部 HTTPS 证书，并使用同一个共享密钥目录。Witness 密钥在服务环境保存，不写入配置文件。",
            AutoSize = true,
            MaximumSize = new Size(520, 0),
            ForeColor = Color.DimGray
        }, 1, 14);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        actions.Controls.Add(_install);
        actions.Controls.Add(new Button { Text = "关闭", AutoSize = true, DialogResult = DialogResult.Cancel });
        panel.Controls.Add(actions, 1, 15);
        panel.Controls.Add(_status, 1, 16);
        Controls.Add(panel);
        LoadCertificates();
        _install.Click += Install;
    }

    private static void Add(TableLayoutPanel panel, int row, string label, System.Windows.Forms.Control control)
    {
        control.Dock = DockStyle.Fill;
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
        panel.Controls.Add(control, 1, row);
    }

    private void LoadCertificates()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        foreach (var certificate in store.Certificates.Cast<X509Certificate2>()
                     .Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7))
                     .OrderBy(item => item.GetNameInfo(X509NameType.SimpleName, false)))
            _certificate.Items.Add(new CertificateItem(certificate));
        foreach (var certificate in store.Certificates.Cast<X509Certificate2>()
                     .Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7) && IsCertificateAuthority(item))
                     .OrderBy(item => item.GetNameInfo(X509NameType.SimpleName, false)))
            _agentIssuer.Items.Add(new CertificateItem(certificate));
        if (_certificate.Items.Count > 0) _certificate.SelectedIndex = 0;
        if (_agentIssuer.Items.Count > 0) _agentIssuer.SelectedIndex = 0;
    }

    private void Install(object? sender, EventArgs eventArgs)
    {
        try
        {
            var nodeId = ValidateNodeId(_nodeId.Text, "本机节点名称");
            var peerNodeId = ValidateNodeId(_peerNodeId.Text, "对端节点名称");
            if (string.Equals(nodeId, peerNodeId, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("两台控制端的节点名称不能相同。");
            var publicUrl = ValidateHttpsUrl(_publicUrl.Text, "本机 HTTPS 地址");
            var peerUrl = ValidateHttpsUrl(_peerUrl.Text, "对端 HTTPS 地址");
            var witnessUrl = ValidateHttpsUrl(_witnessUrl.Text, "见证服务 HTTPS 地址");
            var replication = ValidateUncPath(_replicationDirectory.Text, "共享快照目录");
            var keys = ValidateUncPath(_keyDirectory.Text, "共享密钥目录");
            if (_certificate.SelectedItem is not CertificateItem selectedCertificate) throw new InvalidOperationException("请选择已导入本机证书库的 HTTPS 证书。");
            if (_agentIssuer.SelectedItem is not CertificateItem selectedIssuer) throw new InvalidOperationException("请选择已导入本机证书库的 Agent 注册 CA 证书。");
            var username = _adminUser.Text.Trim();
            if (!Regex.IsMatch(username, "^[A-Za-z0-9._-]{3,64}$")) throw new InvalidOperationException("管理员账号长度为 3 至 64，只能使用字母、数字、点、下划线或连字符。");
            if (_adminPassword.Text.Length < 12 || _adminPassword.Text != _adminPasswordRepeat.Text) throw new InvalidOperationException("管理员密码至少 12 位，且两次输入必须一致。");
            if (_witnessToken.Text.Trim().Length is < 32 or > 256) throw new InvalidOperationException("Witness 密钥长度必须为 32 至 256 位。");

            var root = AppContext.BaseDirectory;
            var templatePath = Path.Combine(root, "appsettings.Production.template.json");
            var installerPath = Path.Combine(root, "Install-Service.ps1");
            if (!File.Exists(templatePath) || !File.Exists(installerPath)) throw new InvalidOperationException("安装包不完整，请重新下载安装包。");
            var config = JsonNode.Parse(File.ReadAllText(templatePath))?.AsObject() ?? throw new InvalidOperationException("配置模板无效。");
            var certificate = selectedCertificate.Certificate;
            var certificateSha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            var issuer = selectedIssuer.Certificate;
            var issuerSha256 = Convert.ToHexString(SHA256.HashData(issuer.RawData));
            config["AllowedHosts"] = new Uri(publicUrl).Host;
            config["ConnectionStrings"]!["Monitoring"] = "Data Source=C:\\ProgramData\\MonitoringPlatform\\data\\monitoring.db;Cache=Shared";
            config["Authentication"]!["DataProtectionKeysPath"] = keys;
            config["Authentication"]!["DataProtectionCertificateThumbprint"] = certificate.Thumbprint;
            config["Kestrel"]!["Endpoints"]!["Https"]!["Url"] = "https://0.0.0.0:" + new Uri(publicUrl).Port;
            config["Kestrel"]!["Endpoints"]!["Https"]!["Certificate"]!["Subject"] = certificate.GetNameInfo(X509NameType.SimpleName, false);
            config["AgentEnrollment"]!["Enabled"] = true;
            config["AgentEnrollment"]!["AllowLegacyAgentKeys"] = false;
            config["AgentEnrollment"]!["IssuerCertificateSubject"] = issuer.GetNameInfo(X509NameType.SimpleName, false);
            config["AgentEnrollment"]!["IssuerCertificateSha256"] = issuerSha256;
            config["HighAvailability"]!["Enabled"] = true;
            config["HighAvailability"]!["NodeId"] = nodeId;
            config["HighAvailability"]!["ConfiguredRole"] = _role.SelectedIndex == 0 ? "active" : "passive";
            config["HighAvailability"]!["WitnessUrl"] = witnessUrl;
            config["HighAvailability"]!["WitnessBearerToken"] = "";
            config["HighAvailability"]!["PublicUrl"] = publicUrl;
            config["HighAvailability"]!["PeerNodeId"] = peerNodeId;
            config["HighAvailability"]!["PeerPublicUrl"] = peerUrl;
            config["HighAvailability"]!["PeerReadyUrl"] = peerUrl.TrimEnd('/') + "/api/ready";
            config["HighAvailability"]!["ReplicationDirectory"] = replication;
            var configPath = Path.Combine(root, "appsettings.Production.json");
            File.WriteAllText(configPath, config.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

            var passwordFile = WriteProtectedSecret(_adminPassword.Text);
            var witnessFile = WriteProtectedSecret(_witnessToken.Text.Trim());
            _adminPassword.Clear();
            _adminPasswordRepeat.Clear();
            _witnessToken.Clear();
            _install.Enabled = false;
            _status.Text = "正在创建 Windows 服务，请在弹出的管理员窗口等待完成。";
            var arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(installerPath) +
                " -PackageRoot " + Quote(root) +
                " -PrivateKeyCertificateSha256 " + Quote(certificateSha256) + " " + Quote(issuerSha256) +
                " -DataProtectionCertificateThumbprint " + Quote(certificate.Thumbprint) +
                " -BootstrapUsername " + Quote(username) +
                " -BootstrapPasswordProtectedFile " + Quote(passwordFile) +
                " -WitnessTokenProtectedFile " + Quote(witnessFile);
            var process = Process.Start(new ProcessStartInfo("powershell.exe", arguments) { UseShellExecute = true, Verb = "runas" })
                ?? throw new InvalidOperationException("无法启动管理员安装步骤。");
            process.WaitForExit();
            if (process.ExitCode != 0) throw new InvalidOperationException("控制端安装失败，请根据管理员窗口提示修正后重新打开本向导。");
            _status.ForeColor = Color.ForestGreen;
            _status.Text = "控制端已启动。请在浏览器打开本机 HTTPS 地址登录，然后在控制台完成站点、短信和通知策略设置。";
        }
        catch (Exception exception)
        {
            _status.ForeColor = Color.Firebrick;
            _status.Text = exception.Message;
        }
        finally { _install.Enabled = true; }
    }

    private static string ValidateNodeId(string value, string field)
    {
        var result = value.Trim();
        if (!Regex.IsMatch(result, "^[A-Za-z0-9._-]{1,64}$")) throw new InvalidOperationException(field + "格式不正确。");
        return result;
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        return constraints?.CertificateAuthority == true && keyUsage is not null && (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0;
    }

    private static string ValidateHttpsUrl(string value, string field)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(uri.Host) || uri.AbsolutePath != "/")
            throw new InvalidOperationException(field + "必须是没有路径的 HTTPS 地址。");
        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }

    private static string ValidateUncPath(string value, string field)
    {
        var result = value.Trim();
        if (!result.StartsWith("\\\\", StringComparison.Ordinal) || result.Length < 5) throw new InvalidOperationException(field + "必须是受控共享目录（例如 \\\\fileserver\\monitoring）。");
        return result.TrimEnd('\\');
    }

    private static string WriteProtectedSecret(string value)
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MonitoringPlatform", "ControlSetup");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser));
        return path;
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
}

internal sealed class WitnessSetupForm : Form
{
    private readonly TextBox _publicUrl = new();
    private readonly ComboBox _certificate = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _nodeA = new() { Text = "monitor-a" };
    private readonly TextBox _nodeAToken = new() { UseSystemPasswordChar = true };
    private readonly TextBox _nodeB = new() { Text = "monitor-b" };
    private readonly TextBox _nodeBToken = new() { UseSystemPasswordChar = true };
    private readonly Button _install = new() { Text = "完成配置并启动见证服务", AutoSize = true };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Color.DimGray };

    public WitnessSetupForm()
    {
        Text = "机房运维监控 - Witness 配置";
        Width = 720;
        Height = 410;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 2, RowCount = 10 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Add(panel, 0, "Witness HTTPS 地址", _publicUrl);
        Add(panel, 1, "Witness HTTPS 证书", _certificate);
        Add(panel, 2, "控制端 A 名称", _nodeA);
        Add(panel, 3, "控制端 A 密钥", _nodeAToken);
        Add(panel, 4, "控制端 B 名称", _nodeB);
        Add(panel, 5, "控制端 B 密钥", _nodeBToken);
        panel.Controls.Add(new Label { Text = "Witness 是第三台独立的小型服务，只保存 HA 租约，不保存监控数据。两个密钥必须不同。", AutoSize = true, MaximumSize = new Size(480, 0), ForeColor = Color.DimGray }, 1, 6);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        actions.Controls.Add(_install);
        actions.Controls.Add(new Button { Text = "关闭", AutoSize = true, DialogResult = DialogResult.Cancel });
        panel.Controls.Add(actions, 1, 7);
        panel.Controls.Add(_status, 1, 8);
        Controls.Add(panel);
        LoadCertificates();
        _install.Click += Install;
    }

    private static void Add(TableLayoutPanel panel, int row, string label, System.Windows.Forms.Control control)
    {
        control.Dock = DockStyle.Fill;
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
        panel.Controls.Add(control, 1, row);
    }

    private void LoadCertificates()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        foreach (var certificate in store.Certificates.Cast<X509Certificate2>()
                     .Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7))
                     .OrderBy(item => item.GetNameInfo(X509NameType.SimpleName, false)))
            _certificate.Items.Add(new CertificateItem(certificate));
        if (_certificate.Items.Count > 0) _certificate.SelectedIndex = 0;
    }

    private void Install(object? sender, EventArgs eventArgs)
    {
        try
        {
            if (!Uri.TryCreate(_publicUrl.Text.Trim(), UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps || url.AbsolutePath != "/") throw new InvalidOperationException("Witness HTTPS 地址必须是没有路径的 HTTPS 地址。");
            var nodeA = ValidateNodeId(_nodeA.Text, "控制端 A 名称");
            var nodeB = ValidateNodeId(_nodeB.Text, "控制端 B 名称");
            if (nodeA.Equals(nodeB, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("两个控制端名称不能相同。");
            if (_nodeAToken.Text.Trim().Length is < 32 or > 256 || _nodeBToken.Text.Trim().Length is < 32 or > 256 || _nodeAToken.Text == _nodeBToken.Text) throw new InvalidOperationException("请输入两条不同且长度为 32 至 256 位的 Witness 密钥。");
            if (_certificate.SelectedItem is not CertificateItem selected) throw new InvalidOperationException("请选择已导入本机证书库的 HTTPS 证书。");

            var root = AppContext.BaseDirectory;
            var templatePath = Path.Combine(root, "appsettings.Production.template.json");
            var installerPath = Path.Combine(root, "Install-WitnessService.ps1");
            if (!File.Exists(templatePath) || !File.Exists(installerPath)) throw new InvalidOperationException("安装包不完整，请重新下载安装包。");
            var config = JsonNode.Parse(File.ReadAllText(templatePath))?.AsObject() ?? throw new InvalidOperationException("Witness 配置模板无效。");
            var certificate = selected.Certificate;
            config["Witness"]!["DataPath"] = "C:\\ProgramData\\MonitoringPlatformWitness\\leases.json";
            config["Kestrel"]!["Endpoints"]!["Https"]!["Url"] = "https://0.0.0.0:" + url.Port;
            config["Kestrel"]!["Endpoints"]!["Https"]!["Certificate"]!["Subject"] = certificate.GetNameInfo(X509NameType.SimpleName, false);
            var configPath = Path.Combine(root, "appsettings.Production.json");
            File.WriteAllText(configPath, config.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            var tokenAFile = WriteProtectedSecret(_nodeAToken.Text.Trim());
            var tokenBFile = WriteProtectedSecret(_nodeBToken.Text.Trim());
            _nodeAToken.Clear();
            _nodeBToken.Clear();
            _install.Enabled = false;
            _status.Text = "正在创建 Witness Windows 服务，请在弹出的管理员窗口等待完成。";
            var hash = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            var arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(installerPath) +
                " -PackageRoot " + Quote(root) +
                " -WitnessConfigPath " + Quote(configPath) +
                " -HttpsCertificateSha256 " + Quote(hash) +
                " -NodeAId " + Quote(nodeA) + " -NodeATokenProtectedFile " + Quote(tokenAFile) +
                " -NodeBId " + Quote(nodeB) + " -NodeBTokenProtectedFile " + Quote(tokenBFile);
            var process = Process.Start(new ProcessStartInfo("powershell.exe", arguments) { UseShellExecute = true, Verb = "runas" }) ?? throw new InvalidOperationException("无法启动管理员安装步骤。");
            process.WaitForExit();
            if (process.ExitCode != 0) throw new InvalidOperationException("Witness 安装失败，请根据管理员窗口提示修正后重新打开本向导。");
            _status.ForeColor = Color.ForestGreen;
            _status.Text = "Witness 已启动。请将两个节点名称和对应密钥分别填入控制端 A、B 的安装向导。";
        }
        catch (Exception exception)
        {
            _status.ForeColor = Color.Firebrick;
            _status.Text = exception.Message;
        }
        finally { _install.Enabled = true; }
    }

    private static string ValidateNodeId(string value, string field)
    {
        var result = value.Trim();
        if (!Regex.IsMatch(result, "^[A-Za-z0-9._-]{1,64}$")) throw new InvalidOperationException(field + "格式不正确。");
        return result;
    }

    private static string WriteProtectedSecret(string value)
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MonitoringPlatform", "WitnessSetup");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser));
        return path;
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
}
