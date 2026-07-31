using System.Diagnostics;
using System.Net;
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
        if (args.Any(arg => string.Equals(arg, "--witness", StringComparison.OrdinalIgnoreCase))) Application.Run(new WitnessSetupForm());
        else if (args.Any(arg => string.Equals(arg, "--lan-certificates", StringComparison.OrdinalIgnoreCase))) Application.Run(new LanCertificatePackForm());
        else Application.Run(new ControlSetupForm());
    }
}

internal sealed class CertificateItem(X509Certificate2 certificate)
{
    public X509Certificate2 Certificate { get; } = certificate;
    public override string ToString() => $"{Certificate.GetNameInfo(X509NameType.SimpleName, false)} | expires {Certificate.NotAfter:yyyy-MM-dd} | {Certificate.Thumbprint}";
}

internal sealed class LanCertificatePackForm : Form
{
    private readonly TextBox _controlA = new();
    private readonly TextBox _controlB = new();
    private readonly TextBox _witness = new();
    private readonly TextBox _output = new() { Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MonitoringPlatform-LanCertificates") };
    private readonly TextBox _password = new() { UseSystemPasswordChar = true };
    private readonly TextBox _passwordRepeat = new() { UseSystemPasswordChar = true };
    private readonly Button _create = new() { Text = "生成内网证书包", AutoSize = true };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(560, 0) };

    public LanCertificatePackForm()
    {
        Text = "机房运维监控 - 内网证书包";
        Width = 760;
        Height = 420;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false;
        MaximizeBox = false;
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 2, RowCount = 10 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Add(panel, 0, "控制端 A IP", _controlA);
        Add(panel, 1, "控制端 B IP", _controlB);
        Add(panel, 2, "Witness IP", _witness);
        var outputPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        _output.Width = 395;
        outputPanel.Controls.Add(_output);
        var browse = new Button { Text = "选择位置", AutoSize = true };
        browse.Click += (_, _) => ChooseOutput();
        outputPanel.Controls.Add(browse);
        Add(panel, 3, "保存证书包的位置", outputPanel);
        Add(panel, 4, "证书包口令", _password);
        Add(panel, 5, "再次输入口令", _passwordRepeat);
        panel.Controls.Add(new Label { Text = "生成后请将对应 PFX 文件复制到 A、B、Witness。使用 Windows 的双击导入向导导入“本地计算机 / 个人”证书库；将 LAN-Root.cer 导入三台机器的“受信任的根证书颁发机构”。Agent 不需要导入根证书。", AutoSize = true, MaximumSize = new Size(520, 0), ForeColor = Color.DimGray }, 1, 6);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        actions.Controls.Add(_create);
        actions.Controls.Add(new Button { Text = "关闭", AutoSize = true, DialogResult = DialogResult.Cancel });
        panel.Controls.Add(actions, 1, 7);
        panel.Controls.Add(_status, 1, 8);
        Controls.Add(panel);
        _create.Click += Create;
    }

    private static void Add(TableLayoutPanel panel, int row, string label, System.Windows.Forms.Control control)
    {
        control.Dock = DockStyle.Fill;
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
        panel.Controls.Add(control, 1, row);
    }

    private void ChooseOutput()
    {
        using var dialog = new FolderBrowserDialog { Description = "选择保存内网证书包的位置", SelectedPath = _output.Text };
        if (dialog.ShowDialog(this) == DialogResult.OK) _output.Text = Path.Combine(dialog.SelectedPath, "MonitoringPlatform-LanCertificates");
    }

    private void Create(object? sender, EventArgs eventArgs)
    {
        try
        {
            var controlA = ParseIp(_controlA.Text, "控制端 A IP");
            var controlB = ParseIp(_controlB.Text, "控制端 B IP");
            var witness = ParseIp(_witness.Text, "Witness IP");
            if (controlA.Equals(controlB) || controlA.Equals(witness) || controlB.Equals(witness)) throw new InvalidOperationException("三台机器必须使用不同 IP。");
            if (_password.Text.Length < 12 || _password.Text != _passwordRepeat.Text) throw new InvalidOperationException("证书包口令至少 12 位，且两次输入必须一致。");
            var output = Path.GetFullPath(_output.Text.Trim());
            if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any()) throw new InvalidOperationException("保存目录已存在内容，请选择一个空位置。");
            Directory.CreateDirectory(output);
            _create.Enabled = false;
            _status.Text = "正在生成内网根证书和各机器证书...";

            using var rootKey = RSA.Create(4096);
            var rootRequest = new CertificateRequest("CN=Monitoring Platform LAN Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
            File.WriteAllBytes(Path.Combine(output, "LAN-Root.cer"), root.Export(X509ContentType.Cert));
            CreateServerCertificate(root, controlA, Path.Combine(output, "Control-A.pfx"), _password.Text);
            CreateServerCertificate(root, controlB, Path.Combine(output, "Control-B.pfx"), _password.Text);
            CreateServerCertificate(root, witness, Path.Combine(output, "Witness.pfx"), _password.Text);
            CreateDataProtectionCertificate(root, Path.Combine(output, "DataProtection.pfx"), _password.Text);
            using var issuer = CreateAgentIssuer(root);
            File.WriteAllBytes(Path.Combine(output, "Agent-Issuer.cer"), issuer.Export(X509ContentType.Cert));
            File.WriteAllBytes(Path.Combine(output, "Agent-Issuer.pfx"), issuer.Export(X509ContentType.Pfx, _password.Text));
            File.WriteAllText(Path.Combine(output, "使用说明.txt"), "1. 将 LAN-Root.cer 导入控制端 A、控制端 B、Witness 的本地计算机\\受信任的根证书颁发机构。\r\n2. 将 Control-A.pfx 导入控制端 A 的本地计算机\\个人；Control-B.pfx 导入控制端 B；Witness.pfx 导入 Witness。\r\n3. 将 DataProtection.pfx 和 Agent-Issuer.pfx 都导入控制端 A、B 的本地计算机\\个人；将 Agent-Issuer.cer 导入 A、B 的本地计算机\\受信任的根证书颁发机构。\r\n4. 证书包口令仅用于导入 PFX，请在导入完成后保存在单位密码管理器中。", Encoding.UTF8);
            _password.Clear();
            _passwordRepeat.Clear();
            _status.ForeColor = Color.ForestGreen;
            _status.Text = "内网证书包已生成。按同目录的“使用说明.txt”通过 Windows 证书导入向导导入，然后运行控制端和 Witness 配置向导。";
        }
        catch (Exception exception)
        {
            _status.ForeColor = Color.Firebrick;
            _status.Text = exception.Message;
        }
        finally { _create.Enabled = true; }
    }

    private static IPAddress ParseIp(string value, string field) => IPAddress.TryParse(value.Trim(), out var parsed) ? parsed : throw new InvalidOperationException(field + "必须是有效 IPv4 或 IPv6 地址。");

    private static void CreateServerCertificate(X509Certificate2 issuer, IPAddress address, string output, string password)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest($"CN={address}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(address);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var issued = request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5), CreateSerial());
        using var withKey = issued.CopyWithPrivateKey(key);
        File.WriteAllBytes(output, withKey.Export(X509ContentType.Pfx, password));
    }

    private static X509Certificate2 CreateAgentIssuer(X509Certificate2 root)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Monitoring Platform Agent Issuer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5), CreateSerial());
        return issued.CopyWithPrivateKey(key);
    }

    private static void CreateDataProtectionCertificate(X509Certificate2 root, string output, string password)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=Monitoring Platform Data Protection", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5), CreateSerial());
        using var withKey = issued.CopyWithPrivateKey(key);
        File.WriteAllBytes(output, withKey.Export(X509ContentType.Pfx, password));
    }

    private static byte[] CreateSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        return serial;
    }
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
    private readonly ComboBox _dataProtectionCertificate = new() { DropDownStyle = ComboBoxStyle.DropDownList };
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
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(22), ColumnCount = 2, RowCount = 18 };
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
        Add(panel, 9, "共享数据保护证书", _dataProtectionCertificate);
        Add(panel, 10, "Agent 注册 CA 证书", _agentIssuer);
        Add(panel, 11, "首次管理员账号", _adminUser);
        Add(panel, 12, "首次管理员密码", _adminPassword);
        Add(panel, 13, "再次输入密码", _adminPasswordRepeat);
        Add(panel, 14, "本节点 Witness 密钥", _witnessToken);
        panel.Controls.Add(new Label
        {
            Text = "两台控制端使用各自的 HTTPS 证书，但必须导入同一张数据保护证书和 Agent 注册 CA，并使用同一个共享密钥目录。Witness 密钥在服务环境保存，不写入配置文件。",
            AutoSize = true,
            MaximumSize = new Size(520, 0),
            ForeColor = Color.DimGray
        }, 1, 15);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        actions.Controls.Add(_install);
        actions.Controls.Add(new Button { Text = "关闭", AutoSize = true, DialogResult = DialogResult.Cancel });
        panel.Controls.Add(actions, 1, 16);
        panel.Controls.Add(_status, 1, 17);
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
                     .Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7))
                     .OrderBy(item => item.GetNameInfo(X509NameType.SimpleName, false)))
            _dataProtectionCertificate.Items.Add(new CertificateItem(certificate));
        foreach (var certificate in store.Certificates.Cast<X509Certificate2>()
                     .Where(item => item.HasPrivateKey && item.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7) && IsCertificateAuthority(item))
                     .OrderBy(item => item.GetNameInfo(X509NameType.SimpleName, false)))
            _agentIssuer.Items.Add(new CertificateItem(certificate));
        if (_certificate.Items.Count > 0) _certificate.SelectedIndex = 0;
        if (_dataProtectionCertificate.Items.Count > 0) _dataProtectionCertificate.SelectedIndex = 0;
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
            if (_dataProtectionCertificate.SelectedItem is not CertificateItem selectedDataProtectionCertificate) throw new InvalidOperationException("请选择两台控制端共同导入的数据保护证书。");
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
            var dataProtectionCertificate = selectedDataProtectionCertificate.Certificate;
            var issuer = selectedIssuer.Certificate;
            var issuerSha256 = Convert.ToHexString(SHA256.HashData(issuer.RawData));
            config["AllowedHosts"] = new Uri(publicUrl).Host;
            config["ConnectionStrings"]!["Monitoring"] = "Data Source=C:\\ProgramData\\MonitoringPlatform\\data\\monitoring.db;Cache=Shared";
            config["Authentication"]!["DataProtectionKeysPath"] = keys;
            config["Authentication"]!["DataProtectionCertificateThumbprint"] = dataProtectionCertificate.Thumbprint;
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
                " -DataProtectionCertificateThumbprint " + Quote(dataProtectionCertificate.Thumbprint) +
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
