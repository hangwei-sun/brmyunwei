static class IncidentState { public const string Open = "未确认"; public const string Acknowledged = "已确认"; public const string Silenced = "已静默"; public const string Maintenance = "维护中"; }
static class ProbeType { public const string Icmp = "icmp"; public const string Tcp = "tcp"; public const string Http = "http"; public static readonly HashSet<string> All = [Icmp, Tcp, Http]; }
static class ProbeStatus { public const string Unknown = "未知"; public const string Healthy = "健康"; public const string Failing = "故障"; }
sealed record LoginRequest(string? Username, string? Password);
sealed record CreateUserRequest(string? Username, string? Password, string? Role);
sealed record UpdateUserRequest(string? Role, bool Enabled, string? Password);
sealed record UserDto(string Username, string Role, bool Enabled, DateTimeOffset? LastLoginAt, DateTimeOffset CreatedAt);
sealed record IncidentActionRequest(string? Note);
sealed record AlertRuleUpdate(bool Enabled, double WarningThreshold, double CriticalThreshold, int TriggerCount = 1, int RecoveryCount = 2);
sealed record NotificationPolicyRequest(string Name, string ServerGroup, string Severity, string ContactGroup, bool Enabled, int RepeatMinutes);
sealed record SmsTestRequest(string[] PhoneNumbers, string[] TemplateParameters);
sealed record HostRequest(string Name, string Ip, string Room, string Service, string? Group = null);
sealed record ProbeRequest(string Name, string Type, string Target, int? Port, int? ExpectedStatus, bool Enabled, int IntervalSeconds, int TimeoutMilliseconds, int FailureThreshold, int RecoveryThreshold);
sealed record ProbeDto(int Id, string Host, string Name, string Type, string Target, int? Port, int? ExpectedStatus, bool Enabled, int IntervalSeconds, int TimeoutMilliseconds, int FailureThreshold, int RecoveryThreshold, string Status, int ConsecutiveFailures, int ConsecutiveSuccesses, string? LastCheckedAt, string? LastSuccessAt, string? LastError)
{
    public static ProbeDto From(ProbeDefinition probe) => new(probe.Id, probe.Host?.Name ?? "未知", probe.Name, probe.Type, probe.Target, probe.Port, probe.ExpectedStatus, probe.Enabled, probe.IntervalSeconds, probe.TimeoutMilliseconds, probe.FailureThreshold, probe.RecoveryThreshold, probe.Status, probe.ConsecutiveFailures, probe.ConsecutiveSuccesses, probe.LastCheckedAt?.ToString("O"), probe.LastSuccessAt?.ToString("O"), probe.LastError);
}
sealed record AgentServiceStatusRequest(string Name, string Status);
sealed record AgentIngestRequest(string HostName, long Sequence, DateTimeOffset CollectedAt, double Cpu, double Memory, double Disk, double Latency, double? NetworkBytesPerSecond = null, DateTimeOffset? BootTime = null, AgentServiceStatusRequest[]? Services = null, string? AgentVersion = null);
sealed record AgentKeyResponse(string HostName, string AgentKey, DateTimeOffset RotatedAt);
sealed record HostDto(string Id, string Ip, string Room, string Service, string Group, string Status, double? Cpu, double? Memory, double? Disk, double? Latency, double? NetworkBytesPerSecond, DateTimeOffset? BootTime, string? AgentVersion, string Heartbeat)
{
    public static HostDto From(Host host) => new(host.Name, host.Ip, host.Room, host.Service, host.Group, host.Status, host.Cpu, host.Memory, host.Disk, host.Latency, host.NetworkBytesPerSecond, host.BootTime, host.AgentVersion, $"{Math.Max(0, (int)(DateTimeOffset.UtcNow - host.LastHeartbeatAt).TotalSeconds)} 秒前");
}
sealed record HostServiceStatusDto(string Name, string Status, DateTimeOffset UpdatedAt);
sealed record NotificationDeliveryDto(Guid IncidentId, int PolicyId, string Status, int Attempts, DateTimeOffset? LastAttemptAt, DateTimeOffset? LastSentAt, DateTimeOffset NextAttemptAt, string? LastError);
sealed record IncidentDto(Guid Id, string Host, string Ip, string Title, string Severity, string Started, string Duration, string Signal, string Value, string State)
{
    public static IncidentDto From(Incident incident) => new(incident.Id, incident.Host?.Name ?? "未知", incident.Host?.Ip ?? "-", incident.Title, incident.Severity, incident.StartedAt.ToLocalTime().ToString("HH:mm:ss"), $"{Math.Max(1, (int)(DateTimeOffset.UtcNow - incident.StartedAt).TotalMinutes)} 分钟", incident.Signal, incident.Value, incident.State);
}
sealed record HaCapability(string Mode, bool FailoverSupported, string Message)
{
    public static readonly HaCapability Current = new("single-node", false, "当前版本未实现真实主备协调与故障转移。");
}

static class Validation
{
    public static string? ValidateHost(HostRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 64) return "服务器名称为必填项，且不得超过 64 个字符。";
        if (!System.Net.IPAddress.TryParse(request.Ip, out _)) return "请输入有效的 IPv4 或 IPv6 地址。";
        if (string.IsNullOrWhiteSpace(request.Room) || request.Room.Trim().Length > 64) return "机房为必填项，且不得超过 64 个字符。";
        if (string.IsNullOrWhiteSpace(request.Service) || request.Service.Trim().Length > 64) return "业务系统为必填项，且不得超过 64 个字符。";
        if (request.Group is not null && (string.IsNullOrWhiteSpace(request.Group) || request.Group.Trim().Length > 64)) return "服务器组不得为空或超过 64 个字符。";
        return null;
    }
    public static bool ValidMetric(double value) => double.IsFinite(value) && value is >= 0 and <= 100;
    public static string? ValidateNotificationPolicy(NotificationPolicyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 80) return "策略名称为必填项，且不得超过 80 个字符。";
        if (string.IsNullOrWhiteSpace(request.ServerGroup) || request.ServerGroup.Trim().Length > 64) return "服务器组为必填项，且不得超过 64 个字符。";
        if (request.Severity is not ("严重" or "警告")) return "严重级别必须为严重或警告。";
        if (string.IsNullOrWhiteSpace(request.ContactGroup) || request.ContactGroup.Trim().Length > 64) return "联系人组为必填项，且不得超过 64 个字符。";
        if (request.RepeatMinutes is < 5 or > 1440) return "重复提醒间隔必须在 5 到 1440 分钟之间。";
        return null;
    }

    public static string? ValidateProbe(ProbeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 80) return "探测名称为必填项，且不得超过 80 个字符。";
        var type = request.Type?.Trim().ToLowerInvariant();
        if (type is null || !ProbeType.All.Contains(type)) return "探测类型必须为 icmp、tcp 或 http。";
        if (request.IntervalSeconds is < 10 or > 3600) return "探测间隔必须在 10 到 3600 秒之间。";
        if (request.TimeoutMilliseconds is < 100 or > 30000) return "超时必须在 100 到 30000 毫秒之间。";
        if (request.FailureThreshold is < 1 or > 20 || request.RecoveryThreshold is < 1 or > 20) return "连续失败和恢复阈值必须在 1 到 20 次之间。";
        if (type == ProbeType.Http)
        {
            if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                !string.IsNullOrEmpty(uri.UserInfo)) return "HTTP 探测目标必须是无账号密码的 http 或 https 地址。";
            if (request.Port is not null) return "HTTP 探测不支持单独设置端口，请在 URL 中指定。";
            if (request.ExpectedStatus is < 100 or > 599) return "期望 HTTP 状态码必须在 100 到 599 之间。";
        }
        else
        {
            if (string.IsNullOrWhiteSpace(request.Target) || request.Target.Trim().Length > 253 || Uri.CheckHostName(request.Target.Trim()) == UriHostNameType.Unknown)
                return "ICMP/TCP 探测目标必须是有效 IP 或主机名。";
            if (type == ProbeType.Tcp && request.Port is not (>= 1 and <= 65535)) return "TCP 探测端口必须在 1 到 65535 之间。";
            if (type == ProbeType.Icmp && request.Port is not null) return "ICMP 探测不支持端口。";
            if (request.ExpectedStatus is not null) return "仅 HTTP 探测支持期望状态码。";
        }
        return null;
    }
}
