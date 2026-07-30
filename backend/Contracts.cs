static class IncidentState { public const string Open = "未确认"; public const string Acknowledged = "已确认"; public const string Silenced = "已静默"; public const string Maintenance = "维护中"; }
sealed record LoginRequest(string? Username, string? Password);
sealed record CreateUserRequest(string? Username, string? Password, string? Role);
sealed record UpdateUserRequest(string? Role, bool Enabled, string? Password);
sealed record UserDto(string Username, string Role, bool Enabled, DateTimeOffset? LastLoginAt, DateTimeOffset CreatedAt);
sealed record IncidentActionRequest(string? Note);
sealed record AlertRuleUpdate(bool Enabled, double WarningThreshold, double CriticalThreshold);
sealed record NotificationPolicyUpdate(bool Enabled, int RepeatMinutes);
sealed record SmsTestRequest(string[] PhoneNumbers, string[] TemplateParameters);
sealed record HostRequest(string Name, string Ip, string Room, string Service);
sealed record AgentIngestRequest(string HostName, long Sequence, DateTimeOffset CollectedAt, double Cpu, double Memory, double Disk, double Latency);
sealed record AgentKeyResponse(string HostName, string AgentKey, DateTimeOffset RotatedAt);
sealed record HostDto(string Id, string Ip, string Room, string Service, string Status, double? Cpu, double? Memory, double? Disk, double? Latency, string Heartbeat)
{
    public static HostDto From(Host host) => new(host.Name, host.Ip, host.Room, host.Service, host.Status, host.Cpu, host.Memory, host.Disk, host.Latency, $"{Math.Max(0, (int)(DateTimeOffset.UtcNow - host.LastHeartbeatAt).TotalSeconds)} 秒前");
}
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
        return null;
    }
    public static bool ValidMetric(double value) => double.IsFinite(value) && value is >= 0 and <= 100;
}
