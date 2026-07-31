using TencentCloud.Common;
using TencentCloud.Common.Profile;
using TencentCloud.Sms.V20210111;
using TencentCloud.Sms.V20210111.Models;

sealed class SmsOptions { public bool Enabled { get; init; } public string RolloutMode { get; init; } = "disabled"; public string[] TestPhoneNumbers { get; init; } = []; public string SecretId { get; init; } = ""; public string SecretKey { get; init; } = ""; public string Region { get; init; } = "ap-guangzhou"; public string SdkAppId { get; init; } = ""; public string SignName { get; init; } = ""; public string TemplateId { get; init; } = ""; }
sealed record SmsSendResult(bool Sent, string? RequestId, string? Error);
static class SmsSafety
{
    public static string? Validate(SmsOptions settings, string[] phoneNumbers)
    {
        var mode = settings.RolloutMode.Trim().ToLowerInvariant();
        if (!settings.Enabled || mode == "disabled") return "TencentCloudSms is disabled.";
        if (mode is not ("test" or "live")) return "TencentCloudSms RolloutMode must be disabled, test, or live.";
        if (phoneNumbers is null || phoneNumbers.Length is < 1 or > 200 || phoneNumbers.Any(number => !System.Text.RegularExpressions.Regex.IsMatch(number ?? "", @"^\+[1-9]\d{7,14}$")))
            return "Phone numbers must use E.164 format.";
        if (mode == "test")
        {
            var allowList = (settings.TestPhoneNumbers ?? []).Where(number => !string.IsNullOrWhiteSpace(number)).ToHashSet(StringComparer.Ordinal);
            if (allowList.Count == 0 || phoneNumbers.Any(number => !allowList.Contains(number))) return "Test mode only permits configured test phone numbers.";
        }
        return null;
    }
}
sealed class SmsSender(RuntimeSettingsStore settingsStore, ILogger<SmsSender> logger)
{
    public async Task<SmsSendResult> SendAsync(string[] phoneNumbers, string[] templateParameters)
    {
        var settings = await settingsStore.GetSmsOptionsAsync();
        var safetyError = SmsSafety.Validate(settings, phoneNumbers);
        if (safetyError is not null) return new SmsSendResult(false, null, safetyError);
        if (string.IsNullOrWhiteSpace(settings.SecretId) || string.IsNullOrWhiteSpace(settings.SecretKey) || string.IsNullOrWhiteSpace(settings.SdkAppId) || string.IsNullOrWhiteSpace(settings.SignName) || string.IsNullOrWhiteSpace(settings.TemplateId))
            return new SmsSendResult(false, null, "TencentCloudSms is not configured.");
        if (templateParameters is null || templateParameters.Length is < 1 or > 12 || templateParameters.Any(value => value is null || value.Length > 128))
            return new SmsSendResult(false, null, "Template parameters are invalid.");
        try
        {
            var credential = new Credential { SecretId = settings.SecretId, SecretKey = settings.SecretKey };
            var client = new SmsClient(credential, settings.Region, new ClientProfile());
            var response = client.SendSmsSync(new SendSmsRequest { SmsSdkAppId = settings.SdkAppId, SignName = settings.SignName, TemplateId = settings.TemplateId, PhoneNumberSet = phoneNumbers, TemplateParamSet = templateParameters });
            var statuses = response.SendStatusSet ?? [];
            var failures = statuses.Where(status => !string.Equals(status.Code, "Ok", StringComparison.OrdinalIgnoreCase)).ToList();
            if (statuses.Length != phoneNumbers.Length || failures.Count > 0)
            {
                var error = failures.Count > 0
                    ? string.Join("; ", failures.Select(status => $"{status.Code}: {status.Message}"))
                    : $"Tencent Cloud returned {statuses.Length} statuses for {phoneNumbers.Length} recipients.";
                return new SmsSendResult(false, response.RequestId, error);
            }
            return new SmsSendResult(true, response.RequestId, null);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Tencent Cloud SMS send failed");
            return new SmsSendResult(false, null, exception.Message);
        }
    }
}
