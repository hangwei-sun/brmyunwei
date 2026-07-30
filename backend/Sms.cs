using Microsoft.Extensions.Options;
using TencentCloud.Common;
using TencentCloud.Common.Profile;
using TencentCloud.Sms.V20210111;
using TencentCloud.Sms.V20210111.Models;

sealed class SmsOptions { public string SecretId { get; init; } = ""; public string SecretKey { get; init; } = ""; public string Region { get; init; } = "ap-guangzhou"; public string SdkAppId { get; init; } = ""; public string SignName { get; init; } = ""; public string TemplateId { get; init; } = ""; }
sealed record SmsSendResult(bool Sent, string? RequestId, string? Error);
sealed class SmsSender(IOptions<SmsOptions> options, ILogger<SmsSender> logger)
{
    public Task<SmsSendResult> SendAsync(string[] phoneNumbers, string[] templateParameters)
    {
        var settings = options.Value;
        if (string.IsNullOrWhiteSpace(settings.SecretId) || string.IsNullOrWhiteSpace(settings.SecretKey) || string.IsNullOrWhiteSpace(settings.SdkAppId) || string.IsNullOrWhiteSpace(settings.SignName) || string.IsNullOrWhiteSpace(settings.TemplateId))
            return Task.FromResult(new SmsSendResult(false, null, "TencentCloudSms is not configured."));
        try
        {
            var credential = new Credential { SecretId = settings.SecretId, SecretKey = settings.SecretKey };
            var client = new SmsClient(credential, settings.Region, new ClientProfile());
            var response = client.SendSmsSync(new SendSmsRequest { SmsSdkAppId = settings.SdkAppId, SignName = settings.SignName, TemplateId = settings.TemplateId, PhoneNumberSet = phoneNumbers, TemplateParamSet = templateParameters });
            var status = response.SendStatusSet?.FirstOrDefault();
            return Task.FromResult(new SmsSendResult(status?.Code == "Ok", response.RequestId, status?.Message));
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Tencent Cloud SMS send failed");
            return Task.FromResult(new SmsSendResult(false, null, exception.Message));
        }
    }
}
