using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

sealed record SmsSettingsDto(
    bool Enabled,
    string RolloutMode,
    string Region,
    string SdkAppId,
    string SignName,
    string TemplateId,
    string[] TestPhoneNumbers,
    bool SecretIdConfigured,
    bool SecretKeyConfigured);

sealed record SystemSettingsDto(string SiteName, string SiteDescription, SmsSettingsDto Sms, DateTimeOffset? UpdatedAt);
sealed record SystemSettingsUpdateRequest(
    string SiteName,
    string? SiteDescription,
    bool SmsEnabled,
    string RolloutMode,
    string? Region,
    string? SdkAppId,
    string? SignName,
    string? TemplateId,
    string[]? TestPhoneNumbers,
    string? SecretId,
    string? SecretKey,
    bool ClearSecretId = false,
    bool ClearSecretKey = false);
sealed record ServerGroupDto(string Name, int HostCount);

sealed class RuntimeSettingsStore(
    MonitoringDbContext db,
    IConfiguration configuration,
    IDataProtectionProvider dataProtection)
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("MonitoringPlatform.RuntimeSettings.v1");

    public async Task<SystemSettingsDto> GetDtoAsync(CancellationToken cancellationToken = default)
    {
        var stored = await db.SystemSettings.AsNoTracking().SingleOrDefaultAsync(item => item.Id == 1, cancellationToken);
        if (stored is null) return ToDto(FromConfiguration());
        return ToDto(stored);
    }

    public async Task<SmsOptions> GetSmsOptionsAsync(CancellationToken cancellationToken = default)
    {
        var stored = await db.SystemSettings.AsNoTracking().SingleOrDefaultAsync(item => item.Id == 1, cancellationToken);
        if (stored is null) return FromConfiguration();
        return new SmsOptions
        {
            Enabled = stored.SmsEnabled,
            RolloutMode = stored.SmsRolloutMode,
            Region = stored.SmsRegion,
            SdkAppId = stored.SmsSdkAppId,
            SignName = stored.SmsSignName,
            TemplateId = stored.SmsTemplateId,
            TestPhoneNumbers = ParsePhoneNumbers(stored.SmsTestPhoneNumbersJson),
            SecretId = Unprotect(stored.SmsSecretIdProtected),
            SecretKey = Unprotect(stored.SmsSecretKeyProtected),
        };
    }

    public async Task<SystemSettingsDto> UpdateAsync(SystemSettingsUpdateRequest request, CancellationToken cancellationToken = default)
    {
        var validationError = Validation.ValidateSystemSettings(request);
        if (validationError is not null) throw new ArgumentException(validationError);

        var stored = await db.SystemSettings.SingleOrDefaultAsync(item => item.Id == 1, cancellationToken);
        if (stored is null)
        {
            var fallback = FromConfiguration();
            stored = new SystemSettings
            {
                Id = 1,
                SmsSecretIdProtected = Protect(fallback.SecretId),
                SmsSecretKeyProtected = Protect(fallback.SecretKey),
            };
            db.SystemSettings.Add(stored);
        }

        stored.SiteName = request.SiteName.Trim();
        stored.SiteDescription = request.SiteDescription?.Trim() ?? "";
        stored.SmsEnabled = request.SmsEnabled;
        stored.SmsRolloutMode = request.RolloutMode.Trim().ToLowerInvariant();
        stored.SmsRegion = request.Region?.Trim() ?? "ap-guangzhou";
        stored.SmsSdkAppId = request.SdkAppId?.Trim() ?? "";
        stored.SmsSignName = request.SignName?.Trim() ?? "";
        stored.SmsTemplateId = request.TemplateId?.Trim() ?? "";
        stored.SmsTestPhoneNumbersJson = JsonSerializer.Serialize(NormalizePhoneNumbers(request.TestPhoneNumbers));
        if (request.ClearSecretId) stored.SmsSecretIdProtected = "";
        else if (!string.IsNullOrWhiteSpace(request.SecretId)) stored.SmsSecretIdProtected = Protect(request.SecretId.Trim());
        if (request.ClearSecretKey) stored.SmsSecretKeyProtected = "";
        else if (!string.IsNullOrWhiteSpace(request.SecretKey)) stored.SmsSecretKeyProtected = Protect(request.SecretKey.Trim());
        stored.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return ToDto(stored);
    }

    private SmsOptions FromConfiguration() => configuration.GetSection("TencentCloudSms").Get<SmsOptions>() ?? new SmsOptions();

    private SystemSettingsDto ToDto(SystemSettings stored) => new(
        stored.SiteName,
        stored.SiteDescription,
        new SmsSettingsDto(stored.SmsEnabled, stored.SmsRolloutMode, stored.SmsRegion, stored.SmsSdkAppId,
            stored.SmsSignName, stored.SmsTemplateId, ParsePhoneNumbers(stored.SmsTestPhoneNumbersJson),
            !string.IsNullOrWhiteSpace(Unprotect(stored.SmsSecretIdProtected)), !string.IsNullOrWhiteSpace(Unprotect(stored.SmsSecretKeyProtected))),
        stored.UpdatedAt);

    private SystemSettingsDto ToDto(SmsOptions fallback) => new(
        "机房运维监控",
        "机房基础设施与业务系统运行状态概览",
        new SmsSettingsDto(fallback.Enabled, fallback.RolloutMode, fallback.Region, fallback.SdkAppId, fallback.SignName,
            fallback.TemplateId, NormalizePhoneNumbers(fallback.TestPhoneNumbers), !string.IsNullOrWhiteSpace(fallback.SecretId), !string.IsNullOrWhiteSpace(fallback.SecretKey)),
        null);

    private string Protect(string value) => string.IsNullOrWhiteSpace(value) ? "" : _protector.Protect(value);
    private string Unprotect(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        try { return _protector.Unprotect(value); }
        catch (CryptographicException) { return ""; }
    }

    private static string[] ParsePhoneNumbers(string? serialized)
    {
        try { return NormalizePhoneNumbers(JsonSerializer.Deserialize<string[]>(serialized ?? "[]")); }
        catch (JsonException) { return []; }
    }

    internal static string[] NormalizePhoneNumbers(IEnumerable<string>? phoneNumbers) => (phoneNumbers ?? [])
        .Where(number => !string.IsNullOrWhiteSpace(number)).Select(number => number.Trim()).Distinct(StringComparer.Ordinal).ToArray();
}
