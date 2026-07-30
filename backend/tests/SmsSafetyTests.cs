using Xunit;

public sealed class SmsSafetyTests
{
    [Fact]
    public void TestMode_OnlyAllowsConfiguredTestNumbers()
    {
        var settings = new SmsOptions { Enabled = true, RolloutMode = "test", TestPhoneNumbers = ["+8613800000000"] };

        Assert.Null(SmsSafety.Validate(settings, ["+8613800000000"]));
        Assert.Contains("Test mode", SmsSafety.Validate(settings, ["+8613900000000"]));
    }

    [Fact]
    public void LiveMode_RequiresExplicitEnablement()
    {
        Assert.Contains("disabled", SmsSafety.Validate(new SmsOptions { Enabled = false, RolloutMode = "live" }, ["+8613900000000"]));
        Assert.Null(SmsSafety.Validate(new SmsOptions { Enabled = true, RolloutMode = "live" }, ["+8613900000000"]));
    }
}
