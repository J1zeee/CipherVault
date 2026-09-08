using System.IO;
using System.Windows;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class SecureClipboardTests
{
    [Fact]
    public void Payload_CarriesTheText()
    {
        var payload = SecureClipboard.BuildPayload("hunter2");

        Assert.Equal("hunter2", payload.GetData(DataFormats.UnicodeText));
    }

    [Fact]
    public void Payload_OptsOutOfClipboardHistory()
    {
        var payload = SecureClipboard.BuildPayload("hunter2");

        Assert.True(payload.GetDataPresent(SecureClipboard.ClipboardHistoryFormat));
    }

    [Fact]
    public void Payload_OptsOutOfCloudClipboardSync()
    {
        var payload = SecureClipboard.BuildPayload("hunter2");

        Assert.True(payload.GetDataPresent(SecureClipboard.CloudClipboardFormat));
    }

    [Fact]
    public void Payload_OptsOutOfClipboardMonitors()
    {
        var payload = SecureClipboard.BuildPayload("hunter2");

        Assert.True(payload.GetDataPresent(SecureClipboard.ExcludeFromMonitorFormat));
    }

    // --- ownership tracking: never wipe content this app did not put there ---

    [Fact]
    public void RememberedContentIsRecognised()
    {
        SecureClipboard.RememberCopy("hunter2");

        Assert.True(SecureClipboard.IsRememberedContent("hunter2"));
    }

    [Fact]
    public void ContentReplacedBySomeoneElseIsNotOurs()
    {
        SecureClipboard.RememberCopy("hunter2");

        Assert.False(SecureClipboard.IsRememberedContent("a shopping list"));
    }

    [Fact]
    public void NothingIsOursBeforeAnythingWasCopied()
    {
        SecureClipboard.ForgetCopy();

        Assert.False(SecureClipboard.IsRememberedContent("anything"));
    }

    [Fact]
    public void AnEmptyOrMissingClipboardIsNotOurs()
    {
        SecureClipboard.RememberCopy("hunter2");

        Assert.False(SecureClipboard.IsRememberedContent(null));
        Assert.False(SecureClipboard.IsRememberedContent(""));
    }

    [Fact]
    public void OptOutFormats_CarryAZeroDwordAsWindowsExpects()
    {
        var payload = SecureClipboard.BuildPayload("hunter2");

        var stream = Assert.IsAssignableFrom<MemoryStream>(payload.GetData(SecureClipboard.ClipboardHistoryFormat));
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, stream.ToArray());
    }
}
