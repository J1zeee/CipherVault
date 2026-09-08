using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class SecureBufferTests
{
    private static byte[] SampleKey()
    {
        var key = new byte[32];
        for (var i = 0; i < key.Length; i++)
            key[i] = (byte)(i * 7 + 1);
        return key;
    }

    [Fact]
    public void ContentSurvivesAProtectUnprotectRoundTrip()
    {
        var key = SampleKey();
        using var buffer = new SecureBuffer(32);

        buffer.Write(key);
        buffer.EndAccess();

        buffer.BeginAccess();
        var readBack = buffer.ToArray();
        buffer.EndAccess();

        Assert.Equal(key, readBack);
    }

    [Fact]
    public void ProtectedBufferDoesNotHoldThePlaintext()
    {
        var key = SampleKey();
        using var buffer = new SecureBuffer(32);

        buffer.Write(key);
        buffer.EndAccess();

        Assert.NotEqual(key, buffer.ToArray());
    }

    [Fact]
    public void FreshBufferIsPinnedInRam()
    {
        using var buffer = new SecureBuffer(32);

        Assert.True(buffer.IsPagePinned);
    }

    [Fact]
    public void PageStaysPinnedWhilePlaintextIsExposed()
    {
        using var buffer = new SecureBuffer(32);
        buffer.Write(SampleKey());
        buffer.EndAccess();

        buffer.BeginAccess();
        try
        {
            Assert.True(buffer.IsPagePinned, "plaintext was exposed on a pageable buffer");
        }
        finally
        {
            buffer.EndAccess();
        }
    }

    [Fact]
    public void ClearWipesTheContent()
    {
        using var buffer = new SecureBuffer(32);
        buffer.Write(SampleKey());

        buffer.Clear();

        Assert.Equal(new byte[32], buffer.ToArray());
    }

    [Fact]
    public void UsingTheBufferAfterDisposeIsRejected()
    {
        var buffer = new SecureBuffer(32);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buffer.ToArray());
    }
}
