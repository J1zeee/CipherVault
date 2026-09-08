using System.Security;
using System.Text;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class SecureStringConverterTests
{
    private static SecureString Make(string value)
    {
        var secure = new SecureString();
        foreach (var c in value) secure.AppendChar(c);
        secure.MakeReadOnly();
        return secure;
    }

    [Fact]
    public void ConvertsAsciiToUtf8()
    {
        using var secure = Make("open sesame");

        var bytes = SecureStringConverter.ToUtf8Bytes(secure);

        Assert.Equal(Encoding.UTF8.GetBytes("open sesame"), bytes);
    }

    [Fact]
    public void ConvertsNonAsciiToUtf8()
    {
        using var secure = Make("пароль-ключ");

        var bytes = SecureStringConverter.ToUtf8Bytes(secure);

        Assert.Equal(Encoding.UTF8.GetBytes("пароль-ключ"), bytes);
    }

    [Fact]
    public void ConvertsCharactersOutsideTheBasicPlane()
    {
        using var secure = Make("key\U0001F510end");

        var bytes = SecureStringConverter.ToUtf8Bytes(secure);

        Assert.Equal(Encoding.UTF8.GetBytes("key\U0001F510end"), bytes);
    }

    [Fact]
    public void AnEmptySecureStringGivesAnEmptyArray()
    {
        using var secure = Make("");

        Assert.Empty(SecureStringConverter.ToUtf8Bytes(secure));
    }

    [Fact]
    public void TheSecureStringItselfIsNotConsumed()
    {
        using var secure = Make("open sesame");

        SecureStringConverter.ToUtf8Bytes(secure);
        var second = SecureStringConverter.ToUtf8Bytes(secure);

        Assert.Equal(Encoding.UTF8.GetBytes("open sesame"), second);
    }
}
