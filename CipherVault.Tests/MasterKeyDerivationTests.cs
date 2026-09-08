using System.Text;
using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class MasterKeyDerivationTests
{
    private static byte[] Salt(byte seed)
    {
        var salt = new byte[32];
        for (var i = 0; i < salt.Length; i++) salt[i] = (byte)(seed + i);
        return salt;
    }

    private static byte[] Read(SecureBuffer buffer)
    {
        buffer.BeginAccess();
        var bytes = buffer.ToArray();
        buffer.EndAccess();
        return bytes;
    }

    [Fact]
    public void SamePasswordAndSaltProduceTheSameKey()
    {
        var salt = Salt(1);

        using var first = MasterKeyDerivation.Derive(Encoding.UTF8.GetBytes("open sesame"), salt);
        using var second = MasterKeyDerivation.Derive(Encoding.UTF8.GetBytes("open sesame"), salt);

        Assert.Equal(Read(first), Read(second));
    }

    [Fact]
    public void ADifferentSaltProducesADifferentKey()
    {
        using var first = MasterKeyDerivation.Derive(Encoding.UTF8.GetBytes("open sesame"), Salt(1));
        using var second = MasterKeyDerivation.Derive(Encoding.UTF8.GetBytes("open sesame"), Salt(9));

        Assert.NotEqual(Read(first), Read(second));
    }

    [Fact]
    public void TheCallersBuffersAreLeftAloneByDefault()
    {
        var password = Encoding.UTF8.GetBytes("open sesame");
        var salt = Salt(1);

        using var key = MasterKeyDerivation.Derive(password, salt);

        Assert.Equal(Encoding.UTF8.GetBytes("open sesame"), password);
        Assert.Equal(Salt(1), salt);
    }

    [Fact]
    public void ThePasswordIsWipedWhenTheCallerAsksForIt()
    {
        var password = Encoding.UTF8.GetBytes("open sesame");

        using var key = MasterKeyDerivation.Derive(password, Salt(1), wipePassword: true);

        Assert.Equal(new byte[password.Length], password);
    }
}
