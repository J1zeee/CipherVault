using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class VaultNameValidatorTests
{
    [Theory]
    [InlineData("Personal")]
    [InlineData("Work vault")]
    [InlineData("Рабочий")]
    [InlineData("backup-2026")]
    public void AcceptsOrdinaryNames(string name)
    {
        Assert.True(VaultNameValidator.IsValid(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void RejectsBlankNames(string name)
    {
        Assert.False(VaultNameValidator.IsValid(name));
    }

    [Theory]
    [InlineData("..")]
    [InlineData("../escape")]
    [InlineData(@"..\..\Windows")]
    [InlineData(@"sub\vault")]
    [InlineData("sub/vault")]
    public void RejectsNamesThatEscapeTheVaultsRoot(string name)
    {
        Assert.False(VaultNameValidator.IsValid(name));
    }

    [Theory]
    [InlineData("a:b")]
    [InlineData("what?")]
    [InlineData("star*")]
    [InlineData("pipe|name")]
    [InlineData("quote\"name")]
    public void RejectsCharactersWindowsForbidsInFileNames(string name)
    {
        Assert.False(VaultNameValidator.IsValid(name));
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("con")]
    [InlineData("PRN")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("LPT9")]
    public void RejectsReservedDeviceNames(string name)
    {
        Assert.False(VaultNameValidator.IsValid(name));
    }

    [Theory]
    [InlineData("trailing.")]
    [InlineData("trailing ")]
    public void RejectsTrailingDotOrSpace(string name)
    {
        Assert.False(VaultNameValidator.IsValid(name));
    }

    [Fact]
    public void RejectsNamesLongerThanTheLimit()
    {
        Assert.True(VaultNameValidator.IsValid(new string('a', VaultNameValidator.MaxLength)));
        Assert.False(VaultNameValidator.IsValid(new string('a', VaultNameValidator.MaxLength + 1)));
    }
}
