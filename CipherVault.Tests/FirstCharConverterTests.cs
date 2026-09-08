using System.Globalization;
using CipherVault.Converters;
using Xunit;

namespace CipherVault.Tests;

public class FirstCharConverterTests
{
    private static object? Convert(object? value) =>
        new FirstCharConverter().Convert(value!, typeof(string), null!, CultureInfo.InvariantCulture);

    [Fact]
    public void ReturnsFirstCharacterOfNonEmptyString()
    {
        Assert.Equal("G", Convert("GitHub"));
    }

    [Fact]
    public void ReturnsEmptyStringForEmptyInput()
    {
        Assert.Equal("", Convert(""));
    }

    [Fact]
    public void ReturnsEmptyStringForNullInput()
    {
        Assert.Equal("", Convert(null));
    }

    [Fact]
    public void DoesNotThrowOnNonStringInput()
    {
        Assert.Equal("", Convert(42));
    }
}
