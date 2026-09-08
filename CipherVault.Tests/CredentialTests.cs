using CipherVault.Models;
using Xunit;

namespace CipherVault.Tests;

public class CredentialTests
{
    [Fact]
    public void EmptyField_ReadsBackAsEmptyString()
    {
        using var cred = new Credential { Title = "GitHub", Notes = "" };

        Assert.Equal("", cred.Notes);
    }

    [Fact]
    public void EmptyField_SerializesAsEmptyString()
    {
        using var cred = new Credential { Title = "GitHub", Notes = "", Email = "" };

        var dto = CredentialDto.FromCredential(cred);

        Assert.Equal("", dto.Notes);
        Assert.Equal("", dto.Email);
    }

    [Fact]
    public void EmptyField_SurvivesRoundTripWithoutGainingWhitespace()
    {
        using var original = new Credential { Title = "GitHub", Username = "j1zeee", Notes = "" };

        var dto = CredentialDto.FromCredential(original);
        using var restored = new Credential();
        dto.ToCredential(restored);

        Assert.Equal("GitHub", restored.Title);
        Assert.Equal("j1zeee", restored.Username);
        Assert.Equal("", restored.Notes);
    }

    [Fact]
    public void PopulatedField_IsPreservedExactly()
    {
        using var cred = new Credential { Title = "Mail", Password = "p@ss w0rd!" };

        Assert.Equal("p@ss w0rd!", cred.Password);
    }
}
