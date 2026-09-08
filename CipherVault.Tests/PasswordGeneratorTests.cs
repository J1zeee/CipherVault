using CipherVault.Services;
using Xunit;

namespace CipherVault.Tests;

public class PasswordGeneratorTests
{
    private readonly PasswordGenerator _generator = new();

    // --- 15: every enabled character class must actually survive into the password ---

    [Fact]
    public void GuaranteedClassesAllSurvive_WhenLengthExactlyMatchesClassCount()
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            var password = _generator.Generate(length: 4);

            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }
    }

    [Fact]
    public void GuaranteedClassesAllSurvive_AtTypicalLength()
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var password = _generator.Generate(length: 16);

            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }
    }

    [Fact]
    public void ShorterThanTheClassCount_StillProducesTheRequestedLength()
    {
        var password = _generator.Generate(length: 2);

        Assert.Equal(2, password.Length);
    }

    [Fact]
    public void DisabledClassesNeverAppear()
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var password = _generator.Generate(length: 12, includeUppercase: false, includeSpecial: false);

            Assert.DoesNotContain(password, char.IsUpper);
            Assert.All(password, c => Assert.True(char.IsLetterOrDigit(c)));
        }
    }

    // --- 16: entropy is reported, not hardcoded to zero ---

    [Fact]
    public void EntropyIsReportedForANonEmptyPassword()
    {
        var result = _generator.AnalyzeStrength("correcthorse");

        Assert.True(result.EntropyBits > 0, "entropy is still reported as zero");
    }

    [Fact]
    public void PoolSizeReflectsTheCharacterClassesActuallyUsed()
    {
        Assert.Equal(26, _generator.AnalyzeStrength("abcdefgh").PoolSize);
        Assert.Equal(36, _generator.AnalyzeStrength("abc12345").PoolSize);
        Assert.True(_generator.AnalyzeStrength("Abc123!@").PoolSize > 80);
    }

    [Fact]
    public void LongerPasswordOverTheSameAlphabetHasMoreEntropy()
    {
        var shorter = _generator.AnalyzeStrength("abcdefgh").EntropyBits;
        var longer = _generator.AnalyzeStrength("abcdefghijklmnop").EntropyBits;

        Assert.True(longer > shorter);
    }

    // --- 17: crack time must depend on the alphabet, not only on length ---

    [Fact]
    public void CrackTimeDistinguishesAlphabets_NotJustLength()
    {
        var lowercaseOnly = _generator.AnalyzeStrength("abcdefgh").CrackTimeSeconds;
        var fullCharset = _generator.AnalyzeStrength("aB3!dE7@").CrackTimeSeconds;

        Assert.True(fullCharset > lowercaseOnly,
            "an 8-char password over 88 symbols is rated the same as 8 lowercase letters");
    }

    [Fact]
    public void EmptyPasswordCracksInstantly()
    {
        var result = _generator.AnalyzeStrength("");

        Assert.Equal(0, result.CrackTimeSeconds);
        Assert.Equal(0, result.EntropyBits);
    }

    // --- 18: no duplicated advice ---

    [Fact]
    public void SuggestionsAreNotRepeated()
    {
        var result = _generator.AnalyzeStrength("password");

        Assert.Equal(result.Suggestions.Distinct().Count(), result.Suggestions.Count);
    }

    // --- 19: scattered adjacent pairs are not a keyboard walk ---

    [Fact]
    public void TwoScatteredAdjacentPairsAreNotTreatedAsAKeyboardWalk()
    {
        var result = _generator.AnalyzeStrength("we8kj3");

        Assert.DoesNotContain("Avoid keyboard patterns", result.Suggestions);
    }

    [Fact]
    public void ARealKeyboardWalkIsStillFlagged()
    {
        var result = _generator.AnalyzeStrength("sdfg9012");

        Assert.Contains("Avoid keyboard patterns", result.Suggestions);
    }

    [Fact]
    public void GeneratedPasswordsAreNotPenalisedAsKeyboardWalks()
    {
        var flagged = 0;
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (_generator.AnalyzeStrength(_generator.Generate(length: 16))
                .Suggestions.Contains("Avoid keyboard patterns"))
            {
                flagged++;
            }
        }

        // A genuine 4-key walk still turns up in random text now and then; this guards
        // against the old behaviour, where roughly a third of them were flagged.
        Assert.True(flagged < 8, $"{flagged}/100 generated passwords were called keyboard walks");
    }
}
