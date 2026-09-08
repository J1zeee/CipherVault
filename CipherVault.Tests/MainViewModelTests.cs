using System.IO;
using System.Text;
using CipherVault.Models;
using CipherVault.Services;
using CipherVault.ViewModels;
using Xunit;

namespace CipherVault.Tests;

public class MainViewModelTests : IDisposable
{
    private readonly string _dir;
    private readonly StorageService _storage;
    private readonly MainViewModel _viewModel;

    public MainViewModelTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "CipherVaultTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);

        _storage = new StorageService(_dir);
        _storage.CreateVault(Encoding.UTF8.GetBytes("correct horse battery staple"));
        _viewModel = new MainViewModel(_storage);
    }

    public void Dispose()
    {
        _storage.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    private Credential Add(string title, string password)
    {
        var credential = new Credential { Title = title, Password = password };
        _viewModel.StartAddCredential();
        Assert.True(_viewModel.SaveCredential(credential));
        return credential;
    }

    [Fact]
    public void EditingReleasesTheEntryItReplaces()
    {
        var original = Add("github", "old-secret");

        _viewModel.SelectedCredential = original;
        _viewModel.StartEditCredential();
        _viewModel.SaveCredential(new Credential { Title = "github", Password = "new-secret" });

        Assert.Equal("", original.Password);
    }

    [Fact]
    public void EditingKeepsTheNewValueInTheCollection()
    {
        var original = Add("github", "old-secret");

        _viewModel.SelectedCredential = original;
        _viewModel.StartEditCredential();
        _viewModel.SaveCredential(new Credential { Title = "github", Password = "new-secret" });

        Assert.Single(_viewModel.Credentials);
        Assert.Equal("new-secret", _viewModel.Credentials[0].Password);
    }

    [Fact]
    public void EditingFailsInsteadOfSilentlyDiscardingTheChange()
    {
        Add("github", "old-secret");

        // A selection that is not in the collection: the edit has nowhere to land.
        using var stale = new Credential { Title = "github", Password = "stale" };
        _viewModel.SelectedCredential = stale;
        _viewModel.StartEditCredential();

        var saved = _viewModel.SaveCredential(new Credential { Title = "github", Password = "new-secret" });

        Assert.False(saved, "the edit was reported as saved but went nowhere");
    }

    [Fact]
    public void EditingPreservesTheOriginalCreationTime()
    {
        var original = Add("github", "old-secret");
        var createdAt = original.CreatedAt;

        _viewModel.SelectedCredential = original;
        _viewModel.StartEditCredential();
        _viewModel.SaveCredential(new Credential { Title = "github", Password = "new-secret" });

        Assert.Equal(createdAt, _viewModel.Credentials[0].CreatedAt);
    }

    [Fact]
    public void DuplicateTitlesAreStillRejectedWhenAdding()
    {
        Add("github", "secret");

        _viewModel.StartAddCredential();
        var saved = _viewModel.SaveCredential(new Credential { Title = "GitHub", Password = "other" });

        Assert.False(saved);
    }
}
