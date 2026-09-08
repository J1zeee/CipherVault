using System.IO;
using System.Text;

namespace CipherVault.Services;

/// <summary>
/// Crash-safe file writes. The payload lands in a sibling temp file that is flushed
/// to disk before it replaces the target, so an interrupted write can never leave a
/// half-written vault behind - the previous content survives in a .bak sibling.
/// </summary>
public static class AtomicFile
{
    public const string TempSuffix = ".tmp";
    public const string BackupSuffix = ".bak";

    public static void WriteAllBytes(string path, byte[] contents)
    {
        var tempPath = path + TempSuffix;
        var backupPath = path + BackupSuffix;

        using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(contents, 0, contents.Length);
            // Flush through the OS cache: File.Replace is only atomic with respect to
            // data that has actually reached the disk.
            stream.Flush(true);
        }

        if (File.Exists(path))
        {
            File.Replace(tempPath, path, backupPath, ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(tempPath, path);
        }
    }

    public static void WriteAllText(string path, string contents)
    {
        WriteAllBytes(path, Encoding.UTF8.GetBytes(contents));
    }
}
