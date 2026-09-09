using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CipherVault.Services;

/// <summary>
/// Writes the contents of a <see cref="SecureString"/> from a WPF PasswordBox into a
/// caller-supplied buffer as UTF-8, without ever materialising a managed string. A
/// .NET string is immutable and cannot be cleared, so a master password that becomes
/// one stays in the heap until a garbage collection happens to overwrite it - which
/// may be never.
///
/// The decrypted characters are read straight from the unmanaged block that
/// SecureStringToGlobalAllocUnicode hands back, so no managed copy of the plaintext is
/// made along the way; that block is zeroed and freed before this returns. The
/// destination belongs to the caller, who is responsible for zeroing it when done.
///
/// SecureString is itself deprecated and offers no protection off Windows. On Windows
/// it is still backed by CryptProtectMemory, which makes it a meaningful improvement
/// over a plain string here.
/// </summary>
public static class SecureStringConverter
{
    /// <summary>Bytes that <see cref="WriteUtf8Bytes"/> can need at most for this value.</summary>
    public static int GetMaxByteCount(SecureString value)
    {
        if (value == null || value.Length == 0)
            return 0;

        return Encoding.UTF8.GetMaxByteCount(value.Length);
    }

    /// <summary>
    /// Writes <paramref name="value"/> into <paramref name="destination"/> as UTF-8 and
    /// returns the number of bytes written. The destination must be at least
    /// <see cref="GetMaxByteCount"/> bytes, or large enough for the encoded value.
    /// </summary>
    public static unsafe int WriteUtf8Bytes(SecureString value, Span<byte> destination)
    {
        if (value == null || value.Length == 0)
            return 0;

        var unmanaged = IntPtr.Zero;

        try
        {
            unmanaged = Marshal.SecureStringToGlobalAllocUnicode(value);

            // Read directly out of the unmanaged block: copying into a managed char[]
            // first would put the plaintext on the GC heap, where it can be relocated
            // and left behind.
            var chars = new ReadOnlySpan<char>((char*)unmanaged, value.Length);

            return Encoding.UTF8.GetBytes(chars, destination);
        }
        finally
        {
            if (unmanaged != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
            }
        }
    }
}
