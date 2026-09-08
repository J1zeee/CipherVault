using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CipherVault.Services;

/// <summary>
/// Turns a <see cref="SecureString"/> from a WPF PasswordBox into UTF-8 bytes without
/// ever materialising a managed string. A .NET string is immutable and cannot be
/// cleared, so a master password that becomes one stays in the heap until a garbage
/// collection happens to overwrite it - which may be never.
///
/// The intermediate character buffer is pinned so clearing it cannot be defeated by
/// the GC relocating it. The array that is returned is the caller's to zero when done;
/// being a managed array it can still be moved by a collection before that happens,
/// which is the residual limit of doing this without unmanaged buffers throughout.
/// </summary>
public static class SecureStringConverter
{
    public static byte[] ToUtf8Bytes(SecureString value)
    {
        if (value == null || value.Length == 0)
            return Array.Empty<byte>();

        var unmanaged = IntPtr.Zero;
        char[]? chars = null;
        GCHandle pinnedChars = default;

        try
        {
            unmanaged = Marshal.SecureStringToGlobalAllocUnicode(value);

            chars = new char[value.Length];
            pinnedChars = GCHandle.Alloc(chars, GCHandleType.Pinned);
            Marshal.Copy(unmanaged, chars, 0, chars.Length);

            return Encoding.UTF8.GetBytes(chars);
        }
        finally
        {
            if (chars != null) Array.Clear(chars, 0, chars.Length);
            if (pinnedChars.IsAllocated) pinnedChars.Free();
            if (unmanaged != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
        }
    }
}
