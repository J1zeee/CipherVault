using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace CipherVault.Services;

/// <summary>
/// Argon2id derivation of the master key.
///
/// Argon2id holds the password and salt it was handed, and its working state is large
/// by design, so the instance is disposed and every copy this class makes is zeroed
/// before it returns. The caller's own buffers are left alone unless it asks for the
/// password to be wiped.
/// </summary>
public static class MasterKeyDerivation
{
    public const int KeySizeBytes = 32;

    private const int Iterations = 3;
    private const int MemoryKB = 131072;
    private const int Parallelism = 4;

    public static SecureBuffer Derive(byte[] password, byte[] salt, bool wipePassword = false)
    {
        // Argon2id keeps a reference to the arrays it is given; hand it copies so the
        // caller's buffers stay under the caller's control.
        var passwordCopy = (byte[])password.Clone();
        var saltCopy = (byte[])salt.Clone();
        byte[]? derivedBytes = null;
        Argon2id? argon2 = null;

        try
        {
            argon2 = new Argon2id(passwordCopy)
            {
                Salt = saltCopy,
                DegreeOfParallelism = Parallelism,
                MemorySize = MemoryKB,
                Iterations = Iterations
            };

            derivedBytes = argon2.GetBytes(KeySizeBytes);

            var key = new SecureBuffer(KeySizeBytes);
            key.Write(derivedBytes);
            key.EndAccess();
            return key;
        }
        finally
        {
            argon2?.Dispose();

            if (derivedBytes != null) CryptographicOperations.ZeroMemory(derivedBytes);
            CryptographicOperations.ZeroMemory(passwordCopy);
            CryptographicOperations.ZeroMemory(saltCopy);

            if (wipePassword) CryptographicOperations.ZeroMemory(password);
        }
    }
}
