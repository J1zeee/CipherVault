using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CipherVault.Services;

public sealed class SecureBuffer : IMemoryOwner<byte>, IDisposable
{
    private IntPtr _ptr;
    private int _size;
    private bool _isDisposed;
    private bool _isLocked;
    private bool _isProtected;
    private static readonly object _lockObj = new();
    private byte[]? _managedBuffer;

    private const int MEM_COMMIT = 0x1000;
    private const int MEM_RESERVE = 0x2000;
    private const int PAGE_READWRITE = 0x04;
    private const int MEM_RELEASE = 0x8000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, int dwAllocationType, int dwProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, int dwSize, int dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualLock(IntPtr lpAddress, int dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, int dwSize);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptProtectMemory(IntPtr pDataIn, uint cbDataIn, uint dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectMemory(IntPtr pDataIn, uint cbDataIn, uint dwFlags);

    private const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00;
    private const uint CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x01;

    public SecureBuffer(int sizeInBytes)
    {
        if (sizeInBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(sizeInBytes));

        _size = sizeInBytes;
        _managedBuffer = new byte[sizeInBytes];
        _ptr = VirtualAlloc(IntPtr.Zero, sizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (_ptr == IntPtr.Zero)
            throw new InvalidOperationException("Failed to allocate secure memory");

        GC.AddMemoryPressure(sizeInBytes);
        Lock();
    }

    public Memory<byte> Memory
    {
        get
        {
            ThrowIfDisposed();
            return _managedBuffer.AsMemory(0, _size);
        }
    }

    public Span<byte> Span
    {
        get
        {
            ThrowIfDisposed();
            unsafe
            {
                return new Span<byte>(_ptr.ToPointer(), _size);
            }
        }
    }

    public void Clear()
    {
        ThrowIfDisposed();
        SecureZero();
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (data.Length > _size)
            throw new ArgumentException("Data too large for buffer");

        Unlock();
        data.CopyTo(GetSpan().Slice(0, data.Length));
        Lock();
    }

    public void Write(byte[] data)
    {
        Write(data.AsSpan());
    }

    public byte[] ToArray()
    {
        ThrowIfDisposed();
        var result = new byte[_size];
        GetSpan().CopyTo(result);
        return result;
    }

    public void FillRandom()
    {
        ThrowIfDisposed();
        Unlock();
        RandomNumberGenerator.Fill(GetSpan());
        Lock();
    }

    public Span<byte> GetWritableSpan()
    {
        ThrowIfDisposed();
        Unlock();
        unsafe
        {
            return new Span<byte>(_ptr.ToPointer(), _size);
        }
    }

    public void CommitAndProtect()
    {
        Lock();
        ProtectMemory();
    }

    public void UnprotectAndUnlock()
    {
        UnprotectMemory();
        Unlock();
    }

    public void ProtectMemory()
    {
        if (_isProtected || _ptr == IntPtr.Zero)
            return;

        if (_size % 16 != 0)
            throw new InvalidOperationException("Size must be multiple of 16 for CryptProtectMemory");

        try
        {
            unsafe
            {
                if (CryptProtectMemory(_ptr, (uint)_size, CRYPTPROTECTMEMORY_SAME_PROCESS))
                {
                    Unlock();
                    _isProtected = true;
                }
            }
        }
        catch { }
    }

    public void UnprotectMemory()
    {
        if (!_isProtected || _ptr == IntPtr.Zero)
            return;

        try
        {
            unsafe
            {
                if (CryptUnprotectMemory(_ptr, (uint)_size, CRYPTPROTECTMEMORY_SAME_PROCESS))
                {
                    _isProtected = false;
                    Lock();
                }
            }
        }
        catch { }
    }

    private void Lock()
    {
        if (_isLocked || _ptr == IntPtr.Zero)
            return;

        if (VirtualLock(_ptr, _size))
            _isLocked = true;
    }

    private void Unlock()
    {
        if (!_isLocked || _ptr == IntPtr.Zero)
            return;

        if (VirtualUnlock(_ptr, _size))
            _isLocked = false;
    }

    private void SecureZero()
    {
        if (_ptr == IntPtr.Zero || _size <= 0)
            return;

        unsafe
        {
            var span = new Span<byte>(_ptr.ToPointer(), _size);
            CryptographicOperations.ZeroMemory(span);
        }
    }

    private Span<byte> GetSpan()
    {
        unsafe
        {
            return new Span<byte>(_ptr.ToPointer(), _size);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_isDisposed)
            throw new ObjectDisposedException(nameof(SecureBuffer));
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        lock (_lockObj)
        {
            if (_isDisposed)
                return;

            Unlock();

            if (_ptr != IntPtr.Zero)
            {
                var sizeToRelease = _size;
                SecureZero();
                VirtualFree(_ptr, 0, MEM_RELEASE);
                _ptr = IntPtr.Zero;
                GC.RemoveMemoryPressure(sizeToRelease);
            }

            if (_managedBuffer != null)
            {
                CryptographicOperations.ZeroMemory(_managedBuffer);
                _managedBuffer = null;
            }

            _size = 0;
            _isDisposed = true;
            _isProtected = false;
            GC.SuppressFinalize(this);
        }
    }

    ~SecureBuffer()
    {
        Dispose();
    }
}

public static class SecureMemory
{
    public static SecureBuffer Allocate(int size) => new SecureBuffer(size);

    public static SecureBuffer CreateRandom(int size)
    {
        var buffer = new SecureBuffer(size);
        buffer.FillRandom();
        return buffer;
    }

    public static void ClearAndDispose(SecureBuffer? buffer)
    {
        buffer?.Dispose();
    }

    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}

public static class SecureStringHelper
{
    public static SecureBuffer StringToSecureBytes(string? str)
    {
        if (string.IsNullOrEmpty(str))
            return new SecureBuffer(0);

        var bytes = System.Text.Encoding.UTF8.GetBytes(str);
        var buffer = new SecureBuffer(bytes.Length);
        buffer.Write(bytes);

        CryptographicOperations.ZeroMemory(bytes);
        Array.Clear(bytes, 0, bytes.Length);

        return buffer;
    }

    public static string SecureBytesToString(SecureBuffer buffer)
    {
        var bytes = buffer.ToArray();
        var str = System.Text.Encoding.UTF8.GetString(bytes);

        CryptographicOperations.ZeroMemory(bytes);
        Array.Clear(bytes, 0, bytes.Length);
        buffer.Clear();

return str;
    }
}

public sealed class SecureSession : IDisposable
{
    private SecureBuffer? _masterKey;
    private DateTime _createdAt;
    private readonly TimeSpan _maxLifetime;
    private bool _isDisposed;
    private static readonly object _lockObj = new();

    public SecureSession(int keySizeBytes = 32, TimeSpan? maxLifetime = null)
    {
        _maxLifetime = maxLifetime ?? TimeSpan.FromSeconds(30);
        _createdAt = DateTime.UtcNow;
        _masterKey = SecureMemory.Allocate(keySizeBytes);
    }

    public void RefreshActivity()
    {
        ThrowIfDisposed();
        _createdAt = DateTime.UtcNow;
    }

    public void SetMasterKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        _masterKey!.Write(key);
        _createdAt = DateTime.UtcNow;
    }

    public Span<byte> GetMasterKeySpan()
    {
        ThrowIfDisposed();
        return _masterKey!.GetWritableSpan();
    }

    public void CommitAndProtect()
    {
        ThrowIfDisposed();
        _masterKey!.CommitAndProtect();
    }

    public bool IsExpired => DateTime.UtcNow - _createdAt > _maxLifetime;

    public TimeSpan RemainingTime => _maxLifetime - (DateTime.UtcNow - _createdAt);

    public void Refresh()
    {
        ThrowIfDisposed();
        _createdAt = DateTime.UtcNow;
    }

    public void ClearAndRefresh()
    {
        ThrowIfDisposed();
        _masterKey!.Clear();
        _createdAt = DateTime.UtcNow;
    }

    private void ThrowIfDisposed()
    {
        if (_isDisposed)
            throw new ObjectDisposedException(nameof(SecureSession));
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        lock (_lockObj)
        {
            if (_isDisposed)
                return;

            _masterKey?.Clear();
            _masterKey?.Dispose();
            _masterKey = null;
            _isDisposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~SecureSession()
    {
        Dispose();
    }
}
