using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using CipherVault.Services;
using System.Security.Cryptography;

namespace CipherVault.SecureControls;

public class SecureInputBox : Control
{
    private SecureBuffer? _secureBuffer;
    private bool _isDisposed;
    private static readonly object _lockObj = new();
    private bool _isPasswordVisible;

    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(nameof(Text), typeof(string), typeof(SecureInputBox),
            new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnTextChanged));

    public static readonly DependencyProperty PlaceholderProperty =
        DependencyProperty.Register(nameof(Placeholder), typeof(string), typeof(SecureInputBox),
            new PropertyMetadata("Password"));

    public static readonly DependencyProperty IsPasswordVisibleProperty =
        DependencyProperty.Register(nameof(IsPasswordVisible), typeof(bool), typeof(SecureInputBox),
            new PropertyMetadata(false, OnVisibilityChanged));

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public string Placeholder
    {
        get => (string)GetValue(PlaceholderProperty);
        set => SetValue(PlaceholderProperty, value);
    }

    public bool IsPasswordVisible
    {
        get => (bool)GetValue(IsPasswordVisibleProperty);
        set => SetValue(IsPasswordVisibleProperty, value);
    }

    public event EventHandler? SecureTextChanged;

    static SecureInputBox()
    {
        DefaultStyleKeyProperty.OverrideMetadata(typeof(SecureInputBox),
            new FrameworkPropertyMetadata(typeof(SecureInputBox)));
    }

    public SecureInputBox()
    {
        _secureBuffer = SecureMemory.Allocate(512);
    }

    private static void OnTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SecureInputBox sib && e.NewValue is string newText)
        {
            sib.SetSecureText(newText);
        }
    }

    private static void OnVisibilityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SecureInputBox sib)
        {
            sib._isPasswordVisible = (bool)e.NewValue;
        }
    }

    public void SetSecureText(string plainText)
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed) return;

            _secureBuffer.UnprotectAndUnlock();
            
            var bytes = System.Text.Encoding.UTF8.GetBytes(plainText ?? "");
            if (bytes.Length > 0)
            {
                _secureBuffer.Write(bytes);
                CryptographicOperations.ZeroMemory(bytes);
                Array.Clear(bytes, 0, bytes.Length);
            }
            
            _secureBuffer.CommitAndProtect();
            SecureTextChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public string GetSecureText()
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed) return "";

            try
            {
                _secureBuffer.UnprotectAndUnlock();
                var span = _secureBuffer.Span;
                var result = System.Text.Encoding.UTF8.GetString(span);
                _secureBuffer.CommitAndProtect();
                return result;
            }
            catch
            {
                return "";
            }
        }
    }

    public byte[] GetSecureBytes()
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed) return Array.Empty<byte>();
            
            try
            {
                _secureBuffer.UnprotectAndUnlock();
                var result = _secureBuffer.ToArray();
                _secureBuffer.CommitAndProtect();
                return result;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }
    }

    public Span<byte> GetSecureSpan()
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed)
                return Span<byte>.Empty;

            _secureBuffer.UnprotectAndUnlock();
            return _secureBuffer.Span;
        }
    }

    public void CommitAndProtect()
    {
        lock (_lockObj)
        {
            _secureBuffer?.CommitAndProtect();
        }
    }

    public void Clear()
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed) return;

            _secureBuffer.UnprotectAndUnlock();
            _secureBuffer.Clear();
            _secureBuffer.CommitAndProtect();
            
            Dispatcher.BeginInvoke(() => Text = "");
        }
    }

    public void SetSecureBytes(byte[] data, int length)
    {
        lock (_lockObj)
        {
            if (_secureBuffer == null || _isDisposed) return;

            _secureBuffer.UnprotectAndUnlock();
            _secureBuffer.Clear();
            
            if (data != null && length > 0 && length <= 512)
            {
                var span = _secureBuffer.Span.Slice(0, length);
                data.AsSpan(0, length).CopyTo(span);
            }
            
            _secureBuffer.CommitAndProtect();
            
            Dispatcher.BeginInvoke(() => 
            {
                Text = GetSecureText();
            });
        }
    }

    public void Dispose()
    {
        lock (_lockObj)
        {
            if (_isDisposed) return;

            _secureBuffer?.Clear();
            _secureBuffer?.Dispose();
            _secureBuffer = null;
            _isDisposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~SecureInputBox()
    {
        Dispose();
    }
}

public class SecurePasswordInput : SecureInputBox
{
    public static readonly DependencyProperty PasswordProperty =
        DependencyProperty.Register(nameof(Password), typeof(string), typeof(SecurePasswordInput),
            new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnPasswordChanged));

    public static readonly DependencyProperty ShowPasswordButtonProperty =
        DependencyProperty.Register(nameof(ShowPasswordButton), typeof(bool), typeof(SecurePasswordInput),
            new PropertyMetadata(true));

    public string Password
    {
        get => (string)GetValue(PasswordProperty);
        set => SetValue(PasswordProperty, value);
    }

    public bool ShowPasswordButton
    {
        get => (bool)GetValue(ShowPasswordButtonProperty);
        set => SetValue(ShowPasswordButtonProperty, value);
    }

    private static void OnPasswordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SecurePasswordInput spi && e.NewValue is string newPass)
        {
            spi.SetSecureText(newPass);
        }
    }

    public new string GetSecureText()
    {
        return base.GetSecureText();
    }
}