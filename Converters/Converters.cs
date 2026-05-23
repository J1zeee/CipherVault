using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace CipherVault.Converters;

public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class CategoryColorConverter : IValueConverter
{
    private static readonly Dictionary<string, (Color Start, Color End)> CategoryColors = new()
    {
        ["General"] = (Color.FromRgb(88, 166, 255), Color.FromRgb(163, 113, 247)),
        ["Social"] = (Color.FromRgb(63, 185, 80), Color.FromRgb(88, 166, 255)),
        ["Work"] = (Color.FromRgb(240, 136, 62), Color.FromRgb(248, 81, 73)),
        ["Finance"] = (Color.FromRgb(63, 185, 80), Color.FromRgb(136, 213, 128)),
        ["Shopping"] = (Color.FromRgb(248, 81, 73), Color.FromRgb(240, 136, 62)),
        ["Entertainment"] = (Color.FromRgb(163, 113, 247), Color.FromRgb(210, 153, 255)),
        ["Other"] = (Color.FromRgb(139, 148, 158), Color.FromRgb(110, 118, 129))
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string category && CategoryColors.TryGetValue(category, out var colors))
        {
            if (parameter?.ToString() == "End")
                return colors.End;
            return colors.Start;
        }
        
        return parameter?.ToString() == "End" 
            ? Color.FromRgb(163, 113, 247) 
            : Color.FromRgb(88, 166, 255);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b && b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is Visibility v && v == Visibility.Visible;
    }
}

public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b && !b;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b && !b;
    }
}
