using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CipherVault.Services;

public class PasswordGenerator
{
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string DigitChars = "0123456789";
    private const string SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    private const string AmbiguousLower = "l";
    private const string AmbiguousUpper = "IO";
    private const string AmbiguousDigits = "0O";
    
    private static readonly string[] CommonPatterns = 
    {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "login",
        "abc123", "111111", "baseball", "iloveyou", "sunshine"
    };

    private static readonly Dictionary<string, int> DictionaryWords = new()
    {
        // Top 100 common passwords
        { "password", 1 }, { "123456", 1 }, { "12345678", 1 }, { "123456789", 1 }, { "12345", 1 },
        { "1234567", 1 }, { "qwerty", 1 }, { "abc123", 1 }, { "million", 1 }, { "princess", 1 },
        { "solo", 1 }, { "starwars", 1 }, { "1234", 1 }, { "123", 1 }, { "admin", 1 },
        { "welcome", 1 }, { "flower", 1 }, { "hottie", 1 }, { "freedom", 1 }, { "xxx", 1 },
        { "love", 1 }, { "ashley", 1 }, { "bailey", 1 }, { "passw0rd", 1 }, { "shadow", 1 },
        { "123123", 1 }, { "654321", 1 }, { "superman", 1 }, { "q1w2e3r4", 1 }, { "michael", 1 },
        { "football", 1 }, { "password1", 1 }, { "password123", 1 }, { "sa", 1 }, { "za", 1 },
        { "hello", 1 }, { "charlie", 1 }, { "donald", 1 }, { "letmein", 1 }, { "admin1", 1 },
        { "root", 1 }, { "toor", 1 }, { "pass", 1 }, { "test", 1 }, { "guest", 1 },
        { "master", 1 }, { "daniel", 1 }, { "jessica", 1 }, { "liverpool", 1 }, { "manutd", 1 }
    };

    private static readonly string[] KeyboardPatterns = 
    {
        "qwerty", "qwertyuiop", "asdfgh", "zxcvbn", "1234567890",
        "qazwsx", "qweasd", "1qaz2wsx", "qaz", "wsx"
    };

    public string Generate(
        int length = 16,
        bool includeLowercase = true,
        bool includeUppercase = true,
        bool includeDigits = true,
        bool includeSpecial = true,
        bool excludeAmbiguous = false)
    {
        if (length < 1) length = 1;
        if (length > 128) length = 128;

        var charPool = new StringBuilder();
        
        if (includeLowercase)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(LowercaseChars, AmbiguousLower) 
                : LowercaseChars;
            charPool.Append(chars);
        }
        
        if (includeUppercase)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(UppercaseChars, AmbiguousUpper) 
                : UppercaseChars;
            charPool.Append(chars);
        }
        
        if (includeDigits)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(DigitChars, AmbiguousDigits) 
                : DigitChars;
            charPool.Append(chars);
        }
        
        if (includeSpecial)
        {
            charPool.Append(SpecialChars);
        }

        if (charPool.Length == 0)
        {
            charPool.Append(LowercaseChars);
            includeLowercase = true;
        }

        var pool = charPool.ToString();
        var result = new char[length];
        var poolSpan = pool.AsSpan();

        for (int i = 0; i < length; i++)
        {
            result[i] = poolSpan[RandomNumberGenerator.GetInt32(poolSpan.Length)];
        }

        var guaranteedPositions = new List<(int pos, char c)>();
        
        if (includeLowercase)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(LowercaseChars, AmbiguousLower) 
                : LowercaseChars;
            guaranteedPositions.Add((RandomNumberGenerator.GetInt32(length), chars[RandomNumberGenerator.GetInt32(chars.Length)]));
        }
        
        if (includeUppercase)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(UppercaseChars, AmbiguousUpper) 
                : UppercaseChars;
            guaranteedPositions.Add((RandomNumberGenerator.GetInt32(length), chars[RandomNumberGenerator.GetInt32(chars.Length)]));
        }
        
        if (includeDigits)
        {
            var chars = excludeAmbiguous 
                ? RemoveChars(DigitChars, AmbiguousDigits) 
                : DigitChars;
            guaranteedPositions.Add((RandomNumberGenerator.GetInt32(length), chars[RandomNumberGenerator.GetInt32(chars.Length)]));
        }
        
        if (includeSpecial)
        {
            guaranteedPositions.Add((RandomNumberGenerator.GetInt32(length), SpecialChars[RandomNumberGenerator.GetInt32(SpecialChars.Length)]));
        }

        foreach (var (pos, c) in guaranteedPositions)
        {
            result[pos] = c;
        }

        return new string(result);
    }

    private static string RemoveChars(string source, string charsToRemove)
    {
        var sb = new StringBuilder(source.Length);
        foreach (var c in source)
        {
            if (!charsToRemove.Contains(c))
                sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Анализ силы пароля на основе энтропии
    /// </summary>
    public PasswordStrengthResult AnalyzeStrength(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return new PasswordStrengthResult
            {
                Score = 0,
                Entropy = 0,
                EntropyBits = 0,
                CrackTimeSeconds = 0,
                CrackTimeDisplay = "Instant",
                Label = "Very Weak",
                Suggestions = new List<string> { "Enter a password" }
            };
        }

        var suggestions = new List<string>();
        
        // Расчёт базовой энтропии (для отображения, не для score)
        //var entropyResult = CalculateEntropy(password);
        //double rawEntropy = entropyResult.Entropy;
        int poolSize = 26; // Assume lowercase only by default
        
        // Проверка на словарные слова
        var dictionaryPenalty = CheckDictionaryWords(password);
        
        // Штрафы за паттерны (в битах)
        double patternPenalty = 0;
        if (HasKeyboardPattern(password)) patternPenalty += 25;
        if (HasSequentialChars(password)) patternPenalty += 10;
        if (HasRepeatedChars(password)) patternPenalty += 10;
        
        // Расчёт score БЕЗ энтропии
        int score = 0;
        
        // Баллы за длину
        if (password.Length >= 8) score += 15;
        if (password.Length >= 12) score += 15;
        if (password.Length >= 16) score += 10;
        if (password.Length >= 20) score += 10;
        
        // Баллы за типы символов
        bool hasLower = password.Any(char.IsLower);
        bool hasUpper = password.Any(char.IsUpper);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));
        
        if (hasLower) score += 15;
        if (hasUpper) score += 15;
        if (hasDigit) score += 15;
        if (hasSpecial) score += 15;
        
        // Штрафы
        if (dictionaryPenalty > 0)
        {
            score = Math.Min(score, 20);
            suggestions.Add("Avoid common words and passwords");
        }
        
        if (patternPenalty > 0)
        {
            score -= 15;
            suggestions.Add("Avoid keyboard patterns");
        }
        
        // Один тип символов - штраф
        int typeCount = 0;
        if (hasLower) typeCount++;
        if (hasUpper) typeCount++;
        if (hasDigit) typeCount++;
        if (hasSpecial) typeCount++;
        
        if (typeCount == 1 && password.Length > 0)
        {
            score = Math.Max(0, score - 25);
            suggestions.Add("Use different character types");
        }
        
        score = Math.Max(0, Math.Min(100, score));
        
        // Штраф за короткий пароль
        if (password.Length < 8)
        {
            score = Math.Min(score, 30);
            suggestions.Add("Minimum 8 characters required");
        }
        else if (password.Length < 12)
        {
            suggestions.Add("Consider using 12+ characters for better security");
        }
        
        // Для crack time - используем простую оценку
        double crackTimeSeconds = Math.Pow(50, password.Length) / 1e10 / 2;
        
        if (double.IsInfinity(crackTimeSeconds) || crackTimeSeconds > 1e15)
            crackTimeSeconds = 1e15;
        
        if (!hasLower) suggestions.Add("Add lowercase letters");
        if (!hasUpper) suggestions.Add("Add uppercase letters");
        if (!hasDigit) suggestions.Add("Add numbers");
        if (!hasSpecial) suggestions.Add("Add special characters (!@#$)");
        
        if (dictionaryPenalty > 0)
        {
            suggestions.Add("Avoid common words and passwords");
        }
        if (patternPenalty > 0)
        {
            suggestions.Add("Avoid keyboard patterns");
        }
        
        string label = score switch
        {
            >= 80 => "Very Strong",
            >= 60 => "Strong",
            >= 40 => "Good",
            >= 20 => "Fair",
            _ => "Weak"
        };
        
        return new PasswordStrengthResult
        {
            Score = score,
            Entropy = 0,
            EntropyBits = 0,
            CrackTimeSeconds = crackTimeSeconds,
            CrackTimeDisplay = FormatCrackTime(crackTimeSeconds),
            PoolSize = poolSize,
            Label = label,
            Suggestions = suggestions,
            HasLowercase = hasLower,
            HasUppercase = hasUpper,
            HasDigits = hasDigit,
            HasSpecial = hasSpecial,
            DictionaryPenalty = dictionaryPenalty
        };
    }

    private (double Entropy, int PoolSize) CalculateEntropy(string password)
    {
        if (string.IsNullOrEmpty(password)) return (0, 0);

        // Определяем размер пула на основе используемых символов
        int poolSize = 0;
        
        if (password.Any(char.IsLower)) poolSize += 26;
        if (password.Any(char.IsUpper)) poolSize += 26;
        if (password.Any(char.IsDigit)) poolSize += 10;
        if (password.Any(c => SpecialChars.Contains(c))) poolSize += SpecialChars.Length;
        
        if (poolSize == 0) poolSize = 26;
        
        // Энтропия = log2(poolSize^length) = length * log2(poolSize)
        double entropy = password.Length * Math.Log2(poolSize);
        
        return (Math.Round(entropy, 2), poolSize);
    }

    private double CheckDictionaryWords(string password)
    {
        var lower = password.ToLower();
        
        // Точное совпадение
        if (DictionaryWords.ContainsKey(lower))
            return 25;
        
        // Частичное совпадение - пароль содержит слово
        foreach (var word in DictionaryWords.Keys)
        {
            if (lower.Contains(word) && word.Length >= 4)
                return 15;
        }
        
        return 0;
    }

    private bool HasKeyboardPattern(string password)
    {
        if (password.Length < 3) return false;
        
        var lower = password.ToLower();
        
        // Check whole patterns
        foreach (var pattern in KeyboardPatterns)
        {
            if (lower.Contains(pattern))
                return true;
            
            var reversed = new string(pattern.Reverse().ToArray());
            if (lower.Contains(reversed))
                return true;
        }
        
        // Check adjacent keys on keyboard (e.g., "rek" = r-e-k are close on keyboard)
        if (HasAdjacentKeys(lower))
            return true;
        
        return false;
    }
    
    private bool HasAdjacentKeys(string password)
    {
        // QWERTY keyboard layout - keys close to each other
        // Format: key -> list of adjacent keys on keyboard
        var adjacentKeys = new Dictionary<char, char[]>
        {
            {'q', new[] {'w', 'a', 's'}},
            {'w', new[] {'q', 'e', 'a', 's', 'd'}},
            {'e', new[] {'w', 'r', 's', 'd', 'f'}},
            {'r', new[] {'e', 't', 'd', 'f', 'g'}},
            {'t', new[] {'r', 'y', 'f', 'g', 'h'}},
            {'y', new[] {'t', 'u', 'g', 'h', 'j'}},
            {'u', new[] {'y', 'i', 'h', 'j', 'k'}},
            {'i', new[] {'u', 'o', 'j', 'k', 'l'}},
            {'o', new[] {'i', 'p', 'k', 'l'}},
            {'a', new[] {'q', 'w', 's', 'z'}},
            {'s', new[] {'q', 'w', 'e', 'a', 'd', 'z', 'x'}},
            {'d', new[] {'w', 'e', 'r', 's', 'f', 'x', 'c'}},
            {'f', new[] {'e', 'r', 't', 'd', 'g', 'c', 'v'}},
            {'g', new[] {'r', 't', 'y', 'f', 'h', 'v', 'b'}},
            {'h', new[] {'t', 'y', 'u', 'g', 'j', 'b', 'n'}},
            {'j', new[] {'y', 'u', 'i', 'h', 'k', 'n', 'm'}},
            {'k', new[] {'u', 'i', 'o', 'j', 'l', 'm'}},
            {'l', new[] {'i', 'o', 'p', 'k'}},
            {'z', new[] {'a', 's', 'x'}},
            {'x', new[] {'s', 'd', 'z', 'c'}},
            {'c', new[] {'d', 'f', 'x', 'v'}},
            {'v', new[] {'f', 'g', 'c', 'b'}},
            {'b', new[] {'g', 'h', 'v', 'n'}},
            {'n', new[] {'h', 'j', 'b', 'm'}},
            {'m', new[] {'j', 'k', 'n'}},
        };
        
        int adjacentCount = 0;
        
        for (int i = 0; i < password.Length - 1; i++)
        {
            char c1 = password[i];
            char c2 = password[i + 1];
            
            if (adjacentKeys.TryGetValue(c1, out var adjacent) && adjacent.Contains(c2))
            {
                adjacentCount++;
                if (adjacentCount >= 2) // Found 2+ adjacent pairs
                    return true;
            }
        }
        
        return false;
    }
       
    private bool HasSequentialChars(string password)
    {
        if (password.Length < 3) return false;

        int sequentialCount = 0;
        
        for (int i = 0; i < password.Length - 2; i++)
        {
            // Проверка последовательных символов (abc, 123)
            if (password[i + 1] == password[i] + 1 && password[i + 2] == password[i] + 2)
                sequentialCount++;
            // Проверка обратной последовательности (cba, 321)
            if (password[i + 1] == password[i] - 1 && password[i + 2] == password[i] - 2)
                sequentialCount++;
        }
        
        return sequentialCount > 0;
    }

    private bool HasRepeatedChars(string password)
    {
        if (password.Length < 3) return false;

        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] && password[i + 1] == password[i + 2])
                return true;
        }
        
        return false;
    }

    private string FormatCrackTime(double seconds)
    {
        if (seconds < 1) return "Instant";
        if (seconds < 60) return $"{seconds:F0} seconds";
        if (seconds < 3600) return $"{seconds / 60:F0} minutes";
        if (seconds < 86400) return $"{seconds / 3600:F0} hours";
        if (seconds < 31536000) return $"{seconds / 86400:F0} days";
        if (seconds < (double)31536000 * 100) return $"{seconds / 31536000:F1} years";
        if (seconds < (double)31536000 * 1000000) return $"{seconds / 31536000 / 1000:F0}K years";
        
        return $"{seconds / 31536000 / 1000000:F0}M+ years";
    }

    [Obsolete("Use AnalyzeStrength instead")]
    public int CalculateStrength(string password)
    {
        return AnalyzeStrength(password).Score;
    }

    [Obsolete("Use AnalyzeStrength instead")]
    public string GetStrengthLabel(int score)
    {
        return score switch
        {
            >= 80 => "Very Strong",
            >= 60 => "Strong",
            >= 40 => "Good",
            >= 20 => "Fair",
            _ => "Weak"
        };
    }
}

public class PasswordStrengthResult
{
    public int Score { get; set; }
    public double Entropy { get; set; }
    public int EntropyBits { get; set; }
    public double CrackTimeSeconds { get; set; }
    public string CrackTimeDisplay { get; set; } = "";
    public int PoolSize { get; set; }
    public string Label { get; set; } = "";
    public List<string> Suggestions { get; set; } = new();
    public bool HasLowercase { get; set; }
    public bool HasUppercase { get; set; }
    public bool HasDigits { get; set; }
    public bool HasSpecial { get; set; }
    public double DictionaryPenalty { get; set; }
}
