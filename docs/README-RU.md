# CipherVault

**Безопасный офлайн-менеджер паролей для Windows с современной криптографией.**

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/download)
[![C#](https://img.shields.io/badge/C%23-14-239120?logo=csharp)](https://learn.microsoft.com/dotnet/csharp)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?logo=windows)](https://www.microsoft.com/windows)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue)](https://github.com/J1zeee/CipherVault/releases/latest)
[![Readme](https://img.shields.io/badge/Readme-English-1976D2)](../README.md)

<br>

<img src="../Screenshots/MainApp.png" alt="Main Application" width="700">

*Главный экран: список записей и панель деталей.*

<br>

## Возможности

- **AES-256-GCM** — аутентифицированное шифрование всех данных хранилища
- **Argon2id** — деривация ключа (128 MB памяти, 3 итерации, 4 потока)
- **HKDF-SHA256** — разделение ключей: отдельный ключ для верификации и шифрования
- **Защищённые буферы в памяти** — `VirtualAlloc` + `VirtualLock` + `CryptProtectMemory`, обнуление при освобождении
- **Защита от захвата экрана** через `SetWindowDisplayAffinity`
- **Автоблокировка** через 1 минуту бездействия
- **Защита от перебора** — экспоненциальная задержка (до ~34 мин)
- **Автоочистка буфера обмена** через 10 секунд после копирования
- **Криптографический генератор паролей** с анализом стойкости
- **Журнал аудита** (опционально, отключён по умолчанию)
- **Несколько хранилищ**
- **Мультиязычный интерфейс** (английский / русский)
- **Тёмная тема** с кастомными WPF-контролами
- **Импорт / Экспорт** в ZIP
- **Self-contained single-file** публикация — не требует .NET Runtime

<br>

## Модель безопасности

| Защита от | Описание |
|---|---|
| **Брутфорс мастер-пароля** | Argon2id (128 MB, 3 iter) + экспоненциальная задержка после 5 попыток |
| **Извлечение данных из памяти** | VirtualLock запрещает сброс на диск; CryptProtectMemory шифрует данные в RAM; буферы обнуляются |
| **Подмена шифротекста** | AES-GCM аутентификационная метка отклоняет изменённые данные |
| **Захват экрана** | `WDA_EXCLUDEFROMCAPTURE` на главном окне |
| **Timing-атаки** | `CryptographicOperations.FixedTimeEquals` для сверки пароля |

| Не покрыто | Причина |
|---|---|
| **Кейлоггер / формы** | ОС предполагается доверенной; нет защиты от малвари на стороне пользователя |
| **Скомпрометированная ОС** | Если злоумышленник контролирует систему — любая защита в процессе обходится |
| **Cold boot атаки** | Выходят за рамки десктопного приложения |

### Параметры Argon2id

| Параметр | Значение |
|---|---|
| Алгоритм | Argon2id |
| Память | 128 MB |
| Итерации | 3 |
| Параллелизм | 4 потока |
| Соль | 32 байта (случайная, на каждое хранилище) |
| Выход | 32 байта (мастер-ключ) |

<br>

## Технологии

```
.NET 8.0  •  WPF  •  C# 14
```

| Библиотека / API | Назначение |
|---|---|
| `System.Security.Cryptography` | AES-256-GCM, HKDF, RNG, constant-time операции |
| `Konscious.Security.Cryptography.Argon2` | Argon2id KDF |
| `kernel32.dll` (P/Invoke) | VirtualAlloc, VirtualLock |
| `crypt32.dll` (P/Invoke) | CryptProtectMemory |
| `System.Text.Json` | Сериализация конфига и хранилища |
| `System.IO.Compression` | Импорт / экспорт хранилищ |

<br>

## Начало работы

### Требования

- Windows 10+ (x64)
- .NET 8 Runtime *(не требуется для self-contained сборки)*

### Сборка из исходников

```powershell
git clone https://github.com/Anomalyous/CipherVaultV2.git
cd CipherVaultV2
dotnet publish -c Release -r win-x64 --self-contained true
.\bin\Release\net8.0-windows10.0.26100.0\win-x64\publish\CipherVault.exe
```

### Скачать релиз

Скачайте `CipherVault-v1.0.0.zip` из [Releases](https://github.com/J1zeee/CipherVault/releases/latest), распакуйте и запустите `CipherVault.exe`.

<br>

## Использование

**1. Создайте хранилище** — задайте мастер-пароль (Argon2id выведет ключ шифрования).

<img src="../Screenshots/LoginScreen.png" alt="Login screen" width="500">

**2. Добавьте запись** — название, имя пользователя, email, пароль, сайт, заметки. Встроенный генератор создаёт криптостойкие пароли.

<img src="../Screenshots/AddCredential.png" alt="Add credential" width="500">

**3. Блокировка и разблокировка** — хранилище блокируется через 1 мин бездействия. Мастер-ключ хранится в защищённой памяти (SecureBuffer) и очищается при блокировке.

<img src="../Screenshots/SettingsPanel.png" alt="Settings" width="500">

<br>

## Архитектура

```
Мастер-пароль  +  Случайная соль
          │
          ▼
      Argon2id  (128 MB / 3 iter / 4 потока)
          │
          ▼
     Мастер-ключ  (32 байта)
          │
          ├── HKDF — info="verify"   ──▶  Ключ верификации  (хранится в config.json)
          │
          └── HKDF — info="encrypt"  ──▶  Ключ шифрования   (в SecureBuffer, никогда не сохраняется)
                                               │
                                               ▼
                                        AES-256-GCM Encrypt / Decrypt
                                               │
                                               ▼
                                       vault.dat  (nonce + ciphertext + tag)
```

- **`vault.dat`** — зашифрованный payload записей. Каждое шифрование использует свежий 12-байтовый random nonce.
- **`config.json`** — хеш верификации, соль Argon2id и метаданные хранилища. Ключ шифрования там **никогда** не хранится.
- Ключ шифрования существует только в памяти процесса внутри `SecureBuffer` (VirtualAlloc + CryptProtectMemory).

<br>

## Планы

- [ ] Интеграция Have I Been Pwned (k-anonymity API)
- [ ] Браузерное автозаполнение
- [ ] TOTP-аутентификатор
- [ ] Android / macOS / Linux (Avalonia / MAUI)

<br>

## Вклад в проект

PR приветствуются. Для крупных изменений сначала откройте issue для обсуждения.

<br>

## Лицензия

[Apache 2.0](../LICENSE)
