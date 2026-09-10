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
- **Argon2id** — деривация ключа (128 MiB памяти, 3 итерации, 4 потока)
- **Единый производный ключ** — вывод Argon2id *и есть* ключ AES, без HKDF
- **Разблокировка расшифровкой** — неверный пароль просто не расшифровывает хранилище
- **Самодостаточный `vault.dat`** — соль Argon2id лежит в заголовке файла; `config.json` не нужен
- **Защищённые буферы в памяти** — `VirtualAlloc` + `VirtualLock` + `CryptProtectMemory`, обнуление при освобождении
- **Защита от захвата экрана** через `SetWindowDisplayAffinity` (`WDA_EXCLUDEFROMCAPTURE`, фолбэк `WDA_MONITOR`)
- **Защита буфера обмена** — автоочистка через 10 с; исключение из истории Win+V и облачного буфера
- **Автоблокировка** через 1 минуту бездействия
- **Защита от перебора** — экспоненциальная задержка на каждое хранилище (до ~34 мин), сохраняется через DPAPI
- **Криптографический генератор паролей** с анализом энтропии и времени взлома
- **Журнал аудита** (опционально, отключён по умолчанию)
- **Несколько хранилищ** с импортом/экспортом в ZIP и безопасным удалением
- **Мультиязычный интерфейс** (английский / русский)
- **Тёмная тема** с кастомными WPF-контролами и плавными анимациями
- **Self-contained single-file** публикация — не требует .NET Runtime

<br>

## Модель безопасности

| Защита от | Описание |
|---|---|
| **Брутфорс мастер-пароля** | Argon2id (128 MiB, 3 iter) + экспоненциальная задержка после 5 попыток, сохраняется на каждое хранилище |
| **Извлечение данных из памяти** | VirtualLock не даёт сбрасывать страницы на диск; CryptProtectMemory шифрует буферы; всё обнуляется при освобождении |
| **Неверный пароль / подмена шифротекста** | AES-GCM аутентификационная метка отклоняет изменённые данные; неверный ключ не расшифровывает хранилище |
| **Захват экрана** | `WDA_EXCLUDEFROMCAPTURE` на всех окнах приложения (фолбэк `WDA_MONITOR` на старых сборках) |
| **История и облако буфера обмена** | Секреты исключаются из истории Win+V и облачного буфера перед копированием |
| **Хардинг процесса (Release-сборки)** | Single-instance мьютекс (Global), антиотладка, принудительная релокация ASLR, блокировка загрузки удалённых / низкоуровневых образов и строгий запрет на создание дочерних процессов. Ни один внешний процесс не может быть запущен: открытие ссылок отключено (кнопка открытия папки логов по-прежнему работает, переиспользуя уже запущенное окно Explorer). Debug-сборки все проверки пропускают |

| Не покрыто | Причина |
|---|---|
| **Кейлоггер / формы** | ОС предполагается доверенной; нет защиты от малвари на стороне пользователя |
| **Скомпрометированная ОС** | Если злоумышленник контролирует систему — любая защита в процессе обходится |
| **Cold boot атаки** | Выходят за рамки десктопного приложения |

### Параметры Argon2id

| Параметр | Значение |
|---|---|
| Алгоритм | Argon2id |
| Память | 128 MiB |
| Итерации | 3 |
| Параллелизм | 4 потока |
| Соль | 32 байта (случайная, на каждое хранилище, хранится в заголовке файла) |
| Выход | 32 байта (ключ AES-256) |

<br>

## Технологии

```
.NET 8.0  •  WPF  •  C# 14
```

| Библиотека / API | Назначение |
|---|---|
| `System.Security.Cryptography` | AES-256-GCM, RNG, constant-time операции |
| `Konscious.Security.Cryptography.Argon2` | Argon2id KDF |
| `System.Security.Cryptography.ProtectedData` | DPAPI для состояния блокировки каждого хранилища |
| `kernel32.dll` (P/Invoke) | VirtualAlloc, VirtualLock |
| `crypt32.dll` (P/Invoke) | CryptProtectMemory |
| `user32.dll` (P/Invoke) | SetWindowDisplayAffinity (защита от захвата экрана) |
| `System.Text.Json` | Сериализация данных хранилища и настроек |
| `System.IO.Compression` | Импорт / экспорт хранилищ |

<br>

## Начало работы

### Требования

- Windows 10 (сборка 19041+) для полной защиты от захвата экрана
- .NET 8 Desktop Runtime *(не требуется для self-contained сборки)*

### Сборка из исходников

```powershell
git clone https://github.com/J1zeee/CipherVault.git
cd CipherVault
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

**3. Блокировка и разблокировка** — хранилище блокируется через 1 мин бездействия. Мастер-ключ хранится в защищённой памяти (`SecureBuffer`) и очищается при блокировке.

<img src="../Screenshots/SettingsPanel.png" alt="Settings" width="500">

<br>

## Архитектура

```
Мастер-пароль  +  Случайная соль
          │
          ▼
      Argon2id  (128 MiB / 3 iter / 4 потока)
          │
          ▼
  Ключ шифрования  (32 байта, в SecureBuffer)
          │
          ▼
 AES-256-GCM Encrypt / Decrypt
          │
          ▼
  vault.dat  (соль + nonce + ciphertext + tag)
```

- **`vault.dat`** самодостаточен: `[соль 32][nonce 12][ciphertext][tag 16]`. Соль генерируется один раз при создании и хранится открытым текстом в заголовке (она не секретна); она переиспользуется при каждом перешифровании, чтобы ключ можно было вывести заново при следующем входе. **`config.json` больше нет.**
- Вывод Argon2id **и есть ключ** шифрования (без HKDF). При входе соль читается из заголовка, из введённого пароля выводится ключ и предпринимается попытка расшифровать хранилище: верный пароль проверяет аутентификационную метку, неверный — провалится.
- Ключ существует только в памяти процесса внутри `SecureBuffer` (VirtualAlloc + CryptProtectMemory) и очищается при блокировке.

### Хранимые данные

| Файл | Расположение | Содержимое |
|---|---|---|
| `vault.dat` | `%LOCALAPPDATA%\CipherVault\ИмяХранилища\` | Соль + nonce + ciphertext + tag (самодостаточен) |
| `settings.json` | `%APPDATA%\CipherVault\` | Корневая папка хранилищ, журнал, защита экрана, язык |
| `vaults.json` | `%APPDATA%\CipherVault\` | Реестр хранилищ (имя, путь, даты) |
| `lockout.dat` | рядом с `vault.dat` | Запечатанный DPAPI счётчик неудачных попыток (не экспортируется) |
| `audit_yyyyMMdd.log` | `%APPDATA%\CipherVault\Logs\` | Опциональный журнал аудита (ежедневно, ротация 10 MB) |

*Корневая папка хранилищ настраивается в Настройках (по умолчанию `%LOCALAPPDATA%\CipherVault`).*

<br>

## Планы

- [ ] Интеграция Have I Been Pwned (k-anonymity API)
- [ ] Браузерное автозаполнение
- [ ] Android / macOS / Linux (Avalonia / MAUI)

<br>

## Вклад в проект

PR приветствуются. Для крупных изменений сначала откройте issue для обсуждения.

<br>

## Лицензия

[Apache 2.0](../LICENSE)