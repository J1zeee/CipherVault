# CipherVault

**Secure, offline password manager for Windows with modern cryptography.**

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/download)
[![C#](https://img.shields.io/badge/C%23-12-239120?logo=csharp)](https://learn.microsoft.com/dotnet/csharp)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?logo=windows)](https://www.microsoft.com/windows)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue)](https://github.com/J1zeee/CipherVault/releases/latest)
[![Readme](https://img.shields.io/badge/Readme-Русский-1976D2)](docs/README-RU.md)

<br>

<img src="Screenshots/MainApp.png" alt="Main Application" width="700">

*Main vault screen with credential list and details panel.*

<br>

## Features

- **AES-256-GCM** authenticated encryption for all vault data
- **Argon2id** key derivation (128 MiB memory, 3 iterations, 4 threads)
- **Single derived key** — the Argon2id output *is* the AES key
- **Decrypt-to-verify unlock** — a wrong password simply fails to decrypt the vault
- **Self-contained `vault.dat`** — the Argon2id salt lives in the file header
- **Secure in-memory buffers** — `VirtualAlloc` + `VirtualLock` + `CryptProtectMemory`, zeroed on dispose
- **Anti-screen-capture** via `SetWindowDisplayAffinity` (`WDA_EXCLUDEFROMCAPTURE`, `WDA_MONITOR` fallback)
- **Clipboard protection** — auto-clear after 10 s, excluded from Win+V history and cloud clipboard
- **Auto-lock** after 1 minute of inactivity
- **Brute-force protection** — per-vault exponential backoff (up to ~34 min), persisted with DPAPI
- **Cryptographic password generator** with entropy and crack-time analysis
- **Audit logging** (optional, disabled by default)
- **Multi-vault** support with import/export as ZIP and safe deletion
- **Multi-language** UI (English / Russian)
- **Dark theme** with custom WPF controls and subtle animations
- **Self-contained single-file** publish — no runtime required

<br>

## Security & Threat Model

| Protected against | Notes |
|---|---|
| **Master password brute-force** | Argon2id (128 MiB, 3 iter) + exponential backoff after 5 failures, persisted per vault |
| **Memory dump extraction** | VirtualLock pins pages in RAM; CryptProtectMemory encrypts buffers; everything is zeroed on release |
| **Wrong password / ciphertext tampering** | AES-GCM authentication tag rejects modified vaults; a wrong key fails to decrypt |
| **Screen capture** | `WDA_EXCLUDEFROMCAPTURE` on all app windows (`WDA_MONITOR` fallback on older builds) |
| **Clipboard history & cloud sync** | Secrets are excluded from Win+V history and cloud clipboard before copying |
| **Process hardening (Release builds)** | Single-instance mutex (Global), anti-debugger checks, forced ASLR relocation, remote/low-integrity image blocking and a strict child-process ban. No external process can be spawned. Debug builds skip all of it |

| Not covered | Reason |
|---|---|
| **Keylogger / formgrabbing** | The OS is assumed trusted; no magic bullet for user-side malware |
| **Compromised OS** | If the attacker controls the system, all in-process protection is bypassable |
| **Physical access with memory freezer** | Cold boot attacks are out of scope for a desktop app |

### Argon2id parameters

| Parameter | Value |
|---|---|
| Algorithm | Argon2id |
| Memory | 128 MiB |
| Iterations | 3 |
| Parallelism | 4 threads |
| Salt | 32 bytes (random per vault, stored in the vault header) |
| Output | 32 bytes (the AES-256 key) |

<br>

## Tech Stack

```
.NET 8.0  •  WPF  •  C# 12
```

| Library / API | Purpose |
|---|---|
| `System.Security.Cryptography` | AES-256-GCM, RNG, constant-time ops |
| `Konscious.Security.Cryptography.Argon2` | Argon2id KDF |
| `System.Security.Cryptography.ProtectedData` | DPAPI sealing for per-vault lockout state |
| `kernel32.dll` (P/Invoke) | VirtualAlloc, VirtualLock |
| `crypt32.dll` (P/Invoke) | CryptProtectMemory |
| `user32.dll` (P/Invoke) | SetWindowDisplayAffinity (screen-capture protection) |
| `System.Text.Json` | Vault data & settings serialization |
| `System.IO.Compression` | Vault import/export |

<br>

## Getting Started

### Requirements

- Windows 10 (build 19041+) for full screen-capture exclusion
- .NET 8 Desktop Runtime *(not needed if using the self-contained build)*

### Build from source

```powershell
git clone https://github.com/J1zeee/CipherVault.git
cd CipherVault
dotnet publish -c Release -r win-x64 --self-contained true
.\bin\Release\net8.0-windows10.0.26100.0\win-x64\publish\CipherVault.exe
```

### Download release

Download the latest `CipherVault-v1.0.0.zip` from [Releases](https://github.com/J1zeee/CipherVault/releases/latest), extract and run `CipherVault.exe`.

<br>

## Usage

**1. Create a vault** — set a master password (Argon2id derives the encryption key).

<img src="Screenshots/LoginScreen.png" alt="Login screen" width="500">

**2. Add credentials** — title, username, email, password, website, notes. Generate strong passwords with the built-in generator.

<img src="Screenshots/AddCredential.png" alt="Add credential" width="500">

**3. Lock & unlock** — the vault locks after 1 minute of inactivity. The master key is held in protected memory (`SecureBuffer`) and wiped on lock.

<img src="Screenshots/SettingsPanel.png" alt="Settings" width="500">

<br>

## Architecture

```
Master password  +  Random salt
          │
          ▼
      Argon2id  (128 MiB / 3 iter / 4 threads)
          │
          ▼
  Encryption key  (32 bytes, held in SecureBuffer)
          │
          ▼
 AES-256-GCM Encrypt / Decrypt
          │
          ▼
  vault.dat  (salt + nonce + ciphertext + tag)
```

- **`vault.dat`** is self-contained: `[salt 32][nonce 12][ciphertext][tag 16]`. The salt is generated once at creation and stored in plaintext as the header (it is not secret); it is reused for every re-encryption so the key can be re-derived at the next login. There is **no `config.json`**.
- The Argon2id output **is** the encryption key (no HKDF split). Unlocking reads the salt from the header, derives the key from the typed password, and attempts to decrypt the vault: a correct password validates the authentication tag, a wrong one fails.
- The key exists only in process memory inside a `SecureBuffer` (VirtualAlloc + CryptProtectMemory) and is wiped on lock.

### Data at rest

| File | Location | Contents |
|---|---|---|
| `vault.dat` | `%LOCALAPPDATA%\CipherVault\VaultName\` | Salt + nonce + ciphertext + tag (self-contained) |
| `settings.json` | `%APPDATA%\CipherVault\` | Vaults root path, logging toggle, capture protection, language |
| `vaults.json` | `%APPDATA%\CipherVault\` | Vault registry (name, path, timestamps) |
| `lockout.dat` | beside `vault.dat` | DPAPI-sealed failed-attempt counter (never exported) |
| `audit_yyyyMMdd.log` | `%APPDATA%\CipherVault\Logs\` | Optional audit log (daily, 10 MB rotation) |

<br>

## Roadmap

- [ ] Have I Been Pwned integration (k-anonymity API)
- [ ] Browser auto-fill extension
- [ ] Android / macOS / Linux support (Avalonia / MAUI)

<br>

## Contributing

PRs are welcome. For major changes, open an issue first to discuss.

<br>

## License

[Apache 2.0](LICENSE)