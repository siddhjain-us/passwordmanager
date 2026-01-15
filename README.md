# 🔐 Secure Password Manager

A command-line password manager with military-grade encryption, TOTP-based two-factor authentication, and intelligent password strength analysis.

<div align="center">

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Cryptography](https://img.shields.io/badge/encryption-AES--128-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security](https://img.shields.io/badge/security-2FA%20enabled-brightgreen.svg)

</div>

---

## ✨ Features

### Core Security
- 🔒 **AES-128 Encryption** via Fernet symmetric encryption
- 🔑 **PBKDF2 Key Derivation** with 480,000 iterations using SHA-256
- 🧂 **Salt-Based Protection** against rainbow table attacks
- 🔐 **Two-Factor Authentication** using TOTP (Time-based One-Time Passwords)
- 🎲 **Cryptographically Secure Password Generation** 

### Password Management
- 📋 **Full CRUD Operations** - Create, read, search, and delete passwords
- 🔍 **Intelligent Search** with partial matching
- 💪 **Password Strength Analyzer** with real-time feedback
- 🔄 **Master Password Change** with automatic re-encryption
- 🗑️ **Bulk Operations** including delete all functionality

### User Experience
- 🙈 **Hidden Input** for master password (no shoulder surfing)
- 📊 **Visual Strength Indicators** (🔴 Weak → 💎 Excellent)
- ⚠️ **Smart Suggestions** for improving weak passwords
- ✅ **Graceful Error Handling** for all edge cases
- 📱 **QR Code Generation** for easy 2FA setup

---

## 🛡️ Security Architecture

### Encryption Flow

```
Master Password + Salt
       ↓
PBKDF2 (480,000 iterations)
       ↓
32-byte Encryption Key
       ↓
Fernet (AES-128-CBC + HMAC)
       ↓
Encrypted Password Storage
```

### How It Works

**Key Derivation Process:**
1. **Salt Generation**: 16-byte cryptographically secure random salt (generated once)
2. **PBKDF2-HMAC-SHA256**: Transforms master password through 480,000 iterations
3. **Base64 Encoding**: Converts to URL-safe format for Fernet compatibility
4. **Zero-Knowledge Architecture**: Encryption key exists only in memory, never stored

**Two-Factor Authentication:**
- TOTP implementation compatible with Google Authenticator, Authy, and similar apps
- 30-second rotating codes with QR code provisioning
- Encrypted secret storage using the same Fernet encryption
- Optional feature that can be enabled/disabled

**Password Strength Analysis:**
Uses regex pattern matching to evaluate:
- Length (minimum 8, recommended 12+)
- Character diversity (uppercase, lowercase, numbers, symbols)
- Real-time scoring from 🔴 Weak to 💎 Excellent
- Actionable suggestions for improvement

---

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/password-manager.git
cd password-manager

# Install dependencies
pip install -r requirements.txt

# Run the application
python password_manager.py
```

### Dependencies
```
cryptography>=41.0.0
pyotp>=2.9.0
qrcode>=7.4.2
```

---

## 💻 Usage

### First Launch

When you first run the program:

1. A cryptographic salt file (`salt.salt`) is automatically generated
2. You'll set your master password (choose something strong!)
3. Optionally enable 2FA for additional security

### Main Menu

```
============================================================
                  PASSWORD MANAGER
============================================================
  [1] View all passwords
  [2] Add new password
  [3] Search passwords
  [4] Delete password
  [5] Change master password
  [6] Setup 2FA (if not done already)
  [7] Disable 2FA (if already set up)
  [8] Quit
============================================================
```

### Common Workflows

**Adding a Password (Generated):**
```bash
Select option: 2
Account Name: Gmail
Generate password or enter manually? (g/m): g
Password length (press Enter for 16): 20
Generated Password: xK9#mL2$pQ7!vN3@hR8%
```

**Adding a Password (Manual with Strength Check):**
```bash
Select option: 2
Account Name: Netflix
Generate password or enter manually? (g/m): m
Password: mypassword
Password Strength: Weak 🔴
Add uppercase letters.
Add some numbers.
Add some special characters.
Consider using a stronger password and try again.
```

**Setting Up 2FA:**
```bash
Select option: 6
Enter your desired account name for 2FA: john@example.com

    2FA SETUP
====================

Scan this QR code with Google Authenticator or Authy:
[QR CODE DISPLAYED IN TERMINAL]

Manual Entry Key: JBSWY3DPEHPK3PXP
------------------------------
Enter the 6-digit code from your app to confirm setup: 123456
✅ 2FA setup successful and enabled!
```

**Changing Master Password:**
```bash
Select option: 5
Current Master Password: [hidden]
New Master Password: [hidden]
Confirm Master Password: [hidden]
Master password updated successfully.
```

---

## 📁 File Structure

```
password-manager/
├── password_manager.py    # Main application
├── requirements.txt       # Python dependencies
├── README.md             # Documentation
├── .gitignore            # Git exclusions
│
├── salt.salt             # Cryptographic salt (auto-generated)
├── passwords.txt         # Encrypted password vault (auto-generated)
└── 2fa.config           # Encrypted 2FA secret (if enabled)
```

**Important:** Never commit `salt.salt`, `passwords.txt`, or `2fa.config` to version control!

---

## 🔒 Security Deep Dive

### What This Protects Against

| Attack Vector | Protection Method |
|--------------|-------------------|
| Brute Force | 480,000 PBKDF2 iterations (~0.1s per guess) |
| Rainbow Tables | Unique salt per installation |
| Data Tampering | Fernet's built-in HMAC authentication |
| Weak Passwords | Strength checker with actionable feedback |
| Unauthorized Access | Optional 2FA with TOTP |
| Password Reuse | Secure password generator |

### What This Does NOT Protect Against

⚠️ **System Compromises:**
- Keyloggers or malware on your computer
- Physical access to an unlocked session
- Screen recording or shoulder surfing (partially mitigated)

⚠️ **User-Related Risks:**
- Weak master passwords (even with PBKDF2)
- Loss of 2FA device without backup codes
- Accidental deletion without backups

⚠️ **Implementation Limitations:**
- Single-user local storage (no cloud sync)
- No encrypted backups (yet)
- Terminal-based (no GUI)

---

## 🎯 Technical Implementation

### Password Strength Algorithm

The strength checker evaluates passwords on a 0-5 scale:

```python
Score Breakdown:
+2 points: Length ≥ 12 characters
+1 point:  Length ≥ 8 characters
+1 point:  Contains uppercase letters
+1 point:  Contains lowercase letters
+1 point:  Contains numbers
+1 point:  Contains special characters

Rating Scale:
0-1: Weak 🔴
2:   Fair 🟠
3:   Good 🟡
4:   Strong 🟢
5:   Excellent 💎
```

### Master Password Change Process

When changing the master password:

1. **Verification**: Current password verified with existing key
2. **Decryption**: All passwords decrypted using old key
3. **Re-encryption**: All passwords re-encrypted with new key
4. **Atomic Write**: File updated in single operation
5. **Session Update**: Current session key refreshed

This ensures data integrity throughout the process.

### 2FA Implementation

Uses TOTP (RFC 6238) with these parameters:
- **Algorithm**: SHA-1 (standard for TOTP)
- **Time Step**: 30 seconds
- **Code Length**: 6 digits
- **Secret Storage**: Encrypted with same Fernet key as passwords

---

## 🚧 Known Limitations

1. **Single User**: Designed for personal use on one device
2. **No Backup System**: Manual backup of files required
3. **CLI Only**: No graphical interface (yet)
4. **No Password History**: Changes aren't tracked
5. **No Biometric Auth**: Relies on master password + optional 2FA

---

## 🛠️ Future Enhancements

- Encrypted backup/restore functionality
- Password expiration reminders
- Password change history
- Clipboard integration with auto-clear
- Cross-platform GUI (Electron or PyQt)
- Cloud sync with end-to-end encryption
- Password breach checking via Have I Been Pwned API
- Biometric authentication support
- Multi-user support with per-user vaults

---

## 🤝 Contributing

Found a bug or have a feature request? Feel free to:
- Open an issue
- Submit a pull request
- Suggest improvements

All contributions are welcome!

---

## 📜 License

MIT License - Free to use for personal and educational purposes.

---

## ⚠️ Disclaimer

This project was built as an educational exercise in applied cryptography and secure software development. While it implements industry-standard security practices, it has not undergone professional security auditing.

For production use or managing critical credentials, consider established solutions like:
- **Bitwarden** (open-source, self-hostable)
- **1Password** (commercial, well-audited)
- **KeePassXC** (open-source, offline-first)

---

## 👨‍💻 Author

**Siddh Jain**

Connect with me:
- GitHub: [@siddhjain-us](https://github.com/siddhjain-us)
- LinkedIn: Siddh Jain - (https://www.linkedin.com/in/siddh-jain-8448452b9/)

---

## 🙏 Acknowledgments

Built using:
- [Cryptography](https://cryptography.io/) - Python cryptographic library
- [PyOTP](https://pyauth.github.io/pyotp/) - TOTP implementation
- [QRCode](https://github.com/lincolnloop/python-qrcode) - QR code generation

Inspired by best practices from OWASP, NIST, and the cryptography community.

---

<div align="center">

**Remember: Your security is only as strong as your master password!**

Choose wisely. 🔐

</div>