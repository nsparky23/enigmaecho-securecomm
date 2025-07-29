# EnigmaEcho SecureComm

A desktop and Android-compatible encrypted communication tool built with strong cryptographic and file-handling features based on modern NIST and industry best practices.

## Features

### 🔐 Security Features
- **AES-256-GCM Encryption** with unique nonce/IV for each operation
- **PBKDF2-HMAC-SHA256** key derivation with 480,000+ iterations
- **HMAC-SHA256** authentication tags for tamper detection
- **Secure memory management** with automatic cleanup
- **No automatic caching** or cloud uploads
- **NIST SP 800-63B, NIST SP 800-57, and OWASP compliant**

### 💻 User Interface
- **Modern dark theme** with silver-blue accents
- **Responsive PySide6 GUI** with clean typography
- **Segmented layout** for text and file operations
- **Manual file control** - no automatic saves
- **Real-time file management** with table view
- **Secure audit logging** with integrity verification

### 📝 Text Operations
- Encrypt/decrypt text with secure passphrase entry
- Copy results to clipboard or save to file
- Base64 encoding for encrypted text display
- Placeholder text that disappears on input

### 📁 File Operations
- Encrypt/decrypt multiple files with batch processing
- Manual save dialogs for complete user control
- Obfuscated filename generation for privacy
- Image rendering validation after decryption
- Progress tracking for batch operations

### 📊 Audit & Logging
- Sanitized operation logging (no sensitive data stored)
- Timestamp tracking with timezone support
- Success/failure outcome recording
- Optional log encryption
- Auto-wipe on exit for security
- Export functionality for compliance

## Installation

### Prerequisites
- Python 3.8 or higher
- Virtual environment (recommended)

### Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
- `PySide6` - Modern Qt6-based GUI framework
- `cryptography` - Industry-standard cryptographic library
- `pyperclip` - Clipboard operations
- `Pillow` - Image processing and validation

### Setup
1. Clone or download the application files
2. Create a virtual environment:
   ```bash
   python -m venv enigma_env
   source enigma_env/bin/activate  # On Windows: enigma_env\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python main.py
   ```

## Usage

### Text Encryption/Decryption
1. Enter text in the input field
2. Select "Encrypt" or "Decrypt" from the operation dropdown
3. Click "Process Text" and enter your passphrase
4. Choose "Copy to Clipboard" or "Copy to File" for output
5. Click "Execute Action" to complete the operation

### File Encryption/Decryption
1. Click "Add Files" to select files for processing
2. Files appear in the table with name, size, and type
3. Select files and click "Remove Selected" if needed
4. Choose "Encrypt" or "Decrypt" from the operation dropdown
5. Click "Process Files" and enter your passphrase
6. Each file will prompt for a save location (manual control)

### Audit Log
- Click "Audit Log" to view operation history
- Logs show timestamps, actions, outcomes, and file hashes
- Export logs to JSON format with optional encryption
- Clear logs when needed (with confirmation)

## Security Architecture

### Cryptographic Implementation
```
Passphrase → PBKDF2-HMAC-SHA256 (480k iterations) → Encryption Key + HMAC Key
                                                   ↓
Data → AES-256-GCM (unique nonce) → Ciphertext + Auth Tag
                                   ↓
Final Package: Salt + Nonce + Ciphertext + Auth Tag + HMAC
```

### Key Security Features
- **No key reuse** - unique salt and nonce for every operation
- **Memory protection** - sensitive data wiped after use
- **Tamper detection** - HMAC verification prevents data modification
- **Filename obfuscation** - original names hidden using SHA-256 hashing
- **Audit trail** - all operations logged without sensitive data

### Compliance Standards
- **NIST SP 800-63B** - Digital identity guidelines
- **NIST SP 800-57** - Cryptographic key management
- **OWASP Cryptographic Storage** - Secure data storage practices

## File Structure

```
EnigmaEcho_SecureComm/
├── main.py                 # Application entry point
├── gui_components.py       # PySide6 GUI implementation
├── cryptography_utils.py   # Encryption/decryption functions
├── file_handler.py         # File operations and management
├── audit_log.py           # Secure logging system
├── config.py              # Configuration and constants
├── requirements.txt       # Python dependencies
└── README.md             # This documentation
```

## Configuration

Edit `config.py` to customize:
- **UI Colors** - Dark theme and accent colors
- **Crypto Settings** - Iteration counts and key lengths
- **Security Options** - Auto-wipe and memory protection
- **UI Behavior** - Window size and font settings

## Future Enhancements

### Planned Features
- **TOTP Integration** - Two-factor authentication on launch
- **Cross-platform Packaging** - .exe (Windows) and .apk (Android)
- **Cloud Messaging** - Optional secure communication features
- **Email Export** - Encrypted message export capability

### Development Roadmap
1. TOTP authentication system
2. PyInstaller packaging for Windows
3. BeeWare/Briefcase for Android deployment
4. Optional cloud integration hooks
5. Enhanced audit log encryption

## Security Considerations

### Best Practices
- Use strong, unique passphrases for each operation
- Verify file integrity after decryption
- Regularly review audit logs for suspicious activity
- Keep the application updated with security patches
- Use in air-gapped environments for maximum security

### Limitations
- Python memory management limits secure deletion effectiveness
- GUI framework may cache some display data temporarily
- File system may retain deleted file fragments
- Network isolation recommended for sensitive operations

## Troubleshooting

### Common Issues
1. **Import Errors** - Ensure all dependencies are installed in virtual environment
2. **GUI Not Displaying** - Check PySide6 installation and system compatibility
3. **Decryption Failures** - Verify passphrase and file integrity
4. **File Permission Errors** - Run with appropriate file system permissions

### Debug Mode
Set environment variable for verbose logging:
```bash
export ENIGMA_DEBUG=1  # Linux/Mac
set ENIGMA_DEBUG=1     # Windows
python main.py
```

## License

This application is designed for educational and professional use in secure environments. Please ensure compliance with local encryption regulations and export controls.

## Support

For technical support or security questions:
- Review the audit logs for operation details
- Check the console output for error messages
- Verify all dependencies are correctly installed
- Ensure Python 3.8+ compatibility

---

**EnigmaEcho SecureComm v1.0.0**  
*Secure Local Encryption - No Cloud, No Compromise*
