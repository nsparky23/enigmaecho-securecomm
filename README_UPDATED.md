# EnigmaEcho SecureComm - Updated Implementation

## Overview

EnigmaEcho SecureComm is a secure desktop encryption tool with modern GUI and strong cryptographic practices. This updated version includes comprehensive improvements to the GUI layout and TOTP authentication system.

## ✅ Key Improvements

### GUI Layout Enhancements
- **Responsive Design**: Dynamic auto-scaling with proper layout managers (QVBoxLayout, QHBoxLayout, QSplitter)
- **Removed Fixed Sizing**: All components now use minimum sizes and stretch factors for responsive behavior
- **Improved Organization**: Text and file operation panels use efficient splitter-based layout
- **Modern Interface**: Larger default sizes (1200x900) with responsive minimum (900x700)

### TOTP Authentication Enhancements
- **Persistent Configuration**: TOTP settings stored in encrypted local profile (`~/.enigmaecho/profile.enc`)
- **Session Management**: 30-minute timeout with activity tracking and real-time status display
- **Streamlined Authentication**: Removed backup code UI clutter, single login per session
- **Access Control**: All operations gated behind active session verification

## 🚀 Quick Start

### Prerequisites
```bash
pip install PySide6 cryptography pyperclip Pillow
```

### Running the Application
```bash
python main_updated.py
```

### First-Time Setup
1. Launch the application
2. Go to **Security → Setup TOTP Authentication**
3. Enter a master password and scan the QR code with your authenticator app
4. Complete verification - configuration persists across sessions

### Daily Usage
1. Launch application
2. Authenticate once with TOTP login dialog
3. Use application normally - session remains active for 30 minutes
4. Session automatically expires after inactivity

## 📁 File Structure

### Core Application Files
- `main_updated.py` - Updated application entry point
- `main_window_updated.py` - Responsive main window with session management
- `session_manager.py` - Session and persistent profile management
- `totp_login_updated.py` - Clean login dialog without backup code functionality
- `config.py` - Updated configuration with session timeout settings

### Existing Core Files
- `totp_auth.py` - TOTP authentication system
- `totp_setup_improved.py` - Improved TOTP setup dialog
- `cryptography_utils.py` - Cryptographic operations
- `audit_log.py` - Security audit logging
- `file_handler.py` - File encryption/decryption operations

### Testing and Documentation
- `test_updated_implementation.py` - Comprehensive validation tests
- `IMPLEMENTATION_SUMMARY.md` - Detailed implementation documentation

## 🔧 Technical Features

### Security Features
- **AES-256-GCM Encryption** with PBKDF2 key derivation (480,000+ iterations)
- **TOTP Two-Factor Authentication** with persistent configuration
- **Session Management** with 30-minute timeout and activity tracking
- **HMAC-SHA256 Authentication** tags for data integrity
- **Secure Audit Logging** with automatic cleanup

### Compliance
- **NIST SP 800-63B** Digital Identity Guidelines
- **NIST SP 800-57** Cryptographic Key Management
- **OWASP** Cryptographic Storage Guidelines

### UI/UX Features
- **Responsive Layout** that adapts to window resizing
- **Modern Dark Theme** with clean typography
- **Session Status Display** with real-time countdown
- **Intuitive Navigation** with organized menu structure
- **Error Handling** with user-friendly messages

## 🧪 Testing

Run the validation tests to verify the implementation:
```bash
python test_updated_implementation.py
```

Expected output: All 6 validation tests should pass, confirming:
- Config updates with session timeout
- Complete file structure
- Responsive design elements
- Session management integration
- Removal of backup code functionality

## 🔒 Security Architecture

### Session Management Flow
1. **Authentication**: User logs in with TOTP code
2. **Session Establishment**: 30-minute timer starts
3. **Activity Tracking**: Timestamp updated on each operation
4. **Automatic Timeout**: Session expires after inactivity
5. **Re-authentication**: Required after timeout or app restart

### Persistent Storage
- **Profile Encryption**: Separate Fernet encryption for TOTP configuration
- **Key Management**: Independent encryption key from master password
- **Secure Permissions**: All config files set to 0o600 (owner read/write only)
- **Cross-Session Persistence**: TOTP setup survives application restarts

## 📋 Usage Examples

### Text Operations
1. Enter text in the input area
2. Select "Encrypt" or "Decrypt" operation
3. Click "Process Text" (triggers session check)
4. Use "Execute Action" to copy or save results

### File Operations
1. Click "Add Files" to select files for processing
2. Choose "Encrypt" or "Decrypt" operation
3. Click "Process Files" (triggers session check)
4. Files are processed with session-protected operations

### Session Management
- View current session status in the main window header
- Use **Security → Session → End Current Session** to logout manually
- Session automatically expires after 30 minutes of inactivity

## 🛠️ Development

### Architecture
- **Modular Design**: Separate modules for UI, authentication, and cryptography
- **Event-Driven**: Qt-based event system with proper signal/slot connections
- **Error Handling**: Comprehensive exception handling with user feedback
- **Logging**: Detailed audit trail for all security operations

### Extending the Application
- Add new operations by extending the widget classes
- Implement additional authentication methods in `session_manager.py`
- Customize UI themes by modifying `config.py` color constants
- Add new cryptographic algorithms in `cryptography_utils.py`

## 📞 Support

For issues or questions:
1. Check the `IMPLEMENTATION_SUMMARY.md` for detailed technical information
2. Run validation tests to verify installation
3. Review audit logs for security-related issues
4. Ensure all dependencies are properly installed

## 🎯 Version Information

- **Version**: 1.0.0 (Updated Implementation)
- **Python**: 3.8+ required
- **Dependencies**: PySide6, cryptography, pyperclip, Pillow
- **Platform**: Cross-platform (Windows, macOS, Linux)
- **License**: Secure local-only processing, no cloud dependencies

---

**EnigmaEcho SecureComm** - Local-Only Processing • No Cloud • No Compromise
