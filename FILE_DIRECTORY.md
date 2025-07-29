# EnigmaEcho SecureComm - Final File Directory

## Core Application Files:
- **main.py** - Application entry point with mandatory TOTP setup
- **gui_components.py** - Main GUI with improved dropdowns and TOTP integration
- **totp_auth.py** - TOTP authentication system (RFC 6238 compliant)
- **totp_setup_improved.py** - Enhanced TOTP setup dialog (700x900, better UX)
- **cryptography_utils.py** - AES-256-GCM encryption with PBKDF2 key derivation
- **file_handler.py** - Secure file operations with manual save dialogs
- **audit_log.py** - Sanitized security audit logging
- **config.py** - Application configuration and UI theme constants

## Dependencies & Documentation:
- **requirements.txt** - Python package dependencies
- **README.md** - Comprehensive documentation and usage guide

## Testing:
- **test_totp.py** - Comprehensive TOTP functionality test suite

## Total Files: 10

## Key Features Implemented:
✅ **Mandatory TOTP Setup** - Users must set up 2FA before app access
✅ **Improved UI** - Light-themed dropdowns for better readability  
✅ **Large QR Codes** - 280x280 display area, no overlapping elements
✅ **Professional Styling** - Modern dark theme with silver-blue accents
✅ **Enterprise Security** - NIST/OWASP compliant encryption
✅ **Local-Only Processing** - No cloud dependencies
✅ **Comprehensive Testing** - Full test suite for all functionality

## Installation & Usage:
1. Download all 10 files
2. Install dependencies: `pip install -r requirements.txt`
3. Run application: `python main.py`
4. Complete mandatory TOTP setup on first launch
5. Use Security menu for TOTP management

## Security Features:
- AES-256-GCM encryption with unique nonce/IV
- PBKDF2-HMAC-SHA256 key derivation (480,000+ iterations)
- TOTP two-factor authentication with backup codes
- HMAC-SHA256 authentication tags
- Secure audit logging with integrity verification
- Manual file control (no automatic saves)
- Encrypted configuration storage