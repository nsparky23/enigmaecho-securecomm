"""
TOTP (Time-based One-Time Password) Authentication for EnigmaEcho SecureComm
Implements RFC 6238 compliant TOTP with QR code generation for authenticator apps
"""

import os
import json
import base64
import hashlib
import secrets
import time
from typing import Optional, Tuple, Dict, Any
from pathlib import Path
from datetime import datetime, timezone
from cryptography.fernet import Fernet

import pyotp
import qrcode
from qrcode.image.pil import PilImage
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography_utils import encrypt_data, decrypt_data, CryptographyError
from audit_log import log_operation
from config import APP_VERSION, APP_AUTHOR, SESSION_TIMEOUT


class TOTPError(Exception):
    """Custom exception for TOTP operations"""
    pass


class TOTPAuthenticator:
    """
    TOTP Authentication system for EnigmaEcho SecureComm
    Provides secure two-factor authentication with QR code setup
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize TOTP authenticator
        
        Args:
            config_dir: Directory to store TOTP configuration (default: ~/.enigmaecho)
        """
        if config_dir is None:
            config_dir = os.path.expanduser("~/.enigmaecho")
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions
        
        self.config_file = self.config_dir / "totp_config.enc"
        self.backup_codes_file = self.config_dir / "backup_codes.enc"
        
        self._totp_secret: Optional[str] = None
        self._backup_codes: Optional[list] = None
        self._is_setup: bool = False
        
        # TOTP Configuration
        self.issuer_name = "EnigmaEcho SecureComm"
        self.account_name = f"User@{self.issuer_name}"
        self.totp_interval = 30  # 30 seconds
        self.totp_digits = 6
        self.totp_algorithm = hashlib.sha1  # RFC 6238 standard
        
        # Load existing configuration if available
        self._load_configuration()
    
    def is_setup_complete(self) -> bool:
        """Check if TOTP setup is complete"""
        return self._is_setup and self._totp_secret is not None
    
    def setup_totp(self, master_password: str) -> Tuple[str, bytes]:
        """
        Set up TOTP authentication with QR code generation
        
        Args:
            master_password: Master password for encrypting TOTP configuration
            
        Returns:
            Tuple of (secret_key, qr_code_image_bytes)
            
        Raises:
            TOTPError: If setup fails
        """
        try:
            # Generate secure random secret (160 bits = 20 bytes for SHA1)
            secret_bytes = secrets.token_bytes(20)
            secret_key = base64.b32encode(secret_bytes).decode('utf-8')
            
            # Create TOTP instance
            totp = pyotp.TOTP(
                secret_key,
                interval=self.totp_interval,
                digits=self.totp_digits,
                digest=self.totp_algorithm
            )
            
            # Generate provisioning URI for QR code
            provisioning_uri = totp.provisioning_uri(
                name=self.account_name,
                issuer_name=self.issuer_name
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Create QR code image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to bytes
            import io
            img_buffer = io.BytesIO()
            qr_image.save(img_buffer, format='PNG')
            qr_code_bytes = img_buffer.getvalue()
            
            # Generate backup codes
            backup_codes = self._generate_backup_codes()
            
            # Save configuration
            self._save_configuration(secret_key, backup_codes, master_password)
            
            # Update instance variables
            self._totp_secret = secret_key
            self._backup_codes = backup_codes
            self._is_setup = True
            
            # Log setup
            log_operation("TOTP Setup", "SUCCESS", "TEXT")
            
            return secret_key, qr_code_bytes
            
        except Exception as e:
            log_operation("TOTP Setup", "FAILURE", "TEXT", error=e)
            raise TOTPError(f"TOTP setup failed: {str(e)}")
    
    def verify_totp(self, token: str, master_password: str) -> bool:
        """
        Verify TOTP token
        
        Args:
            token: 6-digit TOTP token
            master_password: Master password for decrypting configuration
            
        Returns:
            True if token is valid
            
        Raises:
            TOTPError: If verification fails due to configuration issues
        """
        try:
            # Load configuration if not already loaded
            if not self._is_setup:
                self._load_configuration(master_password)
            
            if not self._totp_secret:
                raise TOTPError("TOTP not configured")
            
            # Clean token (remove spaces, etc.)
            clean_token = ''.join(filter(str.isdigit, token))
            
            if len(clean_token) != self.totp_digits:
                log_operation("TOTP Verification", "FAILURE", "TEXT", 
                            error=Exception("Invalid token length"))
                return False
            
            # Create TOTP instance
            totp = pyotp.TOTP(
                self._totp_secret,
                interval=self.totp_interval,
                digits=self.totp_digits,
                digest=self.totp_algorithm
            )
            
            # Verify token with window (allow 1 interval before/after for clock skew)
            is_valid = totp.verify(clean_token, valid_window=1)
            
            if is_valid:
                log_operation("TOTP Verification", "SUCCESS", "TEXT")
            else:
                log_operation("TOTP Verification", "FAILURE", "TEXT",
                            error=Exception("Invalid TOTP token"))
            
            return is_valid
            
        except Exception as e:
            log_operation("TOTP Verification", "FAILURE", "TEXT", error=e)
            raise TOTPError(f"TOTP verification failed: {str(e)}")
    
    def verify_backup_code(self, backup_code: str, master_password: str) -> bool:
        """
        Verify and consume a backup code
        
        Args:
            backup_code: Backup recovery code
            master_password: Master password for decrypting configuration
            
        Returns:
            True if backup code is valid and consumed
        """
        try:
            # Load configuration if not already loaded
            if not self._is_setup:
                self._load_configuration(master_password)
            
            if not self._backup_codes:
                raise TOTPError("Backup codes not configured")
            
            # Clean backup code
            clean_code = backup_code.strip().upper()
            
            # Check if code exists and remove it (one-time use)
            if clean_code in self._backup_codes:
                self._backup_codes.remove(clean_code)
                
                # Save updated configuration
                self._save_configuration(self._totp_secret, self._backup_codes, master_password)
                
                log_operation("Backup Code Verification", "SUCCESS", "TEXT")
                return True
            else:
                log_operation("Backup Code Verification", "FAILURE", "TEXT",
                            error=Exception("Invalid backup code"))
                return False
                
        except Exception as e:
            log_operation("Backup Code Verification", "FAILURE", "TEXT", error=e)
            raise TOTPError(f"Backup code verification failed: {str(e)}")
    
    def get_backup_codes(self, master_password: str) -> list:
        """
        Get remaining backup codes
        
        Args:
            master_password: Master password for decrypting configuration
            
        Returns:
            List of remaining backup codes
        """
        try:
            if not self._is_setup:
                self._load_configuration(master_password)
            
            return self._backup_codes.copy() if self._backup_codes else []
            
        except Exception as e:
            raise TOTPError(f"Failed to retrieve backup codes: {str(e)}")
    
    def regenerate_backup_codes(self, master_password: str) -> list:
        """
        Generate new backup codes (invalidates old ones)
        
        Args:
            master_password: Master password for encrypting configuration
            
        Returns:
            List of new backup codes
        """
        try:
            if not self._totp_secret:
                raise TOTPError("TOTP not configured")
            
            # Generate new backup codes
            new_backup_codes = self._generate_backup_codes()
            
            # Save configuration with new codes
            self._save_configuration(self._totp_secret, new_backup_codes, master_password)
            
            self._backup_codes = new_backup_codes
            
            log_operation("Backup Codes Regeneration", "SUCCESS", "TEXT")
            
            return new_backup_codes.copy()
            
        except Exception as e:
            log_operation("Backup Codes Regeneration", "FAILURE", "TEXT", error=e)
            raise TOTPError(f"Failed to regenerate backup codes: {str(e)}")
    
    def reset_totp(self) -> bool:
        """
        Reset TOTP configuration (removes all data)
        
        Returns:
            True if reset was successful
        """
        try:
            # Remove configuration files
            if self.config_file.exists():
                self.config_file.unlink()
            
            if self.backup_codes_file.exists():
                self.backup_codes_file.unlink()
            
            # Clear instance variables
            self._totp_secret = None
            self._backup_codes = None
            self._is_setup = False
            
            log_operation("TOTP Reset", "SUCCESS", "TEXT")
            
            return True
            
        except Exception as e:
            log_operation("TOTP Reset", "FAILURE", "TEXT", error=e)
            return False
    
    def _generate_backup_codes(self, count: int = 10) -> list:
        """
        Generate secure backup recovery codes
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        backup_codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            backup_codes.append(formatted_code)
        
        return backup_codes
    
    def _derive_encryption_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from master password
        
        Args:
            master_password: Master password
            salt: Random salt
            
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=480000,  # Same as main app
            backend=default_backend()
        )
        
        return kdf.derive(master_password.encode('utf-8'))
    
    def _save_configuration(self, secret_key: str, backup_codes: list, master_password: str) -> None:
        """
        Save TOTP configuration to encrypted file
        
        Args:
            secret_key: TOTP secret key
            backup_codes: List of backup codes
            master_password: Master password for encryption
        """
        try:
            # Prepare configuration data
            config_data = {
                'version': APP_VERSION,
                'created': datetime.now(timezone.utc).isoformat(),
                'totp_secret': secret_key,
                'backup_codes': backup_codes,
                'issuer': self.issuer_name,
                'account': self.account_name,
                'interval': self.totp_interval,
                'digits': self.totp_digits
            }
            
            # Convert to JSON
            json_data = json.dumps(config_data, indent=2)
            
            # Encrypt configuration
            encrypted_data = encrypt_data(json_data.encode('utf-8'), master_password)
            
            # Write to file with secure permissions
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set secure file permissions (owner read/write only)
            os.chmod(self.config_file, 0o600)
            
        except Exception as e:
            raise TOTPError(f"Failed to save TOTP configuration: {str(e)}")
    
    def _load_configuration(self, master_password: Optional[str] = None) -> None:
        """
        Load TOTP configuration from encrypted file
        
        Args:
            master_password: Master password for decryption
        """
        try:
            if not self.config_file.exists():
                return
            
            if master_password is None:
                # Just check if setup exists
                self._is_setup = True
                return
            
            # Read encrypted configuration
            with open(self.config_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt configuration
            decrypted_data = decrypt_data(encrypted_data, master_password)
            
            # Parse JSON
            config_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Load configuration
            self._totp_secret = config_data.get('totp_secret')
            self._backup_codes = config_data.get('backup_codes', [])
            self._is_setup = True
            
            # Update settings if they exist in config
            if 'interval' in config_data:
                self.totp_interval = config_data['interval']
            if 'digits' in config_data:
                self.totp_digits = config_data['digits']
            
        except CryptographyError:
            raise TOTPError("Invalid master password or corrupted TOTP configuration")
        except Exception as e:
            raise TOTPError(f"Failed to load TOTP configuration: {str(e)}")
    
    def get_current_token(self, master_password: str) -> str:
        """
        Get current TOTP token (for testing purposes)
        
        Args:
            master_password: Master password for decrypting configuration
            
        Returns:
            Current TOTP token
        """
        try:
            if not self._is_setup:
                self._load_configuration(master_password)
            
            if not self._totp_secret:
                raise TOTPError("TOTP not configured")
            
            totp = pyotp.TOTP(
                self._totp_secret,
                interval=self.totp_interval,
                digits=self.totp_digits,
                digest=self.totp_algorithm
            )
            
            return totp.now()
            
        except Exception as e:
            raise TOTPError(f"Failed to get current token: {str(e)}")
    
    def get_time_remaining(self) -> int:
        """
        Get seconds remaining until next TOTP token
        
        Returns:
            Seconds remaining
        """
        import time
        current_time = int(time.time())
        return self.totp_interval - (current_time % self.totp_interval)


# Global TOTP authenticator instance
totp_authenticator = TOTPAuthenticator()


def get_totp_authenticator() -> TOTPAuthenticator:
    """Get the global TOTP authenticator instance"""
    return totp_authenticator
