"""
Session Management for EnigmaEcho SecureComm
Handles TOTP session authentication and timeout management
"""

import time
import json
import os
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from datetime import datetime, timezone

from audit_log import log_operation
from config import SESSION_TIMEOUT, APP_VERSION


class SessionManager:
    """Manages TOTP authentication sessions with timeout"""
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = os.path.expanduser("~/.enigmaecho")
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True, mode=0o700)
        
        self.profile_file = self.config_dir / "profile.enc"
        self.profile_key_file = self.config_dir / "profile.key"
        
        # Session state
        self.session_authenticated: bool = False
        self.last_activity_timestamp: Optional[float] = None
        self._profile_key: Optional[bytes] = None
        
        # Load persistent profile if available
        self._load_profile_key()
    
    def establish_session(self) -> None:
        """Establish an authenticated session"""
        self.session_authenticated = True
        self.last_activity_timestamp = time.time()
        log_operation("Session Established", "SUCCESS", "TEXT")
    
    def is_session_active(self) -> bool:
        """
        Check if the current session is still active
        
        Returns:
            True if session is active, False otherwise
        """
        if not self.session_authenticated:
            return False
        
        if self.last_activity_timestamp is None:
            return False
        
        elapsed_time = time.time() - self.last_activity_timestamp
        return elapsed_time < SESSION_TIMEOUT
    
    def update_session(self) -> None:
        """Update the last activity timestamp"""
        if self.session_authenticated:
            self.last_activity_timestamp = time.time()
    
    def end_session(self) -> None:
        """End the current session"""
        self.session_authenticated = False
        self.last_activity_timestamp = None
        log_operation("Session Ended", "SUCCESS", "TEXT")
    
    def get_session_time_remaining(self) -> int:
        """
        Get seconds remaining in current session
        
        Returns:
            Seconds remaining, or 0 if session is inactive
        """
        if not self.is_session_active():
            return 0
        
        elapsed_time = time.time() - self.last_activity_timestamp
        remaining = SESSION_TIMEOUT - elapsed_time
        return max(0, int(remaining))
    
    def _generate_profile_key(self) -> bytes:
        """Generate a key for encrypting the persistent profile"""
        return Fernet.generate_key()
    
    def _load_profile_key(self) -> None:
        """Load the profile encryption key"""
        try:
            if self.profile_key_file.exists():
                with open(self.profile_key_file, 'rb') as f:
                    self._profile_key = f.read()
        except Exception as e:
            log_operation("Profile Key Load", "FAILURE", "TEXT", error=e)
    
    def save_persistent_profile(self, totp_secret: str, backup_codes: list, 
                               issuer: str, account: str, interval: int, digits: int) -> None:
        """Save TOTP configuration to persistent profile with separate encryption"""
        try:
            # Generate or load profile encryption key
            if self._profile_key is None:
                self._profile_key = self._generate_profile_key()
                # Save the key to a separate file
                with open(self.profile_key_file, 'wb') as f:
                    f.write(self._profile_key)
                os.chmod(self.profile_key_file, 0o600)
            
            # Prepare profile data
            profile_data = {
                'version': APP_VERSION,
                'created': datetime.now(timezone.utc).isoformat(),
                'totp_secret': totp_secret,
                'backup_codes': backup_codes,
                'issuer': issuer,
                'account': account,
                'interval': interval,
                'digits': digits
            }
            
            # Encrypt with Fernet
            fernet = Fernet(self._profile_key)
            json_data = json.dumps(profile_data, indent=2)
            encrypted_data = fernet.encrypt(json_data.encode('utf-8'))
            
            # Write to profile file
            with open(self.profile_file, 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod(self.profile_file, 0o600)
            log_operation("Profile Saved", "SUCCESS", "TEXT")
            
        except Exception as e:
            log_operation("Profile Save", "FAILURE", "TEXT", error=e)
            raise Exception(f"Failed to save persistent profile: {str(e)}")
    
    def load_persistent_profile(self) -> Optional[dict]:
        """Load TOTP configuration from persistent profile"""
        try:
            # Check if both profile and key files exist
            if not (self.profile_file.exists() and self.profile_key_file.exists()):
                return None
            
            # Load encryption key if not already loaded
            if self._profile_key is None:
                self._load_profile_key()
            
            if self._profile_key is None:
                return None
            
            # Load and decrypt profile
            with open(self.profile_file, 'rb') as f:
                encrypted_data = f.read()
            
            fernet = Fernet(self._profile_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            profile_data = json.loads(decrypted_data.decode('utf-8'))
            
            log_operation("Profile Loaded", "SUCCESS", "TEXT")
            return profile_data
            
        except Exception as e:
            # If loading fails, just continue without persistent profile
            log_operation("Profile Load", "FAILURE", "TEXT", error=e)
            return None
    
    def clear_persistent_profile(self) -> bool:
        """Clear the persistent profile"""
        try:
            if self.profile_file.exists():
                self.profile_file.unlink()
            
            if self.profile_key_file.exists():
                self.profile_key_file.unlink()
            
            self._profile_key = None
            log_operation("Profile Cleared", "SUCCESS", "TEXT")
            return True
            
        except Exception as e:
            log_operation("Profile Clear", "FAILURE", "TEXT", error=e)
            return False


# Global session manager instance
session_manager = SessionManager()


def get_session_manager() -> SessionManager:
    """Get the global session manager instance"""
    return session_manager
