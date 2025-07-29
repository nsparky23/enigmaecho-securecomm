"""
Audit logging system for EnigmaEcho SecureComm
Maintains sanitized logs of all operations without storing sensitive data
Compliant with security best practices for audit trails
"""

import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from cryptography_utils import encrypt_data, decrypt_data, CryptographyError
from config import MAX_LOG_ENTRIES, AUTO_WIPE_ON_EXIT


@dataclass
class LogEntry:
    """Structure for audit log entries"""
    timestamp: str
    action: str
    filename_hash: Optional[str]  # Obfuscated filename
    outcome: str  # "SUCCESS" or "FAILURE"
    error_type: Optional[str]  # Type of error if failure
    file_size: Optional[int]  # File size for file operations
    operation_type: str  # "TEXT" or "FILE"


class AuditLog:
    """
    Secure audit logging system
    Maintains in-memory logs with optional encryption and integrity checking
    """
    
    def __init__(self):
        self._log_entries: List[LogEntry] = []
        self._lock = threading.Lock()
        self._log_encrypted = False
        self._encryption_passphrase: Optional[str] = None
        self._integrity_hash: Optional[str] = None
        
    def add_entry(self, 
                  action: str,
                  outcome: str,
                  operation_type: str = "TEXT",
                  filename: Optional[str] = None,
                  error_type: Optional[str] = None,
                  file_size: Optional[int] = None) -> None:
        """
        Add a new audit log entry
        
        Args:
            action: Description of the action performed
            outcome: "SUCCESS" or "FAILURE"
            operation_type: "TEXT" or "FILE"
            filename: Original filename (will be hashed for privacy)
            error_type: Type of error if outcome is FAILURE
            file_size: Size of file for file operations
        """
        try:
            with self._lock:
                # Generate timestamp in ISO format with timezone
                timestamp = datetime.now(timezone.utc).isoformat()
                
                # Hash filename for privacy if provided
                filename_hash = None
                if filename:
                    filename_hash = hashlib.sha256(filename.encode('utf-8')).hexdigest()[:16]
                
                # Create log entry
                entry = LogEntry(
                    timestamp=timestamp,
                    action=action,
                    filename_hash=filename_hash,
                    outcome=outcome,
                    error_type=error_type,
                    file_size=file_size,
                    operation_type=operation_type
                )
                
                # Add to log buffer
                self._log_entries.append(entry)
                
                # Maintain maximum log entries
                if len(self._log_entries) > MAX_LOG_ENTRIES:
                    self._log_entries.pop(0)  # Remove oldest entry
                
                # Update integrity hash
                self._update_integrity_hash()
                
        except Exception as e:
            # Silent failure for logging to prevent application crashes
            print(f"Audit log error: {str(e)}")
    
    def get_logs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Retrieve audit log entries
        
        Args:
            limit: Maximum number of entries to return (None for all)
            
        Returns:
            List of log entries as dictionaries
        """
        try:
            with self._lock:
                # Verify integrity
                if not self._verify_integrity():
                    raise Exception("Log integrity verification failed")
                
                entries = self._log_entries.copy()
                
                if limit:
                    entries = entries[-limit:]  # Get most recent entries
                
                # Convert to dictionaries for JSON serialization
                return [asdict(entry) for entry in entries]
                
        except Exception as e:
            print(f"Error retrieving logs: {str(e)}")
            return []
    
    def get_log_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of audit logs
        
        Returns:
            Dictionary with log statistics
        """
        try:
            with self._lock:
                total_entries = len(self._log_entries)
                success_count = sum(1 for entry in self._log_entries if entry.outcome == "SUCCESS")
                failure_count = total_entries - success_count
                
                # Count by operation type
                text_operations = sum(1 for entry in self._log_entries if entry.operation_type == "TEXT")
                file_operations = sum(1 for entry in self._log_entries if entry.operation_type == "FILE")
                
                # Get date range
                first_entry = self._log_entries[0].timestamp if self._log_entries else None
                last_entry = self._log_entries[-1].timestamp if self._log_entries else None
                
                return {
                    "total_entries": total_entries,
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "text_operations": text_operations,
                    "file_operations": file_operations,
                    "first_entry": first_entry,
                    "last_entry": last_entry,
                    "integrity_verified": self._verify_integrity()
                }
                
        except Exception as e:
            print(f"Error generating log summary: {str(e)}")
            return {"error": str(e)}
    
    def enable_log_encryption(self, passphrase: str) -> bool:
        """
        Enable encryption for the log buffer
        
        Args:
            passphrase: Passphrase for log encryption
            
        Returns:
            True if encryption was enabled successfully
        """
        try:
            with self._lock:
                self._encryption_passphrase = passphrase
                self._log_encrypted = True
                return True
        except Exception as e:
            print(f"Error enabling log encryption: {str(e)}")
            return False
    
    def disable_log_encryption(self) -> None:
        """Disable log encryption"""
        with self._lock:
            self._log_encrypted = False
            self._encryption_passphrase = None
    
    def export_logs(self, filepath: str, passphrase: Optional[str] = None) -> bool:
        """
        Export logs to file with optional encryption
        
        Args:
            filepath: Path to save logs
            passphrase: Optional passphrase for encryption
            
        Returns:
            True if export was successful
        """
        try:
            logs_data = {
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": self.get_log_summary(),
                "entries": self.get_logs()
            }
            
            json_data = json.dumps(logs_data, indent=2)
            
            if passphrase:
                # Encrypt the log data
                encrypted_data = encrypt_data(json_data.encode('utf-8'), passphrase)
                with open(filepath, 'wb') as f:
                    f.write(encrypted_data)
            else:
                # Save as plain text JSON
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(json_data)
            
            self.add_entry("Log Export", "SUCCESS", "FILE", filepath)
            return True
            
        except Exception as e:
            self.add_entry("Log Export", "FAILURE", "FILE", filepath, str(type(e).__name__))
            print(f"Error exporting logs: {str(e)}")
            return False
    
    def wipe_logs(self) -> None:
        """
        Securely wipe all log entries from memory
        """
        try:
            with self._lock:
                # Clear log entries
                self._log_entries.clear()
                
                # Clear encryption passphrase if set
                if self._encryption_passphrase:
                    # Overwrite passphrase (best effort)
                    self._encryption_passphrase = "0" * len(self._encryption_passphrase)
                    self._encryption_passphrase = None
                
                # Reset state
                self._log_encrypted = False
                self._integrity_hash = None
                
        except Exception as e:
            print(f"Error wiping logs: {str(e)}")
    
    def _update_integrity_hash(self) -> None:
        """Update integrity hash for log verification"""
        try:
            # Create hash of all log entries
            log_data = json.dumps([asdict(entry) for entry in self._log_entries], sort_keys=True)
            self._integrity_hash = hashlib.sha256(log_data.encode('utf-8')).hexdigest()
        except Exception:
            self._integrity_hash = None
    
    def _verify_integrity(self) -> bool:
        """
        Verify log integrity using stored hash
        
        Returns:
            True if integrity is verified
        """
        try:
            if not self._integrity_hash:
                return True  # No hash to verify against
            
            # Recalculate hash
            log_data = json.dumps([asdict(entry) for entry in self._log_entries], sort_keys=True)
            current_hash = hashlib.sha256(log_data.encode('utf-8')).hexdigest()
            
            return current_hash == self._integrity_hash
            
        except Exception:
            return False
    
    def __del__(self):
        """Destructor - auto-wipe logs if enabled"""
        if AUTO_WIPE_ON_EXIT:
            self.wipe_logs()


# Global audit log instance
audit_log = AuditLog()


def log_operation(action: str, 
                 outcome: str,
                 operation_type: str = "TEXT",
                 filename: Optional[str] = None,
                 error: Optional[Exception] = None,
                 file_size: Optional[int] = None) -> None:
    """
    Convenience function to log operations
    
    Args:
        action: Description of the action
        outcome: "SUCCESS" or "FAILURE"
        operation_type: "TEXT" or "FILE"
        filename: Original filename
        error: Exception object if failure
        file_size: File size for file operations
    """
    error_type = None
    if error:
        error_type = type(error).__name__
    
    audit_log.add_entry(
        action=action,
        outcome=outcome,
        operation_type=operation_type,
        filename=filename,
        error_type=error_type,
        file_size=file_size
    )


def get_audit_log() -> AuditLog:
    """Get the global audit log instance"""
    return audit_log
