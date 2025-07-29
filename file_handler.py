"""
File handling utilities for EnigmaEcho SecureComm
Manages secure file encryption/decryption with manual save dialogs
Includes image rendering and secure file management
"""

import os
import mimetypes
from typing import Optional, List, Tuple, Any
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QMessageBox, QWidget
from PySide6.QtCore import QObject, Signal
from PIL import Image
import io

from cryptography_utils import (
    encrypt_data, decrypt_data, obfuscate_filename, 
    CryptographyError, secure_wipe_memory
)
from audit_log import log_operation
from config import ENCRYPTED_FILE_EXTENSION


class FileHandlerError(Exception):
    """Custom exception for file handling operations"""
    pass


class FileHandler(QObject):
    """
    Handles all file operations including encryption, decryption, and management
    """
    
    # Signals for UI updates
    operation_completed = Signal(str, bool)  # message, success
    progress_updated = Signal(int)  # progress percentage
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__()
        self.parent_widget = parent
        self._supported_image_formats = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp'}
    
    def encrypt_file(self, filepath: str, passphrase: str, save_location: Optional[str] = None) -> bool:
        """
        Encrypt a single file with manual save dialog
        
        Args:
            filepath: Path to file to encrypt
            passphrase: Encryption passphrase
            save_location: Optional predetermined save location
            
        Returns:
            True if encryption was successful
        """
        try:
            # Validate input file
            if not os.path.exists(filepath):
                raise FileHandlerError(f"File not found: {filepath}")
            
            if not os.path.isfile(filepath):
                raise FileHandlerError(f"Path is not a file: {filepath}")
            
            # Get file info
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # Read file data
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Encrypt file data
            encrypted_data = encrypt_data(file_data, passphrase)
            
            # Determine save location
            if not save_location:
                save_location = self._get_save_location(
                    f"Save Encrypted File",
                    f"{obfuscate_filename(filename)}"
                )
            
            if not save_location:
                log_operation("File Encryption", "FAILURE", "FILE", filename, 
                            Exception("User cancelled save operation"), file_size)
                return False
            
            # Write encrypted file
            with open(save_location, 'wb') as f:
                f.write(encrypted_data)
            
            # Log successful operation
            log_operation("File Encryption", "SUCCESS", "FILE", filename, None, file_size)
            
            # Emit success signal
            self.operation_completed.emit(
                f"File encrypted successfully: {os.path.basename(save_location)}", 
                True
            )
            
            return True
            
        except Exception as e:
            error_msg = f"File encryption failed: {str(e)}"
            log_operation("File Encryption", "FAILURE", "FILE", 
                         filepath if 'filepath' in locals() else None, e,
                         file_size if 'file_size' in locals() else None)
            
            self.operation_completed.emit(error_msg, False)
            self._show_error_dialog("Encryption Error", error_msg)
            return False
        
        finally:
            # Secure memory cleanup
            if 'file_data' in locals():
                secure_wipe_memory(file_data)
            if 'encrypted_data' in locals():
                secure_wipe_memory(encrypted_data)
    
    def decrypt_file(self, filepath: str, passphrase: str, save_location: Optional[str] = None) -> bool:
        """
        Decrypt a single file with manual save dialog
        
        Args:
            filepath: Path to encrypted file
            passphrase: Decryption passphrase
            save_location: Optional predetermined save location
            
        Returns:
            True if decryption was successful
        """
        try:
            # Validate input file
            if not os.path.exists(filepath):
                raise FileHandlerError(f"File not found: {filepath}")
            
            if not os.path.isfile(filepath):
                raise FileHandlerError(f"Path is not a file: {filepath}")
            
            # Get file info
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # Read encrypted file data
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt file data
            decrypted_data = decrypt_data(encrypted_data, passphrase)
            
            # Determine original filename and save location
            if not save_location:
                # Try to determine original extension from file content
                original_extension = self._detect_file_type(decrypted_data)
                suggested_name = f"decrypted_file{original_extension}"
                
                save_location = self._get_save_location(
                    f"Save Decrypted File",
                    suggested_name
                )
            
            if not save_location:
                log_operation("File Decryption", "FAILURE", "FILE", filename,
                            Exception("User cancelled save operation"), file_size)
                return False
            
            # Write decrypted file
            with open(save_location, 'wb') as f:
                f.write(decrypted_data)
            
            # Check if it's an image and try to render it
            if self._is_image_file(save_location):
                self._try_render_image(save_location)
            
            # Log successful operation
            log_operation("File Decryption", "SUCCESS", "FILE", filename, None, file_size)
            
            # Emit success signal
            self.operation_completed.emit(
                f"File decrypted successfully: {os.path.basename(save_location)}", 
                True
            )
            
            return True
            
        except CryptographyError as e:
            error_msg = f"File decryption failed: {str(e)}"
            log_operation("File Decryption", "FAILURE", "FILE",
                         filepath if 'filepath' in locals() else None, e,
                         file_size if 'file_size' in locals() else None)
            
            self.operation_completed.emit(error_msg, False)
            self._show_error_dialog("Decryption Error", error_msg)
            return False
            
        except Exception as e:
            error_msg = f"File decryption failed: {str(e)}"
            log_operation("File Decryption", "FAILURE", "FILE",
                         filepath if 'filepath' in locals() else None, e,
                         file_size if 'file_size' in locals() else None)
            
            self.operation_completed.emit(error_msg, False)
            self._show_error_dialog("Decryption Error", error_msg)
            return False
        
        finally:
            # Secure memory cleanup
            if 'encrypted_data' in locals():
                secure_wipe_memory(encrypted_data)
            if 'decrypted_data' in locals():
                secure_wipe_memory(decrypted_data)
    
    def encrypt_multiple_files(self, filepaths: List[str], passphrase: str) -> Tuple[int, int]:
        """
        Encrypt multiple files with individual save dialogs
        
        Args:
            filepaths: List of file paths to encrypt
            passphrase: Encryption passphrase
            
        Returns:
            Tuple of (successful_count, total_count)
        """
        successful = 0
        total = len(filepaths)
        
        for i, filepath in enumerate(filepaths):
            # Update progress
            progress = int((i / total) * 100)
            self.progress_updated.emit(progress)
            
            # Encrypt individual file
            if self.encrypt_file(filepath, passphrase):
                successful += 1
        
        # Final progress update
        self.progress_updated.emit(100)
        
        # Log batch operation
        log_operation(
            f"Batch File Encryption ({successful}/{total})",
            "SUCCESS" if successful == total else "PARTIAL",
            "FILE"
        )
        
        return successful, total
    
    def decrypt_multiple_files(self, filepaths: List[str], passphrase: str) -> Tuple[int, int]:
        """
        Decrypt multiple files with individual save dialogs
        
        Args:
            filepaths: List of encrypted file paths to decrypt
            passphrase: Decryption passphrase
            
        Returns:
            Tuple of (successful_count, total_count)
        """
        successful = 0
        total = len(filepaths)
        
        for i, filepath in enumerate(filepaths):
            # Update progress
            progress = int((i / total) * 100)
            self.progress_updated.emit(progress)
            
            # Decrypt individual file
            if self.decrypt_file(filepath, passphrase):
                successful += 1
        
        # Final progress update
        self.progress_updated.emit(100)
        
        # Log batch operation
        log_operation(
            f"Batch File Decryption ({successful}/{total})",
            "SUCCESS" if successful == total else "PARTIAL",
            "FILE"
        )
        
        return successful, total
    
    def _get_save_location(self, title: str, suggested_name: str) -> Optional[str]:
        """
        Show manual file save dialog
        
        Args:
            title: Dialog title
            suggested_name: Suggested filename
            
        Returns:
            Selected file path or None if cancelled
        """
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self.parent_widget,
                title,
                suggested_name,
                "All Files (*)"
            )
            return file_path if file_path else None
            
        except Exception as e:
            self._show_error_dialog("File Dialog Error", f"Failed to open save dialog: {str(e)}")
            return None
    
    def _detect_file_type(self, data: bytes) -> str:
        """
        Detect file type from binary data
        
        Args:
            data: File binary data
            
        Returns:
            File extension based on detected type
        """
        try:
            # Check common file signatures
            if data.startswith(b'\xFF\xD8\xFF'):
                return '.jpg'
            elif data.startswith(b'\x89PNG\r\n\x1a\n'):
                return '.png'
            elif data.startswith(b'GIF8'):
                return '.gif'
            elif data.startswith(b'BM'):
                return '.bmp'
            elif data.startswith(b'RIFF') and b'WEBP' in data[:12]:
                return '.webp'
            elif data.startswith(b'%PDF'):
                return '.pdf'
            elif data.startswith(b'PK'):
                return '.zip'  # Could be zip, docx, xlsx, etc.
            elif data.startswith(b'\x00\x00\x00\x20ftypmp4'):
                return '.mp4'
            else:
                return '.bin'  # Unknown binary file
                
        except Exception:
            return '.bin'
    
    def _is_image_file(self, filepath: str) -> bool:
        """
        Check if file is an image based on extension
        
        Args:
            filepath: Path to file
            
        Returns:
            True if file appears to be an image
        """
        try:
            extension = Path(filepath).suffix.lower()
            return extension in self._supported_image_formats
        except Exception:
            return False
    
    def _try_render_image(self, filepath: str) -> bool:
        """
        Attempt to render/validate an image file
        
        Args:
            filepath: Path to image file
            
        Returns:
            True if image was successfully validated
        """
        try:
            with Image.open(filepath) as img:
                # Verify image can be loaded
                img.verify()
                
            log_operation("Image Validation", "SUCCESS", "FILE", 
                         os.path.basename(filepath))
            return True
            
        except Exception as e:
            log_operation("Image Validation", "FAILURE", "FILE",
                         os.path.basename(filepath), e)
            return False
    
    def _show_error_dialog(self, title: str, message: str) -> None:
        """
        Show error dialog to user
        
        Args:
            title: Dialog title
            message: Error message
        """
        try:
            if self.parent_widget:
                msg_box = QMessageBox(self.parent_widget)
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle(title)
                msg_box.setText(message)
                msg_box.exec()
        except Exception:
            # Fallback to console output
            print(f"{title}: {message}")
    
    def get_file_info(self, filepath: str) -> Optional[dict]:
        """
        Get information about a file
        
        Args:
            filepath: Path to file
            
        Returns:
            Dictionary with file information or None if error
        """
        try:
            if not os.path.exists(filepath):
                return None
            
            stat = os.stat(filepath)
            mime_type, _ = mimetypes.guess_type(filepath)
            
            return {
                'name': os.path.basename(filepath),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'mime_type': mime_type,
                'is_encrypted': filepath.endswith(ENCRYPTED_FILE_EXTENSION)
            }
            
        except Exception:
            return None
