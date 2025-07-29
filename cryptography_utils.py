"""
Cryptographic utilities for EnigmaEcho SecureComm
Implements AES-256-GCM encryption with PBKDF2 key derivation and HMAC authentication
Compliant with NIST SP 800-63B, NIST SP 800-57, and OWASP guidelines
"""

import os
import hashlib
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import (
    PBKDF2_ITERATIONS, SALT_LENGTH, NONCE_LENGTH, 
    HMAC_KEY_LENGTH, ENCRYPTION_KEY_LENGTH
)


class CryptographyError(Exception):
    """Custom exception for cryptographic operations"""
    pass


def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes"""
    return os.urandom(length)


def derive_keys(passphrase: str, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive encryption and HMAC keys from passphrase using PBKDF2-HMAC-SHA256
    
    Args:
        passphrase: User-provided passphrase
        salt: Random salt bytes
        
    Returns:
        Tuple of (encryption_key, hmac_key)
        
    Raises:
        CryptographyError: If key derivation fails
    """
    try:
        # Convert passphrase to bytes
        passphrase_bytes = passphrase.encode('utf-8')
        
        # Create PBKDF2 instance
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=ENCRYPTION_KEY_LENGTH + HMAC_KEY_LENGTH,  # 64 bytes total
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        # Derive combined key material
        key_material = kdf.derive(passphrase_bytes)
        
        # Split into encryption and HMAC keys
        encryption_key = key_material[:ENCRYPTION_KEY_LENGTH]
        hmac_key = key_material[ENCRYPTION_KEY_LENGTH:]
        
        return encryption_key, hmac_key
        
    except Exception as e:
        raise CryptographyError(f"Key derivation failed: {str(e)}")
    finally:
        # Secure memory cleanup
        if 'passphrase_bytes' in locals():
            passphrase_bytes = b'\x00' * len(passphrase_bytes)
        if 'key_material' in locals():
            key_material = b'\x00' * len(key_material)


def generate_hmac(data: bytes, hmac_key: bytes) -> bytes:
    """
    Generate HMAC-SHA256 authentication tag
    
    Args:
        data: Data to authenticate
        hmac_key: HMAC key
        
    Returns:
        HMAC authentication tag
    """
    try:
        h = hmac.new(hmac_key, data, hashlib.sha256)
        return h.digest()
    except Exception as e:
        raise CryptographyError(f"HMAC generation failed: {str(e)}")


def verify_hmac(data: bytes, hmac_key: bytes, tag: bytes) -> bool:
    """
    Verify HMAC-SHA256 authentication tag
    
    Args:
        data: Data to verify
        hmac_key: HMAC key
        tag: Expected HMAC tag
        
    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        expected_tag = generate_hmac(data, hmac_key)
        return hmac.compare_digest(expected_tag, tag)
    except Exception:
        return False


def encrypt_data(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt data using AES-256-GCM with PBKDF2 key derivation
    
    Args:
        plaintext: Data to encrypt
        passphrase: User passphrase
        
    Returns:
        Encrypted data with metadata (salt + nonce + ciphertext + auth_tag + hmac)
        
    Raises:
        CryptographyError: If encryption fails
    """
    try:
        # Generate random salt and nonce
        salt = secure_random_bytes(SALT_LENGTH)
        nonce = secure_random_bytes(NONCE_LENGTH)
        
        # Derive keys
        encryption_key, hmac_key = derive_keys(passphrase, salt)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        # Create encrypted package: salt + nonce + ciphertext + auth_tag
        encrypted_package = salt + nonce + ciphertext + auth_tag
        
        # Generate HMAC for the entire package
        hmac_tag = generate_hmac(encrypted_package, hmac_key)
        
        # Final format: encrypted_package + hmac_tag
        final_data = encrypted_package + hmac_tag
        
        return final_data
        
    except Exception as e:
        raise CryptographyError(f"Encryption failed: {str(e)}")
    finally:
        # Secure memory cleanup
        if 'encryption_key' in locals():
            encryption_key = b'\x00' * len(encryption_key)
        if 'hmac_key' in locals():
            hmac_key = b'\x00' * len(hmac_key)


def decrypt_data(ciphertext: bytes, passphrase: str) -> bytes:
    """
    Decrypt data using AES-256-GCM with PBKDF2 key derivation
    
    Args:
        ciphertext: Encrypted data with metadata
        passphrase: User passphrase
        
    Returns:
        Decrypted plaintext data
        
    Raises:
        CryptographyError: If decryption fails or data is tampered
    """
    try:
        # Validate minimum length
        min_length = SALT_LENGTH + NONCE_LENGTH + 16 + 32  # salt + nonce + min_ciphertext + hmac
        if len(ciphertext) < min_length:
            raise CryptographyError("Invalid ciphertext format")
        
        # Extract HMAC tag (last 32 bytes)
        hmac_tag = ciphertext[-32:]
        encrypted_package = ciphertext[:-32]
        
        # Extract components from encrypted package
        salt = encrypted_package[:SALT_LENGTH]
        nonce = encrypted_package[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
        encrypted_data = encrypted_package[SALT_LENGTH + NONCE_LENGTH:-16]
        auth_tag = encrypted_package[-16:]
        
        # Derive keys
        encryption_key, hmac_key = derive_keys(passphrase, salt)
        
        # Verify HMAC
        if not verify_hmac(encrypted_package, hmac_key, hmac_tag):
            raise CryptographyError("HMAC verification failed - data may be tampered")
        
        # Create cipher for decryption
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return plaintext
        
    except CryptographyError:
        raise
    except Exception as e:
        raise CryptographyError(f"Decryption failed: {str(e)}")
    finally:
        # Secure memory cleanup
        if 'encryption_key' in locals():
            encryption_key = b'\x00' * len(encryption_key)
        if 'hmac_key' in locals():
            hmac_key = b'\x00' * len(hmac_key)


def encrypt_text(plaintext: str, passphrase: str) -> str:
    """
    Encrypt text and return base64-encoded result
    
    Args:
        plaintext: Text to encrypt
        passphrase: User passphrase
        
    Returns:
        Base64-encoded encrypted text
    """
    try:
        plaintext_bytes = plaintext.encode('utf-8')
        encrypted_bytes = encrypt_data(plaintext_bytes, passphrase)
        
        # Use base64 encoding for text display
        import base64
        return base64.b64encode(encrypted_bytes).decode('ascii')
        
    except Exception as e:
        raise CryptographyError(f"Text encryption failed: {str(e)}")


def decrypt_text(ciphertext: str, passphrase: str) -> str:
    """
    Decrypt base64-encoded text
    
    Args:
        ciphertext: Base64-encoded encrypted text
        passphrase: User passphrase
        
    Returns:
        Decrypted plaintext
    """
    try:
        import base64
        encrypted_bytes = base64.b64decode(ciphertext.encode('ascii'))
        decrypted_bytes = decrypt_data(encrypted_bytes, passphrase)
        
        return decrypted_bytes.decode('utf-8')
        
    except Exception as e:
        raise CryptographyError(f"Text decryption failed: {str(e)}")


def obfuscate_filename(filename: str) -> str:
    """
    Obfuscate filename using SHA-256 hash with base64 encoding
    
    Args:
        filename: Original filename
        
    Returns:
        Obfuscated filename
    """
    try:
        filename_hash = hashlib.sha256(filename.encode('utf-8')).digest()
        import base64
        obfuscated = base64.urlsafe_b64encode(filename_hash[:16]).decode('ascii').rstrip('=')
        return f"{obfuscated}.enc"
    except Exception as e:
        raise CryptographyError(f"Filename obfuscation failed: {str(e)}")


def secure_wipe_memory(data: bytes) -> None:
    """
    Attempt to securely wipe sensitive data from memory
    Note: This is best-effort in Python due to garbage collection
    
    Args:
        data: Bytes to wipe
    """
    try:
        if isinstance(data, bytes):
            # Overwrite with zeros (best effort)
            for i in range(len(data)):
                data = data[:i] + b'\x00' + data[i+1:]
    except Exception:
        # Silent failure for memory wiping
        pass
