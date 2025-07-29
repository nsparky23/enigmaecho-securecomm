#!/usr/bin/env python3
"""
Comprehensive test suite for EnigmaEcho SecureComm
Tests cryptographic functions, TOTP authentication, audit logging, and file handling
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Test imports
try:
    from cryptography_utils import (
        encrypt_text, decrypt_text, encrypt_data, decrypt_data,
        obfuscate_filename, CryptographyError
    )
    from audit_log import log_operation, get_audit_log
    from totp_auth import get_totp_authenticator, TOTPError
    from file_handler import FileHandler
    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def test_cryptographic_functions():
    """Test core cryptographic operations"""
    print("\n🔐 Testing Cryptographic Functions...")
    
    # Test text encryption/decryption
    try:
        test_text = "Hello, EnigmaEcho SecureComm! This is a test message with special characters: àáâãäåæçèéêë"
        test_password = "TestPassword123!"
        
        # Encrypt text
        encrypted_text = encrypt_text(test_text, test_password)
        print(f"✅ Text encryption successful (length: {len(encrypted_text)})")
        
        # Decrypt text
        decrypted_text = decrypt_text(encrypted_text, test_password)
        print(f"✅ Text decryption successful")
        
        # Verify integrity
        if decrypted_text == test_text:
            print("✅ Text encryption/decryption integrity verified")
        else:
            print("❌ Text encryption/decryption integrity failed")
            return False
            
        # Test wrong password
        try:
            decrypt_text(encrypted_text, "WrongPassword")
            print("❌ Wrong password should have failed")
            return False
        except CryptographyError:
            print("✅ Wrong password correctly rejected")
            
    except Exception as e:
        print(f"❌ Text encryption/decryption failed: {e}")
        return False
    
    # Test binary data encryption/decryption
    try:
        test_data = b"Binary test data: \x00\x01\x02\x03\xFF\xFE\xFD"
        test_password = "BinaryTestPassword456!"
        
        # Encrypt binary data
        encrypted_data = encrypt_data(test_data, test_password)
        print(f"✅ Binary encryption successful (length: {len(encrypted_data)})")
        
        # Decrypt binary data
        decrypted_data = decrypt_data(encrypted_data, test_password)
        print(f"✅ Binary decryption successful")
        
        # Verify integrity
        if decrypted_data == test_data:
            print("✅ Binary encryption/decryption integrity verified")
        else:
            print("❌ Binary encryption/decryption integrity failed")
            return False
            
    except Exception as e:
        print(f"❌ Binary encryption/decryption failed: {e}")
        return False
    
    # Test filename obfuscation
    try:
        test_filename = "sensitive_document.pdf"
        obfuscated = obfuscate_filename(test_filename)
        print(f"✅ Filename obfuscation: '{test_filename}' -> '{obfuscated}'")
        
        # Verify it's different and has .enc extension
        if obfuscated != test_filename and obfuscated.endswith('.enc'):
            print("✅ Filename obfuscation working correctly")
        else:
            print("❌ Filename obfuscation failed")
            return False
            
    except Exception as e:
        print(f"❌ Filename obfuscation failed: {e}")
        return False
    
    return True


def test_audit_logging():
    """Test audit logging functionality"""
    print("\n📝 Testing Audit Logging...")
    
    try:
        audit_log = get_audit_log()
        
        # Clear existing logs for clean test
        audit_log.wipe_logs()
        
        # Test logging operations
        log_operation("Test Encryption", "SUCCESS", "TEXT")
        log_operation("Test Decryption", "SUCCESS", "FILE", "test.txt")
        log_operation("Test Failure", "FAILURE", "TEXT", error=Exception("Test error"))
        
        # Get logs
        logs = audit_log.get_logs()
        print(f"✅ Logged {len(logs)} operations")
        
        # Verify log content
        if len(logs) >= 3:
            print("✅ All test operations logged")
            
            # Check log structure
            first_log = logs[0]
            required_fields = ['timestamp', 'action', 'outcome', 'operation_type']
            if all(field in first_log for field in required_fields):
                print("✅ Log structure is correct")
            else:
                print("❌ Log structure is missing required fields")
                return False
        else:
            print("❌ Not all operations were logged")
            return False
        
        # Test log summary
        summary = audit_log.get_log_summary()
        if 'total_entries' in summary and summary['total_entries'] >= 3:
            print("✅ Log summary working correctly")
        else:
            print("❌ Log summary failed")
            return False
        
        # Test log export
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            if audit_log.export_logs(temp_path):
                print("✅ Log export successful")
                
                # Verify exported file exists and has content
                if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                    print("✅ Exported log file is valid")
                else:
                    print("❌ Exported log file is invalid")
                    return False
            else:
                print("❌ Log export failed")
                return False
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
        return True
        
    except Exception as e:
        print(f"❌ Audit logging test failed: {e}")
        return False


def test_totp_authentication():
    """Test TOTP authentication functionality"""
    print("\n🔑 Testing TOTP Authentication...")
    
    try:
        totp_auth = get_totp_authenticator()
        test_password = "TOTPTestPassword789!"
        
        # Reset any existing TOTP configuration
        totp_auth.reset_totp()
        
        # Test initial state
        if not totp_auth.is_setup_complete():
            print("✅ Initial TOTP state is correct (not setup)")
        else:
            print("❌ TOTP should not be setup initially")
            return False
        
        # Test TOTP setup
        try:
            secret_key, qr_code_bytes = totp_auth.setup_totp(test_password)
            print(f"✅ TOTP setup successful (secret length: {len(secret_key)})")
            print(f"✅ QR code generated (size: {len(qr_code_bytes)} bytes)")
            
            # Verify setup is complete
            if totp_auth.is_setup_complete():
                print("✅ TOTP setup completion detected")
            else:
                print("❌ TOTP setup completion not detected")
                return False
                
        except Exception as e:
            print(f"❌ TOTP setup failed: {e}")
            return False
        
        # Test token generation and verification
        try:
            # Get current token for testing
            current_token = totp_auth.get_current_token(test_password)
            print(f"✅ Current TOTP token generated: {current_token}")
            
            # Verify the token
            if totp_auth.verify_totp(current_token, test_password):
                print("✅ TOTP token verification successful")
            else:
                print("❌ TOTP token verification failed")
                return False
                
            # Test invalid token
            if not totp_auth.verify_totp("000000", test_password):
                print("✅ Invalid TOTP token correctly rejected")
            else:
                print("❌ Invalid TOTP token should have been rejected")
                return False
                
        except Exception as e:
            print(f"❌ TOTP token testing failed: {e}")
            return False
        
        # Test backup codes
        try:
            backup_codes = totp_auth.get_backup_codes(test_password)
            print(f"✅ Retrieved {len(backup_codes)} backup codes")
            
            if len(backup_codes) > 0:
                # Test backup code verification
                test_backup_code = backup_codes[0]
                if totp_auth.verify_backup_code(test_backup_code, test_password):
                    print("✅ Backup code verification successful")
                    
                    # Verify code is consumed (should fail second time)
                    if not totp_auth.verify_backup_code(test_backup_code, test_password):
                        print("✅ Backup code correctly consumed after use")
                    else:
                        print("❌ Backup code should be consumed after use")
                        return False
                else:
                    print("❌ Backup code verification failed")
                    return False
            else:
                print("❌ No backup codes generated")
                return False
                
        except Exception as e:
            print(f"❌ Backup code testing failed: {e}")
            return False
        
        # Test time remaining function
        try:
            time_remaining = totp_auth.get_time_remaining()
            if 0 <= time_remaining <= 30:
                print(f"✅ Time remaining function working: {time_remaining}s")
            else:
                print(f"❌ Time remaining out of range: {time_remaining}s")
                return False
        except Exception as e:
            print(f"❌ Time remaining test failed: {e}")
            return False
        
        # Clean up - reset TOTP
        totp_auth.reset_totp()
        print("✅ TOTP configuration reset for cleanup")
        
        return True
        
    except Exception as e:
        print(f"❌ TOTP authentication test failed: {e}")
        return False


def test_file_operations():
    """Test file handling operations"""
    print("\n📁 Testing File Operations...")
    
    try:
        # Create temporary directory for testing
        temp_dir = tempfile.mkdtemp()
        print(f"✅ Created temporary directory: {temp_dir}")
        
        try:
            # Create test files
            test_text_file = os.path.join(temp_dir, "test.txt")
            test_binary_file = os.path.join(temp_dir, "test.bin")
            
            # Write test content
            with open(test_text_file, 'w', encoding='utf-8') as f:
                f.write("This is a test text file for EnigmaEcho SecureComm.\nIt contains multiple lines.\nWith special characters: àáâãäåæçèéêë")
            
            with open(test_binary_file, 'wb') as f:
                f.write(b"Binary test data: \x00\x01\x02\x03\xFF\xFE\xFD" * 100)  # Make it larger
            
            print("✅ Test files created")
            
            # Test file info retrieval
            file_handler = FileHandler()
            
            text_info = file_handler.get_file_info(test_text_file)
            binary_info = file_handler.get_file_info(test_binary_file)
            
            if text_info and binary_info:
                print(f"✅ File info retrieved - Text: {text_info['size']} bytes, Binary: {binary_info['size']} bytes")
            else:
                print("❌ File info retrieval failed")
                return False
            
            # Test filename obfuscation
            original_name = "sensitive_document.pdf"
            obfuscated_name = obfuscate_filename(original_name)
            
            if obfuscated_name != original_name and obfuscated_name.endswith('.enc'):
                print(f"✅ Filename obfuscation working: {original_name} -> {obfuscated_name}")
            else:
                print("❌ Filename obfuscation failed")
                return False
            
            print("✅ File operations test completed successfully")
            return True
            
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)
            print("✅ Temporary directory cleaned up")
            
    except Exception as e:
        print(f"❌ File operations test failed: {e}")
        return False


def test_configuration():
    """Test configuration loading and constants"""
    print("\n⚙️ Testing Configuration...")
    
    try:
        from config import (
            COLOR_BG, COLOR_ACCENT, COLOR_TEXT, WINDOW_TITLE,
            PBKDF2_ITERATIONS, AES_MODE, SALT_LENGTH, NONCE_LENGTH
        )
        
        # Verify color constants
        colors = [COLOR_BG, COLOR_ACCENT, COLOR_TEXT]
        if all(isinstance(color, str) and color.startswith('#') for color in colors):
            print("✅ Color constants are valid hex colors")
        else:
            print("❌ Color constants are invalid")
            return False
        
        # Verify cryptographic constants
        if PBKDF2_ITERATIONS >= 480000:
            print(f"✅ PBKDF2 iterations meet NIST requirements: {PBKDF2_ITERATIONS}")
        else:
            print(f"❌ PBKDF2 iterations too low: {PBKDF2_ITERATIONS}")
            return False
        
        if AES_MODE == "AES-256-GCM":
            print("✅ AES mode is correctly configured")
        else:
            print(f"❌ AES mode is incorrect: {AES_MODE}")
            return False
        
        if SALT_LENGTH >= 16 and NONCE_LENGTH >= 12:
            print(f"✅ Salt and nonce lengths are secure: {SALT_LENGTH}, {NONCE_LENGTH}")
        else:
            print(f"❌ Salt or nonce length too short: {SALT_LENGTH}, {NONCE_LENGTH}")
            return False
        
        if WINDOW_TITLE == "EnigmaEcho SecureComm":
            print("✅ Window title is correct")
        else:
            print(f"❌ Window title is incorrect: {WINDOW_TITLE}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False


def run_all_tests():
    """Run all test suites"""
    print("🚀 Starting EnigmaEcho SecureComm Test Suite")
    print("=" * 60)
    
    test_results = []
    
    # Run individual test suites
    test_results.append(("Configuration", test_configuration()))
    test_results.append(("Cryptographic Functions", test_cryptographic_functions()))
    test_results.append(("Audit Logging", test_audit_logging()))
    test_results.append(("TOTP Authentication", test_totp_authentication()))
    test_results.append(("File Operations", test_file_operations()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:<25} {status}")
        if result:
            passed += 1
    
    print("=" * 60)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! EnigmaEcho SecureComm is ready for use.")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review the issues above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
