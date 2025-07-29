#!/usr/bin/env python3
"""
Test script for TOTP authentication in EnigmaEcho SecureComm
This tests the TOTP functionality without GUI dependencies
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_totp_functionality():
    """Test the TOTP authentication functionality"""
    print("Testing EnigmaEcho SecureComm TOTP Authentication")
    print("=" * 60)
    
    try:
        from totp_auth import get_totp_authenticator, TOTPError
        from audit_log import get_audit_log
        
        # Test 1: TOTP Setup
        print("\n1. Testing TOTP Setup...")
        totp_auth = get_totp_authenticator()
        
        # Reset any existing configuration
        totp_auth.reset_totp()
        
        test_master_password = "TestMasterPassword123!"
        
        # Setup TOTP
        secret_key, qr_code_bytes = totp_auth.setup_totp(test_master_password)
        print(f"   Secret key generated: {secret_key[:10]}...")
        print(f"   QR code size: {len(qr_code_bytes)} bytes")
        print("   ✅ TOTP setup: PASSED")
        
        # Test 2: TOTP Verification
        print("\n2. Testing TOTP Verification...")
        
        # Get current token for testing
        current_token = totp_auth.get_current_token(test_master_password)
        print(f"   Current TOTP token: {current_token}")
        
        # Verify the token
        is_valid = totp_auth.verify_totp(current_token, test_master_password)
        if is_valid:
            print("   ✅ TOTP verification: PASSED")
        else:
            print("   ❌ TOTP verification: FAILED")
            return False
        
        # Test 3: Invalid Token
        print("\n3. Testing Invalid Token (should fail)...")
        try:
            invalid_result = totp_auth.verify_totp("000000", test_master_password)
            if not invalid_result:
                print("   ✅ Invalid token correctly rejected: PASSED")
            else:
                print("   ❌ Invalid token test: FAILED (should have been rejected)")
                return False
        except Exception as e:
            print(f"   ✅ Invalid token correctly rejected: {type(e).__name__}")
        
        # Test 4: Backup Codes
        print("\n4. Testing Backup Codes...")
        backup_codes = totp_auth.get_backup_codes(test_master_password)
        print(f"   Generated {len(backup_codes)} backup codes")
        
        if len(backup_codes) > 0:
            # Test using a backup code
            test_backup_code = backup_codes[0]
            print(f"   Testing backup code: {test_backup_code}")
            
            backup_valid = totp_auth.verify_backup_code(test_backup_code, test_master_password)
            if backup_valid:
                print("   ✅ Backup code verification: PASSED")
                
                # Verify the code is consumed (should fail on second use)
                backup_reuse = totp_auth.verify_backup_code(test_backup_code, test_master_password)
                if not backup_reuse:
                    print("   ✅ Backup code one-time use: PASSED")
                else:
                    print("   ❌ Backup code one-time use: FAILED")
                    return False
            else:
                print("   ❌ Backup code verification: FAILED")
                return False
        else:
            print("   ❌ Backup codes generation: FAILED")
            return False
        
        # Test 5: Backup Code Regeneration
        print("\n5. Testing Backup Code Regeneration...")
        original_count = len(totp_auth.get_backup_codes(test_master_password))
        new_codes = totp_auth.regenerate_backup_codes(test_master_password)
        
        if len(new_codes) == 10:  # Default count
            print(f"   ✅ Backup code regeneration: PASSED ({len(new_codes)} codes)")
        else:
            print(f"   ❌ Backup code regeneration: FAILED (expected 10, got {len(new_codes)})")
            return False
        
        # Test 6: Wrong Master Password
        print("\n6. Testing Wrong Master Password (should fail)...")
        try:
            wrong_token = totp_auth.verify_totp(current_token, "WrongPassword")
            print("   ❌ Wrong master password test: FAILED (should have thrown error)")
            return False
        except TOTPError as e:
            print(f"   ✅ Wrong master password correctly rejected: {type(e).__name__}")
        except Exception as e:
            print(f"   ✅ Wrong master password correctly rejected: {type(e).__name__}")
        
        # Test 7: Time Remaining
        print("\n7. Testing Time Remaining...")
        time_remaining = totp_auth.get_time_remaining()
        if 0 <= time_remaining <= 30:
            print(f"   ✅ Time remaining: {time_remaining}s (valid range)")
        else:
            print(f"   ❌ Time remaining: {time_remaining}s (invalid range)")
            return False
        
        # Test 8: Configuration Persistence
        print("\n8. Testing Configuration Persistence...")
        
        # Create new authenticator instance (simulates app restart)
        from totp_auth import TOTPAuthenticator
        new_auth = TOTPAuthenticator()
        
        if new_auth.is_setup_complete():
            print("   ✅ Configuration persistence: PASSED")
            
            # Verify it can still authenticate
            new_token = new_auth.get_current_token(test_master_password)
            if new_auth.verify_totp(new_token, test_master_password):
                print("   ✅ Persistent authentication: PASSED")
            else:
                print("   ❌ Persistent authentication: FAILED")
                return False
        else:
            print("   ❌ Configuration persistence: FAILED")
            return False
        
        # Test 9: Reset TOTP
        print("\n9. Testing TOTP Reset...")
        if totp_auth.reset_totp():
            print("   ✅ TOTP reset: PASSED")
            
            # Verify setup is no longer complete
            if not totp_auth.is_setup_complete():
                print("   ✅ Reset verification: PASSED")
            else:
                print("   ❌ Reset verification: FAILED")
                return False
        else:
            print("   ❌ TOTP reset: FAILED")
            return False
        
        print("\n" + "=" * 60)
        print("🎉 ALL TOTP TESTS PASSED!")
        print("The TOTP authentication system is working correctly.")
        print("=" * 60)
        
        return True
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Please ensure all dependencies are installed: pip install -r requirements.txt")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integration():
    """Test integration with cryptographic functions"""
    print("\n" + "=" * 60)
    print("Testing TOTP Integration with Cryptographic Functions")
    print("=" * 60)
    
    try:
        from totp_auth import get_totp_authenticator
        from cryptography_utils import encrypt_text, decrypt_text
        
        # Setup TOTP
        totp_auth = get_totp_authenticator()
        totp_auth.reset_totp()
        
        master_password = "IntegrationTestPassword123!"
        secret_key, qr_code_bytes = totp_auth.setup_totp(master_password)
        
        print("1. TOTP setup completed for integration test")
        
        # Test text encryption with master password
        test_text = "This is a test message encrypted with TOTP master password!"
        
        encrypted_text = encrypt_text(test_text, master_password)
        print(f"2. Text encrypted: {encrypted_text[:50]}...")
        
        decrypted_text = decrypt_text(encrypted_text, master_password)
        print(f"3. Text decrypted: {decrypted_text}")
        
        if test_text == decrypted_text:
            print("   ✅ TOTP-Crypto integration: PASSED")
        else:
            print("   ❌ TOTP-Crypto integration: FAILED")
            return False
        
        # Verify TOTP still works after crypto operations
        current_token = totp_auth.get_current_token(master_password)
        if totp_auth.verify_totp(current_token, master_password):
            print("   ✅ TOTP after crypto operations: PASSED")
        else:
            print("   ❌ TOTP after crypto operations: FAILED")
            return False
        
        print("🎉 INTEGRATION TESTS PASSED!")
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("EnigmaEcho SecureComm - TOTP Authentication Test")
    print("This test verifies the TOTP functionality without GUI dependencies")
    print()
    
    # Test TOTP functionality
    totp_success = test_totp_functionality()
    
    # Test integration
    integration_success = test_integration()
    
    if totp_success and integration_success:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("EnigmaEcho SecureComm with TOTP is ready for use.")
        print("\nTo run the full GUI application:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run: python main.py")
        print("3. Use Security menu to setup TOTP authentication")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        print("Please check the error messages above.")
        sys.exit(1)
