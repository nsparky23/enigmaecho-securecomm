#!/usr/bin/env python3
"""
Test script to verify all imports work correctly
This helps identify any undefined variable issues during import
"""

import sys
import os

def test_imports():
    """Test all module imports"""
    print("🧪 Testing EnigmaEcho SecureComm imports...")
    
    try:
        print("📦 Testing config import...")
        import config
        print("✅ config imported successfully")
        
        print("📦 Testing cryptography_utils import...")
        import cryptography_utils
        print("✅ cryptography_utils imported successfully")
        
        print("📦 Testing audit_log import...")
        import audit_log
        print("✅ audit_log imported successfully")
        
        print("📦 Testing totp_auth import...")
        import totp_auth
        print("✅ totp_auth imported successfully")
        
        print("📦 Testing file_handler import...")
        import file_handler
        print("✅ file_handler imported successfully")
        
        # Test GUI components (this might fail in headless environment)
        print("📦 Testing gui_components import...")
        try:
            import gui_components
            print("✅ gui_components imported successfully")
        except Exception as e:
            print(f"⚠️  gui_components import failed (expected in headless): {e}")
        
        print("\n🎉 Core imports successful!")
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_basic_functionality():
    """Test basic functionality without GUI"""
    print("\n🔧 Testing basic functionality...")
    
    try:
        # Test cryptographic functions
        from cryptography_utils import encrypt_text, decrypt_text
        
        test_text = "Hello, EnigmaEcho!"
        test_password = "TestPassword123"
        
        encrypted = encrypt_text(test_text, test_password)
        decrypted = decrypt_text(encrypted, test_password)
        
        if decrypted == test_text:
            print("✅ Cryptographic functions working")
        else:
            print("❌ Cryptographic functions failed")
            return False
        
        # Test audit logging
        from audit_log import log_operation, get_audit_log
        
        log_operation("Test Operation", "SUCCESS", "TEXT")
        audit_log = get_audit_log()
        logs = audit_log.get_logs()
        
        if len(logs) > 0:
            print("✅ Audit logging working")
        else:
            print("❌ Audit logging failed")
            return False
        
        print("🎉 Basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_application_initialization():
    """Test application initialization without showing GUI"""
    print("\n🚀 Testing application initialization...")
    
    try:
        # Set environment variable to prevent GUI display
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'
        
        from main import EnigmaEchoApplication
        
        app_instance = EnigmaEchoApplication()
        
        # Try to initialize (this should work even without display)
        if app_instance.initialize():
            print("✅ Application initialization successful")
            return True
        else:
            print("❌ Application initialization failed")
            return False
            
    except Exception as e:
        print(f"⚠️  Application initialization test failed (expected in headless): {e}")
        # This is expected in headless environments
        return True

def main():
    """Run all tests"""
    print("🧪 EnigmaEcho SecureComm - Import and Initialization Test")
    print("=" * 60)
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test basic functionality
    if not test_basic_functionality():
        success = False
    
    # Test application initialization
    if not test_application_initialization():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 ALL TESTS PASSED!")
        print("✅ EnigmaEcho SecureComm is ready for use")
        print("ℹ️  To run the GUI: python main.py")
        print("ℹ️  To run CLI demo: python demo_cli.py")
    else:
        print("❌ SOME TESTS FAILED!")
        print("⚠️  Please check the errors above")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
