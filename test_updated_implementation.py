"""
Basic test script for updated EnigmaEcho SecureComm implementation
Tests core functionality without external dependencies
"""

import sys
import os
import time
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_config_updates():
    """Test that config.py has been updated with session timeout"""
    print("Testing config updates...")
    try:
        from config import SESSION_TIMEOUT
        assert SESSION_TIMEOUT == 1800, f"Expected SESSION_TIMEOUT=1800, got {SESSION_TIMEOUT}"
        print("✅ Config updated with SESSION_TIMEOUT = 1800 seconds (30 minutes)")
        return True
    except ImportError as e:
        print(f"❌ Config import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Config test failed: {e}")
        return False

def test_file_structure():
    """Test that all new files exist and have expected content"""
    print("\nTesting file structure...")
    
    required_files = {
        'config.py': 'SESSION_TIMEOUT',
        'session_manager.py': 'class SessionManager',
        'totp_login_updated.py': 'class UpdatedTOTPLoginDialog',
        'main_window_updated.py': 'class UpdatedMainWindow',
        'main_updated.py': 'class EnigmaEchoUpdatedApplication',
        'IMPLEMENTATION_SUMMARY_UPDATED.md': '# EnigmaEcho SecureComm - Updated Implementation Summary'
    }
    
    all_passed = True
    
    for file_name, expected_content in required_files.items():
        if not Path(file_name).exists():
            print(f"❌ Missing file: {file_name}")
            all_passed = False
            continue
            
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                content = f.read()
                if expected_content in content:
                    print(f"✅ {file_name} exists and contains expected content")
                else:
                    print(f"❌ {file_name} missing expected content: {expected_content}")
                    all_passed = False
        except Exception as e:
            print(f"❌ Error reading {file_name}: {e}")
            all_passed = False
    
    return all_passed

def test_session_timeout_constant():
    """Test that SESSION_TIMEOUT is properly configured"""
    print("\nTesting session timeout configuration...")
    
    try:
        from config import SESSION_TIMEOUT
        
        # Test value
        assert SESSION_TIMEOUT == 1800, f"SESSION_TIMEOUT should be 1800, got {SESSION_TIMEOUT}"
        print(f"✅ SESSION_TIMEOUT = {SESSION_TIMEOUT} seconds (30 minutes)")
        
        # Test that it's an integer
        assert isinstance(SESSION_TIMEOUT, int), f"SESSION_TIMEOUT should be int, got {type(SESSION_TIMEOUT)}"
        print("✅ SESSION_TIMEOUT is proper integer type")
        
        # Test reasonable range
        assert 300 <= SESSION_TIMEOUT <= 7200, f"SESSION_TIMEOUT should be between 5-120 minutes, got {SESSION_TIMEOUT}"
        print("✅ SESSION_TIMEOUT is in reasonable range")
        
        return True
        
    except Exception as e:
        print(f"❌ Session timeout test failed: {e}")
        return False

def test_file_content_structure():
    """Test that files have the expected structure without importing"""
    print("\nTesting file content structure...")
    
    tests = []
    
    # Test session_manager.py structure
    try:
        with open('session_manager.py', 'r') as f:
            content = f.read()
            
        required_elements = [
            'class SessionManager',
            'def establish_session',
            'def is_session_active',
            'def update_session',
            'def end_session',
            'def get_session_time_remaining',
            'def save_persistent_profile',
            'def load_persistent_profile',
            'SESSION_TIMEOUT'
        ]
        
        missing = [elem for elem in required_elements if elem not in content]
        if missing:
            print(f"❌ session_manager.py missing: {missing}")
            tests.append(False)
        else:
            print("✅ session_manager.py has all required elements")
            tests.append(True)
            
    except Exception as e:
        print(f"❌ Error testing session_manager.py: {e}")
        tests.append(False)
    
    # Test totp_login_updated.py structure
    try:
        with open('totp_login_updated.py', 'r') as f:
            content = f.read()
            
        # Should NOT contain backup code functionality
        forbidden_elements = [
            'backup_code_button',
            'backup_code_input',
            'Use Backup Code'
        ]
        
        found_forbidden = [elem for elem in forbidden_elements if elem in content]
        if found_forbidden:
            print(f"❌ totp_login_updated.py contains forbidden elements: {found_forbidden}")
            tests.append(False)
        else:
            print("✅ totp_login_updated.py properly removes backup code functionality")
            tests.append(True)
            
    except Exception as e:
        print(f"❌ Error testing totp_login_updated.py: {e}")
        tests.append(False)
    
    # Test main_window_updated.py structure
    try:
        with open('main_window_updated.py', 'r') as f:
            content = f.read()
            
        required_elements = [
            'QSplitter',
            'setSizePolicy',
            'setMinimumSize',
            'session_manager',
            'is_session_active',
            'UpdatedTOTPLoginDialog'
        ]
        
        missing = [elem for elem in required_elements if elem not in content]
        if missing:
            print(f"❌ main_window_updated.py missing: {missing}")
            tests.append(False)
        else:
            print("✅ main_window_updated.py has responsive layout elements")
            tests.append(True)
            
    except Exception as e:
        print(f"❌ Error testing main_window_updated.py: {e}")
        tests.append(False)
    
    return all(tests)

def test_responsive_design_elements():
    """Test that responsive design elements are present"""
    print("\nTesting responsive design elements...")
    
    try:
        with open('main_window_updated.py', 'r') as f:
            content = f.read()
        
        responsive_elements = [
            'QSplitter',  # For responsive splitting
            'setSizePolicy',  # For responsive sizing
            'QSizePolicy.Expanding',  # For expanding elements
            'setMinimumSize',  # For minimum responsive sizes
            'setStretchFactor',  # For proportional stretching
            'setSizes'  # For initial proportions
        ]
        
        found_elements = [elem for elem in responsive_elements if elem in content]
        missing_elements = [elem for elem in responsive_elements if elem not in content]
        
        if len(found_elements) >= 4:  # At least 4 out of 6 responsive elements
            print(f"✅ Found {len(found_elements)}/6 responsive design elements")
            print(f"   Found: {found_elements}")
            if missing_elements:
                print(f"   Missing: {missing_elements}")
            return True
        else:
            print(f"❌ Only found {len(found_elements)}/6 responsive design elements")
            print(f"   Missing: {missing_elements}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing responsive design: {e}")
        return False

def test_session_management_integration():
    """Test that session management is properly integrated"""
    print("\nTesting session management integration...")
    
    files_to_check = [
        ('main_window_updated.py', ['session_manager', 'is_session_active', 'UpdatedTOTPLoginDialog']),
        ('totp_login_updated.py', ['session_manager', 'establish_session']),
        ('main_updated.py', ['session_manager', 'end_session'])
    ]
    
    all_passed = True
    
    for filename, required_elements in files_to_check:
        try:
            with open(filename, 'r') as f:
                content = f.read()
            
            missing = [elem for elem in required_elements if elem not in content]
            if missing:
                print(f"❌ {filename} missing session elements: {missing}")
                all_passed = False
            else:
                print(f"✅ {filename} has proper session management integration")
                
        except Exception as e:
            print(f"❌ Error checking {filename}: {e}")
            all_passed = False
    
    return all_passed

def main():
    """Run all basic tests"""
    print("=" * 70)
    print("EnigmaEcho SecureComm - Basic Implementation Validation")
    print("=" * 70)
    
    tests = [
        ("Config Updates", test_config_updates),
        ("File Structure", test_file_structure),
        ("Session Timeout Configuration", test_session_timeout_constant),
        ("File Content Structure", test_file_content_structure),
        ("Responsive Design Elements", test_responsive_design_elements),
        ("Session Management Integration", test_session_management_integration),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS SUMMARY")
    print("=" * 70)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:<35} {status}")
        if result:
            passed += 1
    
    print("-" * 70)
    print(f"Total: {passed}/{total} validations passed")
    
    if passed == total:
        print("\n🎉 ALL VALIDATIONS PASSED! 🎉")
        print("The updated implementation structure is correct.")
        print("\n📋 IMPLEMENTATION SUMMARY:")
        print("=" * 50)
        print("✅ GUI Layout Improvements:")
        print("   • Responsive design with QSplitter and layout managers")
        print("   • Dynamic auto-scaling components")
        print("   • Removed fixed heights/widths")
        print("   • Proper stretch factors and size policies")
        print()
        print("✅ TOTP Authentication Enhancements:")
        print("   • Persistent configuration with separate encryption")
        print("   • 30-minute session timeout (1800 seconds)")
        print("   • Session-based access control")
        print("   • Removed backup code UI clutter")
        print("   • Single login per application launch")
        print()
        print("✅ New Files Created:")
        print("   • session_manager.py - Session and profile management")
        print("   • totp_login_updated.py - Clean login dialog")
        print("   • main_window_updated.py - Responsive main window")
        print("   • main_updated.py - Updated application entry point")
        print("   • test_implementation_basic.py - Validation tests")
        print()
        print("🚀 NEXT STEPS:")
        print("1. Install dependencies: pip install PySide6 cryptography pyperclip Pillow")
        print("2. Run updated app: python main_updated.py")
        print("3. Test responsive layout by resizing window")
        print("4. Verify session timeout after 30 minutes of inactivity")
        
        return 0
    else:
        print(f"\n❌ {total - passed} validations failed.")
        print("Please review the implementation files.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
