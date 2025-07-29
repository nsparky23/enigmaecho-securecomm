#!/usr/bin/env python3
"""
Command-line demo of EnigmaEcho SecureComm core functionality
Demonstrates encryption, TOTP authentication, and audit logging without GUI
"""

import os
import sys
import getpass
from pathlib import Path

from cryptography_utils import encrypt_text, decrypt_text, CryptographyError
from totp_auth import get_totp_authenticator, TOTPError
from audit_log import log_operation, get_audit_log


def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    EnigmaEcho SecureComm                     ║
║                  Command-Line Demo Mode                     ║
║                        Version 1.0.0                        ║
╠══════════════════════════════════════════════════════════════╣
║  • AES-256-GCM Encryption with PBKDF2 Key Derivation       ║
║  • HMAC-SHA256 Authentication                               ║
║  • TOTP Two-Factor Authentication                           ║
║  • NIST SP 800-63B & OWASP Compliant                       ║
║  • Local-Only Processing (No Cloud)                        ║
║  • Secure Audit Logging                                    ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def demo_text_encryption():
    """Demonstrate text encryption and decryption"""
    print("\n🔐 TEXT ENCRYPTION DEMO")
    print("=" * 50)
    
    # Get text to encrypt
    text_to_encrypt = input("Enter text to encrypt: ").strip()
    if not text_to_encrypt:
        print("❌ No text entered, skipping encryption demo.")
        return
    
    # Get password
    password = getpass.getpass("Enter encryption password: ")
    if not password:
        print("❌ No password entered, skipping encryption demo.")
        return
    
    try:
        # Encrypt text
        print("\n🔒 Encrypting text...")
        encrypted_text = encrypt_text(text_to_encrypt, password)
        print(f"✅ Encryption successful!")
        print(f"📝 Encrypted text (Base64): {encrypted_text[:50]}...")
        
        # Log the operation
        log_operation("Text Encryption", "SUCCESS", "TEXT")
        
        # Decrypt text
        print("\n🔓 Decrypting text...")
        decrypted_text = decrypt_text(encrypted_text, password)
        print(f"✅ Decryption successful!")
        print(f"📝 Decrypted text: {decrypted_text}")
        
        # Verify integrity
        if decrypted_text == text_to_encrypt:
            print("✅ Integrity verified - original and decrypted text match!")
            log_operation("Text Decryption", "SUCCESS", "TEXT")
        else:
            print("❌ Integrity check failed!")
            log_operation("Text Decryption", "FAILURE", "TEXT")
        
    except CryptographyError as e:
        print(f"❌ Encryption/Decryption failed: {e}")
        log_operation("Text Encryption", "FAILURE", "TEXT", error=e)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        log_operation("Text Encryption", "FAILURE", "TEXT", error=e)


def demo_totp_setup():
    """Demonstrate TOTP setup and verification"""
    print("\n🔑 TOTP AUTHENTICATION DEMO")
    print("=" * 50)
    
    totp_auth = get_totp_authenticator()
    
    # Check if TOTP is already setup
    if totp_auth.is_setup_complete():
        print("ℹ️  TOTP is already configured.")
        choice = input("Do you want to reset and reconfigure? (y/N): ").strip().lower()
        if choice == 'y':
            totp_auth.reset_totp()
            print("✅ TOTP configuration reset.")
        else:
            return demo_totp_login()
    
    # Setup TOTP
    print("\n🔧 Setting up TOTP authentication...")
    master_password = getpass.getpass("Enter master password for TOTP: ")
    if not master_password:
        print("❌ No master password entered, skipping TOTP demo.")
        return
    
    try:
        # Generate TOTP setup
        secret_key, qr_code_bytes = totp_auth.setup_totp(master_password)
        print(f"✅ TOTP setup successful!")
        print(f"📱 Secret key: {secret_key}")
        print(f"🖼️  QR code generated ({len(qr_code_bytes)} bytes)")
        
        # Save QR code to file for user
        qr_file = "totp_qr_code.png"
        with open(qr_file, 'wb') as f:
            f.write(qr_code_bytes)
        print(f"💾 QR code saved to: {qr_file}")
        print("📱 Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)")
        
        # Get backup codes
        backup_codes = totp_auth.get_backup_codes(master_password)
        print(f"\n🔑 Backup codes generated ({len(backup_codes)} codes):")
        for i, code in enumerate(backup_codes, 1):
            print(f"   {i:2d}. {code}")
        print("⚠️  Save these backup codes securely!")
        
        # Verify setup
        input("\nPress Enter after setting up your authenticator app...")
        return demo_totp_verification(master_password)
        
    except TOTPError as e:
        print(f"❌ TOTP setup failed: {e}")
        log_operation("TOTP Setup", "FAILURE", "TEXT", error=e)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        log_operation("TOTP Setup", "FAILURE", "TEXT", error=e)


def demo_totp_login():
    """Demonstrate TOTP login for existing setup"""
    print("\n🔐 TOTP LOGIN DEMO")
    print("=" * 30)
    
    totp_auth = get_totp_authenticator()
    
    # Get master password
    master_password = getpass.getpass("Enter master password: ")
    if not master_password:
        print("❌ No master password entered.")
        return
    
    return demo_totp_verification(master_password)


def demo_totp_verification(master_password):
    """Demonstrate TOTP token verification"""
    totp_auth = get_totp_authenticator()
    
    try:
        # Show time remaining
        time_remaining = totp_auth.get_time_remaining()
        print(f"⏰ Time remaining for current token: {time_remaining}s")
        
        # Get TOTP token from user
        totp_token = input("Enter 6-digit TOTP code from your authenticator app: ").strip()
        
        if len(totp_token) != 6 or not totp_token.isdigit():
            print("❌ Invalid TOTP code format. Must be 6 digits.")
            return
        
        # Verify token
        if totp_auth.verify_totp(totp_token, master_password):
            print("✅ TOTP verification successful!")
            print("🎉 You are now authenticated!")
            log_operation("TOTP Verification", "SUCCESS", "TEXT")
            return True
        else:
            print("❌ TOTP verification failed. Invalid code or expired token.")
            log_operation("TOTP Verification", "FAILURE", "TEXT")
            
            # Offer backup code option
            choice = input("Do you want to try a backup code? (y/N): ").strip().lower()
            if choice == 'y':
                return demo_backup_code_verification(master_password)
            
    except TOTPError as e:
        print(f"❌ TOTP verification error: {e}")
        log_operation("TOTP Verification", "FAILURE", "TEXT", error=e)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        log_operation("TOTP Verification", "FAILURE", "TEXT", error=e)
    
    return False


def demo_backup_code_verification(master_password):
    """Demonstrate backup code verification"""
    totp_auth = get_totp_authenticator()
    
    try:
        # Show remaining backup codes count
        backup_codes = totp_auth.get_backup_codes(master_password)
        print(f"ℹ️  You have {len(backup_codes)} backup codes remaining.")
        
        # Get backup code from user
        backup_code = input("Enter backup code (format: XXXX-XXXX): ").strip().upper()
        
        # Verify backup code
        if totp_auth.verify_backup_code(backup_code, master_password):
            print("✅ Backup code verification successful!")
            print("🎉 You are now authenticated!")
            
            # Show remaining codes
            remaining_codes = totp_auth.get_backup_codes(master_password)
            print(f"ℹ️  You have {len(remaining_codes)} backup codes remaining.")
            
            log_operation("Backup Code Verification", "SUCCESS", "TEXT")
            return True
        else:
            print("❌ Backup code verification failed. Invalid or already used code.")
            log_operation("Backup Code Verification", "FAILURE", "TEXT")
            
    except TOTPError as e:
        print(f"❌ Backup code verification error: {e}")
        log_operation("Backup Code Verification", "FAILURE", "TEXT", error=e)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        log_operation("Backup Code Verification", "FAILURE", "TEXT", error=e)
    
    return False


def demo_audit_log():
    """Demonstrate audit log functionality"""
    print("\n📝 AUDIT LOG DEMO")
    print("=" * 50)
    
    try:
        audit_log = get_audit_log()
        
        # Get log summary
        summary = audit_log.get_log_summary()
        print("📊 Audit Log Summary:")
        print(f"   Total entries: {summary.get('total_entries', 0)}")
        print(f"   Successful operations: {summary.get('success_count', 0)}")
        print(f"   Failed operations: {summary.get('failure_count', 0)}")
        print(f"   Text operations: {summary.get('text_operations', 0)}")
        print(f"   File operations: {summary.get('file_operations', 0)}")
        
        if summary.get('first_entry'):
            print(f"   First entry: {summary['first_entry']}")
        if summary.get('last_entry'):
            print(f"   Last entry: {summary['last_entry']}")
        
        # Show recent log entries
        logs = audit_log.get_logs(limit=10)  # Get last 10 entries
        
        if logs:
            print(f"\n📋 Recent Log Entries (last {len(logs)}):")
            print("-" * 80)
            print(f"{'Timestamp':<20} {'Action':<20} {'Type':<6} {'Outcome':<8} {'Error':<15}")
            print("-" * 80)
            
            for log_entry in logs[-5:]:  # Show last 5 for brevity
                timestamp = log_entry.get('timestamp', '')[:19]  # Truncate timestamp
                action = log_entry.get('action', '')[:19]
                op_type = log_entry.get('operation_type', '')
                outcome = log_entry.get('outcome', '')
                error = log_entry.get('error_type', '') or 'None'
                
                print(f"{timestamp:<20} {action:<20} {op_type:<6} {outcome:<8} {error:<15}")
        else:
            print("ℹ️  No log entries found.")
        
        # Offer to export logs
        choice = input("\nDo you want to export logs to file? (y/N): ").strip().lower()
        if choice == 'y':
            export_file = input("Enter export filename (default: audit_logs.json): ").strip()
            if not export_file:
                export_file = "audit_logs.json"
            
            if audit_log.export_logs(export_file):
                print(f"✅ Logs exported to: {export_file}")
                log_operation("Log Export", "SUCCESS", "FILE", export_file)
            else:
                print("❌ Log export failed.")
                log_operation("Log Export", "FAILURE", "FILE", export_file)
        
    except Exception as e:
        print(f"❌ Audit log demo failed: {e}")
        log_operation("Audit Log Demo", "FAILURE", "TEXT", error=e)


def main_menu():
    """Main demo menu"""
    while True:
        print("\n" + "=" * 60)
        print("🎯 ENIGMAECHO SECURECOMM - DEMO MENU")
        print("=" * 60)
        print("1. 🔐 Text Encryption/Decryption Demo")
        print("2. 🔑 TOTP Authentication Setup")
        print("3. 🔐 TOTP Authentication Login")
        print("4. 📝 Audit Log Viewer")
        print("5. 🧪 Run Full Test Suite")
        print("6. ❌ Exit")
        print("=" * 60)
        
        choice = input("Select an option (1-6): ").strip()
        
        if choice == '1':
            demo_text_encryption()
        elif choice == '2':
            demo_totp_setup()
        elif choice == '3':
            demo_totp_login()
        elif choice == '4':
            demo_audit_log()
        elif choice == '5':
            print("\n🧪 Running full test suite...")
            os.system("python test_application.py")
        elif choice == '6':
            print("\n👋 Thank you for trying EnigmaEcho SecureComm!")
            print("🔒 All audit logs will be securely wiped on exit.")
            
            # Wipe logs on exit
            audit_log = get_audit_log()
            audit_log.wipe_logs()
            print("✅ Audit logs wiped securely.")
            break
        else:
            print("❌ Invalid choice. Please select 1-6.")


def main():
    """Main entry point"""
    try:
        print_banner()
        print("\n🚀 Welcome to the EnigmaEcho SecureComm Command-Line Demo!")
        print("This demo showcases the core functionality without the GUI.")
        print("All operations use the same secure cryptographic functions as the full application.")
        
        # Log demo startup
        log_operation("CLI Demo Startup", "SUCCESS", "TEXT")
        
        main_menu()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user.")
        print("🔒 Performing secure cleanup...")
        
        # Wipe logs on interrupt
        audit_log = get_audit_log()
        audit_log.wipe_logs()
        print("✅ Cleanup complete.")
        
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        log_operation("CLI Demo Error", "FAILURE", "TEXT", error=e)
    
    finally:
        print("\n🔒 EnigmaEcho SecureComm Demo - Session Ended")


if __name__ == "__main__":
    main()
