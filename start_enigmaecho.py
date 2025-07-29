#!/usr/bin/env python3
"""
Smart startup script for EnigmaEcho SecureComm
Automatically chooses GUI or CLI mode based on environment
"""

import os
import sys
import subprocess

def check_gui_available():
    """Check if GUI is available"""
    # Check for DISPLAY on Linux
    if sys.platform.startswith('linux'):
        return bool(os.environ.get('DISPLAY'))
    
    # On Windows and macOS, assume GUI is available
    return sys.platform in ['win32', 'darwin']

def main():
    """Smart startup"""
    print("🚀 EnigmaEcho SecureComm - Smart Startup")
    print("=" * 50)
    
    if check_gui_available():
        print("🖥️  GUI environment detected - starting full application...")
        try:
            subprocess.run([sys.executable, 'main.py'])
        except Exception as e:
            print(f"❌ GUI startup failed: {e}")
            print("🔄 Falling back to CLI demo...")
            subprocess.run([sys.executable, 'demo_cli.py'])
    else:
        print("💻 Headless environment detected - starting CLI demo...")
        subprocess.run([sys.executable, 'demo_cli.py'])

if __name__ == "__main__":
    main()
