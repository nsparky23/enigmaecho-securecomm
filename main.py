"""
EnigmaEcho SecureComm - Main Application Entry Point
A secure desktop encryption tool with modern GUI and strong cryptographic practices
Compliant with NIST SP 800-63B, NIST SP 800-57, and OWASP guidelines
"""

import sys
import os
import traceback
import warnings
from pathlib import Path

# Add current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QIcon
    
    from gui_components import MainWindow, create_application
    from audit_log import log_operation, get_audit_log
    from config import WINDOW_TITLE, AUTO_WIPE_ON_EXIT
    
except ImportError as e:
    print(f"Import Error: {e}")
    print("Please ensure all required dependencies are installed:")
    print("pip install PySide6 cryptography pyperclip Pillow")
    sys.exit(1)


class EnigmaEchoApplication:
    """Main application class for EnigmaEcho SecureComm"""
    
    def __init__(self):
        self.app = None
        self.main_window = None
        self.audit_log = None
        
    def initialize(self):
        """Initialize the application"""
        try:
            # Create QApplication
            self.app = create_application()
            
            # Set up global exception handler
            sys.excepthook = self._handle_exception
            
            # Initialize audit log
            self.audit_log = get_audit_log()
            
            # Log application startup
            log_operation("Application Startup", "SUCCESS", "TEXT")
            
            # Create main window
            self.main_window = MainWindow()
            
            # Set up cleanup on exit
            if AUTO_WIPE_ON_EXIT:
                self.app.aboutToQuit.connect(self._cleanup_on_exit)
            
            return True
            
        except Exception as e:
            self._show_critical_error("Initialization Error", 
                                    f"Failed to initialize application: {str(e)}")
            return False
    
    def run(self):
        """Run the application"""
        try:
            if not self.initialize():
                return 1
            
            # Show main window
            self.main_window.show()
            
            # Log successful startup
            log_operation("GUI Initialization", "SUCCESS", "TEXT")
            
            # Start event loop
            return self.app.exec()
            
        except Exception as e:
            self._show_critical_error("Runtime Error", 
                                    f"Application runtime error: {str(e)}")
            return 1
    
    def _handle_exception(self, exc_type, exc_value, exc_traceback):
        """Global exception handler"""
        try:
            # Log the exception
            error_msg = f"{exc_type.__name__}: {str(exc_value)}"
            log_operation("Unhandled Exception", "FAILURE", "TEXT", error=exc_value)
            
            # Print to console for debugging
            print("Unhandled exception occurred:")
            traceback.print_exception(exc_type, exc_value, exc_traceback)
            
            # Show error dialog if GUI is available
            if self.app and self.main_window:
                QMessageBox.critical(
                    self.main_window,
                    "Critical Error",
                    f"An unexpected error occurred:\n\n{error_msg}\n\n"
                    "The application may become unstable. Please restart."
                )
            
        except Exception:
            # If even error handling fails, just print to console
            print(f"Critical error in exception handler: {exc_type.__name__}: {str(exc_value)}")
    
    def _cleanup_on_exit(self):
        """Perform cleanup operations on application exit"""
        try:
            # Log application shutdown
            log_operation("Application Shutdown", "SUCCESS", "TEXT")
            
            # Wipe audit logs if configured
            if self.audit_log and AUTO_WIPE_ON_EXIT:
                self.audit_log.wipe_logs()
            
            print("EnigmaEcho SecureComm shutdown complete.")
            
        except Exception as e:
            print(f"Cleanup error: {str(e)}")
    
    def _show_critical_error(self, title, message):
        """Show critical error message"""
        try:
            if self.app:
                # Create a temporary message box
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setWindowTitle(title)
                msg_box.setText(message)
                msg_box.exec()
            else:
                print(f"{title}: {message}")
        except Exception:
            print(f"{title}: {message}")


def check_dependencies():
    """Check if all required dependencies are available"""
    missing_deps = []
    
    try:
        import PySide6
    except ImportError:
        missing_deps.append("PySide6")
    
    try:
        import cryptography
    except ImportError:
        missing_deps.append("cryptography")
    
    try:
        import pyperclip
    except ImportError:
        missing_deps.append("pyperclip")
    
    try:
        import PIL
    except ImportError:
        missing_deps.append("Pillow")
    
    if missing_deps:
        print("Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nPlease install missing dependencies:")
        print(f"pip install {' '.join(missing_deps)}")
        return False
    
    return True


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print(f"Python 3.8 or higher is required. Current version: {sys.version}")
        return False
    return True


def setup_environment():
    """Setup application environment"""
    try:
        # Check if we're in a headless environment
        display = os.environ.get('DISPLAY')
        if not display and sys.platform.startswith('linux'):
            print("⚠️  Warning: No DISPLAY environment variable detected.")
            print("   This appears to be a headless environment.")
            print("   GUI functionality may not work.")
            print("   Try: python demo_cli.py for command-line demo")
            
        # Set high DPI scaling (suppress deprecation warnings)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            
            if hasattr(Qt, 'AA_EnableHighDpiScaling'):
                QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
            
            if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
                QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
            
            # Set application attributes for better rendering
            if hasattr(Qt, 'AA_DisableWindowContextHelpButton'):
                QApplication.setAttribute(Qt.AA_DisableWindowContextHelpButton, True)
        
        return True
        
    except Exception as e:
        print(f"Environment setup warning: {str(e)}")
        return True  # Non-critical, continue anyway


def print_startup_banner():
    """Print application startup banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    EnigmaEcho SecureComm                     ║
║                  Secure Encryption Tool                     ║
║                        Version 1.0.0                        ║
╠══════════════════════════════════════════════════════════════╣
║  • AES-256-GCM Encryption with PBKDF2 Key Derivation       ║
║  • HMAC-SHA256 Authentication                               ║
║  • NIST SP 800-63B & OWASP Compliant                       ║
║  • Local-Only Processing (No Cloud)                        ║
║  • Secure Audit Logging                                    ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    """Main entry point"""
    try:
        # Print startup banner
        print_startup_banner()
        
        # Check Python version
        if not check_python_version():
            return 1
        
        # Check dependencies
        if not check_dependencies():
            return 1
        
        # Setup environment
        if not setup_environment():
            print("Warning: Environment setup had issues, continuing anyway...")
        
        # Create and run application
        app_instance = EnigmaEchoApplication()
        return app_instance.run()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
        return 0
        
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Ensure clean exit
    exit_code = main()
    sys.exit(exit_code)
