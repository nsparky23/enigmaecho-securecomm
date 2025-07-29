"""
Updated TOTP Login Dialog without backup code functionality
Implements session management and responsive design
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

from totp_auth import get_totp_authenticator, TOTPError
from session_manager import get_session_manager
from config import COLOR_BG, COLOR_ACCENT, COLOR_TEXT, COLOR_SECONDARY, COLOR_BORDER, COLOR_HOVER


class UpdatedTOTPLoginDialog(QDialog):
    """Updated TOTP authentication dialog without backup code functionality"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Two-Factor Authentication")
        self.setModal(True)
        self.setMinimumSize(450, 300)  # Responsive minimum size
        self.resize(500, 350)  # Larger default size
        
        self.master_password = ""
        self.authenticated = False
        self._setup_ui()
        self._apply_styles()
        self._start_timer()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)  # More spacing between elements
        
        # Title with better styling
        title = QLabel("Two-Factor Authentication")
        title.setStyleSheet(f"""
            color: {COLOR_ACCENT}; 
            font-size: 16px; 
            font-weight: bold; 
            margin: 15px 0px 20px 0px;
            padding: 10px;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel("Enter your master password and current TOTP code to continue:")
        instructions.setStyleSheet(f"""
            color: {COLOR_TEXT}; 
            font-size: 12px; 
            margin: 10px 0px;
            text-align: center;
        """)
        instructions.setWordWrap(True)
        instructions.setAlignment(Qt.AlignCenter)
        layout.addWidget(instructions)
        
        # Master password section
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; font-weight: bold;")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter master password...")
        self.password_input.setMinimumHeight(35)
        layout.addWidget(self.password_input)
        
        # TOTP code section
        totp_layout = QHBoxLayout()
        
        totp_label = QLabel("Authenticator Code:")
        totp_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; font-weight: bold;")
        layout.addWidget(totp_label)
        
        code_layout = QHBoxLayout()
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setMaxLength(6)
        self.totp_input.setMinimumHeight(35)
        self.totp_input.setStyleSheet(f"""
            QLineEdit {{
                font-size: 16px;
                text-align: center;
                letter-spacing: 2px;
                font-weight: bold;
            }}
        """)
        code_layout.addWidget(self.totp_input)
        
        self.time_label = QLabel("30s")
        self.time_label.setStyleSheet(f"""
            color: {COLOR_ACCENT}; 
            font-weight: bold; 
            min-width: 40px;
            font-size: 14px;
            padding: 5px;
        """)
        code_layout.addWidget(self.time_label)
        
        layout.addLayout(code_layout)
        
        # Session info
        session_info = QLabel("Once authenticated, you'll remain logged in for 30 minutes of activity.")
        session_info.setStyleSheet(f"""
            color: {COLOR_SECONDARY}; 
            font-size: 10px; 
            margin: 10px 0px;
            font-style: italic;
        """)
        session_info.setWordWrap(True)
        session_info.setAlignment(Qt.AlignCenter)
        layout.addWidget(session_info)
        
        # Buttons with better spacing
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setMinimumHeight(40)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self._authenticate)
        self.login_button.setDefault(True)
        self.login_button.setMinimumHeight(40)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.login_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()  # Push content up
        
        self.setLayout(layout)
        
        # Focus on password input
        self.password_input.setFocus()
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
            }}
            QLineEdit {{
                background-color: {COLOR_SECONDARY};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 10px;
                color: {COLOR_TEXT};
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border-color: {COLOR_ACCENT};
                border-width: 2px;
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 20px;
                font-weight: bold;
                min-width: 100px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
            QPushButton:default {{
                background-color: #28a745;
            }}
            QPushButton:default:hover {{
                background-color: #218838;
            }}
        """)
    
    def _start_timer(self):
        """Start timer to update remaining time"""
        self.timer = QTimer()
        self.timer.timeout.connect(self._update_time)
        self.timer.start(1000)  # Update every second
        self._update_time()
    
    def _update_time(self):
        """Update remaining time display"""
        try:
            totp_auth = get_totp_authenticator()
            remaining = totp_auth.get_time_remaining()
            self.time_label.setText(f"{remaining}s")
            
            # Change color when time is running out
            if remaining <= 10:
                self.time_label.setStyleSheet(f"""
                    color: #ff6b6b; 
                    font-weight: bold; 
                    min-width: 40px;
                    font-size: 14px;
                    padding: 5px;
                """)
            else:
                self.time_label.setStyleSheet(f"""
                    color: {COLOR_ACCENT}; 
                    font-weight: bold; 
                    min-width: 40px;
                    font-size: 14px;
                    padding: 5px;
                """)
        except Exception:
            self.time_label.setText("--")
    
    def _authenticate(self):
        """Authenticate user with TOTP"""
        try:
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter your master password.")
                return
            
            totp_code = self.totp_input.text().strip()
            if len(totp_code) != 6 or not totp_code.isdigit():
                QMessageBox.warning(self, "Warning", "Please enter a valid 6-digit TOTP code.")
                return
            
            totp_auth = get_totp_authenticator()
            
            if totp_auth.verify_totp(totp_code, password):
                # Establish session using session manager
                session_manager = get_session_manager()
                session_manager.establish_session()
                
                # Also establish session in TOTP authenticator if it has the method
                if hasattr(totp_auth, 'establish_session'):
                    totp_auth.establish_session()
                
                self.master_password = password
                self.authenticated = True
                self.accept()
            else:
                QMessageBox.warning(self, "Authentication Failed", 
                                  "Invalid TOTP code or master password.\n\n"
                                  "Please check your authenticator app and try again.")
                    
        except TOTPError as e:
            QMessageBox.critical(self, "Authentication Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Authentication failed: {str(e)}")
    
    def closeEvent(self, event):
        """Clean up timer on close"""
        if hasattr(self, 'timer'):
            self.timer.stop()
        super().closeEvent(event)
    
    def get_master_password(self):
        """Get the master password after successful authentication"""
        return self.master_password
