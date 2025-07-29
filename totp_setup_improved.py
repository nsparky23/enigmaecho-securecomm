"""
Improved TOTP Setup Dialog with better sizing and layout
This replaces the cramped dialog in gui_components.py
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QGroupBox, QMessageBox, QScrollArea, QWidget
)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSizePolicy
from PySide6.QtGui import QPixmap

from totp_auth import get_totp_authenticator, TOTPError
from config import COLOR_BG, COLOR_ACCENT, COLOR_TEXT, COLOR_SECONDARY, COLOR_BORDER, COLOR_HOVER


class ImprovedTOTPSetupDialog(QDialog):
    """Improved TOTP setup dialog with better sizing and layout"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Setup Two-Factor Authentication")
        self.setModal(True)
        self.resize(700, 900)  # Much larger size
        self.setMinimumSize(650, 850)  # Minimum size to prevent cramping
        self.master_password = ""
        self.setup_completed = False
        self._setup_ui()

        # Make dialog responsive
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumSize(600, 700)
        self.resize(750, 950)  # Slightly larger default
        
        # Enable resizing
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)
        self._apply_styles()
    
    def _setup_ui(self):
        # Main scroll area to handle overflow
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        layout = QVBoxLayout()
        
        # Title with more spacing
        title = QLabel("Setup Two-Factor Authentication")
        title.setStyleSheet(f"""
            color: {COLOR_ACCENT}; 
            font-size: 18px; 
            font-weight: bold; 
            margin: 15px 0px 20px 0px;
            padding: 10px;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Instructions with better formatting
        instructions = QLabel(
            "Follow these steps to set up secure two-factor authentication:\n\n"
            "1. Enter a strong master password (minimum 8 characters)\n"
            "2. Generate and scan the QR code with your authenticator app\n"
            "   (Google Authenticator, Authy, Microsoft Authenticator, etc.)\n"
            "3. Enter the 6-digit verification code to complete setup"
        )
        instructions.setStyleSheet(f"""
            color: {COLOR_TEXT}; 
            font-size: 12px; 
            margin: 10px 0px 20px 0px;
            padding: 15px;
            background-color: {COLOR_SECONDARY};
            border: 1px solid {COLOR_BORDER};
            border-radius: 6px;
            line-height: 1.4;
        """)
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        
        # Master password section with more space
        password_group = QGroupBox("Step 1: Master Password")
        password_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                font-size: 14px;
                border: 2px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 15px 0px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 5px 10px;
                background-color: {COLOR_BG};
            }}
        """)
        password_layout = QVBoxLayout()
        password_layout.setSpacing(15)  # More spacing between elements
        
        # Password input with labels
        pwd_label = QLabel("Enter master password:")
        pwd_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; margin-bottom: 5px;")
        password_layout.addWidget(pwd_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter a strong master password (min 8 characters)...")
        self.password_input.setMinimumHeight(35)  # Taller input fields
        password_layout.addWidget(self.password_input)
        
        confirm_label = QLabel("Confirm master password:")
        confirm_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; margin-bottom: 5px;")
        password_layout.addWidget(confirm_label)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Re-enter the same password...")
        self.confirm_password_input.setMinimumHeight(35)
        password_layout.addWidget(self.confirm_password_input)
        
        # Generate button with more prominence
        self.generate_qr_button = QPushButton("Generate QR Code")
        self.generate_qr_button.clicked.connect(self._generate_qr_code)
        self.generate_qr_button.setMinimumHeight(40)
        self.generate_qr_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
        """)
        password_layout.addWidget(self.generate_qr_button)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # QR Code section with much more space
        qr_group = QGroupBox("Step 2: Scan QR Code")
        qr_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                font-size: 14px;
                border: 2px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 15px 0px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 5px 10px;
                background-color: {COLOR_BG};
            }}
        """)
        qr_layout = QVBoxLayout()
        qr_layout.setSpacing(15)
        
        qr_instruction = QLabel("Scan this QR code with your authenticator app:")
        qr_instruction.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; margin-bottom: 10px;")
        qr_layout.addWidget(qr_instruction)
        
        # QR Code display with much larger area
        self.qr_label = QLabel("QR Code will appear here after generating...")
        self.qr_label.setStyleSheet(f"""
            QLabel {{
                border: 2px dashed {COLOR_BORDER};
                border-radius: 8px;
                padding: 30px;
                text-align: center;
                color: {COLOR_TEXT};
                min-height: 280px;
                min-width: 280px;
                background-color: {COLOR_SECONDARY};
                font-size: 12px;
            }}
        """)
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setScaledContents(False)  # Prevent scaling issues
        qr_layout.addWidget(self.qr_label)
        
        qr_group.setLayout(qr_layout)
        layout.addWidget(qr_group)
        
        # Verification section
        verify_group = QGroupBox("Step 3: Verify Setup")
        verify_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                font-size: 14px;
                border: 2px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 15px 0px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 5px 10px;
                background-color: {COLOR_BG};
            }}
        """)
        verify_layout = QVBoxLayout()
        verify_layout.setSpacing(15)
        
        verify_label = QLabel("Enter the 6-digit code from your authenticator app:")
        verify_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; margin-bottom: 5px;")
        verify_layout.addWidget(verify_label)
        
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setMaxLength(6)
        self.totp_input.setEnabled(False)
        self.totp_input.setMinimumHeight(35)
        self.totp_input.setStyleSheet(f"""
            QLineEdit {{
                font-size: 16px;
                text-align: center;
                letter-spacing: 3px;
                font-weight: bold;
            }}
        """)
        verify_layout.addWidget(self.totp_input)
        
        self.verify_button = QPushButton("Verify & Complete Setup")
        self.verify_button.clicked.connect(self._verify_setup)
        self.verify_button.setEnabled(False)
        self.verify_button.setMinimumHeight(40)
        self.verify_button.setStyleSheet(f"""
            QPushButton {{
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: #218838;
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: #888888;
            }}
        """)
        verify_layout.addWidget(self.verify_button)
        
        verify_group.setLayout(verify_layout)
        layout.addWidget(verify_group)
        
        # Bottom buttons with more space
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setMinimumHeight(35)
        
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()  # Push everything up
        
        scroll_widget.setLayout(layout)
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        
        # Main dialog layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
            }}
            QScrollArea {{
                border: none;
                background-color: {COLOR_BG};
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
                padding: 10px 16px;
                font-weight: bold;
                min-width: 120px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: #888888;
            }}
        """)
    
    def _generate_qr_code(self):
        """Generate QR code for TOTP setup"""
        try:
            password = self.password_input.text()
            confirm_password = self.confirm_password_input.text()
            
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter a master password.")
                return
            
            if password != confirm_password:
                QMessageBox.warning(self, "Warning", "Passwords do not match.")
                return
            
            if len(password) < 8:
                QMessageBox.warning(self, "Warning", "Master password must be at least 8 characters long.")
                return
            
            # Generate TOTP setup
            totp_auth = get_totp_authenticator()
            secret_key, qr_code_bytes = totp_auth.setup_totp(password)
            
            # Display QR code with proper scaling
            pixmap = QPixmap()
            pixmap.loadFromData(qr_code_bytes)
            # Scale to fit the larger area while maintaining aspect ratio
            scaled_pixmap = pixmap.scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_label.setPixmap(scaled_pixmap)
            
            # Enable verification
            self.totp_input.setEnabled(True)
            self.verify_button.setEnabled(True)
            self.master_password = password
            
            # Disable password fields
            self.password_input.setEnabled(False)
            self.confirm_password_input.setEnabled(False)
            self.generate_qr_button.setEnabled(False)
            
            QMessageBox.information(self, "QR Code Generated", 
                                  "QR code generated successfully!\n\n"
                                  "Scan it with your authenticator app, then enter the 6-digit code below to verify.")
            
        except TOTPError as e:
            QMessageBox.critical(self, "TOTP Setup Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate QR code: {str(e)}")
    
    def _verify_setup(self):
        """Verify TOTP setup with user-entered code"""
        try:
            token = self.totp_input.text().strip()
            
            if len(token) != 6 or not token.isdigit():
                QMessageBox.warning(self, "Warning", "Please enter a valid 6-digit code.")
                return
            
            # Verify token
            totp_auth = get_totp_authenticator()
            if totp_auth.verify_totp(token, self.master_password):
                self.setup_completed = True
                
                # Show backup codes
                backup_codes = totp_auth.get_backup_codes(self.master_password)
                backup_text = "\n".join(backup_codes)
                
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Information)
                msg.setWindowTitle("Setup Complete!")
                msg.setText("TOTP setup completed successfully!\n\n"
                           "IMPORTANT: Save these backup codes securely.\n"
                           "You can use them if you lose access to your authenticator app.")
                msg.setDetailedText(backup_text)
                msg.exec()
                
                self.accept()
            else:
                QMessageBox.warning(self, "Verification Failed", 
                                  "Invalid code. Please check your authenticator app and try again.\n\n"
                                  "Make sure the time on your device is synchronized.")
                
        except TOTPError as e:
            QMessageBox.critical(self, "Verification Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification failed: {str(e)}")
