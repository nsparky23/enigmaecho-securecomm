"""
GUI Components for EnigmaEcho SecureComm
Implements modern dark theme interface with PySide6
Features text and file encryption/decryption with secure manual file handling
"""

import os
import sys
from typing import List, Optional
from pathlib import Path

from PySide6.QtWidgets import (
    QSizePolicy,
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QGridLayout, QTextEdit, QComboBox, QPushButton, QLabel, 
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QDialog, QProgressBar, QSplitter, QFrame,
    QScrollArea, QGroupBox, QLineEdit, QMenuBar, QMenu
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QPixmap, QPalette, QColor, QAction

import pyperclip
from cryptography_utils import encrypt_text, decrypt_text, CryptographyError
from file_handler import FileHandler
from audit_log import get_audit_log, log_operation
from totp_auth import get_totp_authenticator, TOTPError
from totp_setup_improved import ImprovedTOTPSetupDialog
from config import (
    COLOR_BG, COLOR_ACCENT, COLOR_DROPDOWN, COLOR_TEXT, COLOR_SECONDARY,
    COLOR_BORDER, COLOR_HOVER, WINDOW_TITLE, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
    FONT_FAMILY, FONT_SIZE, TEXT_INPUT_PLACEHOLDER, TEXT_OUTPUT_PLACEHOLDER,
    OPERATION_OPTIONS, OUTPUT_OPTIONS
)


class TOTPSetupDialog(QDialog):
    """Dialog for TOTP setup with QR code display"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Setup Two-Factor Authentication")
        self.setModal(True)
        self.setFixedSize(500, 600)
        self.master_password = ""
        self.setup_completed = False
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Setup Two-Factor Authentication")
        title.setStyleSheet(f"color: {COLOR_ACCENT}; font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel(
            "1. Enter a master password to secure your TOTP configuration\n"
            "2. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)\n"
            "3. Enter the 6-digit code from your app to verify setup"
        )
        instructions.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 11px; margin-bottom: 15px;")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        
        # Master password section
        password_group = QGroupBox("Master Password")
        password_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }}
        """)
        password_layout = QVBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter master password...")
        password_layout.addWidget(self.password_input)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm master password...")
        password_layout.addWidget(self.confirm_password_input)
        
        self.generate_qr_button = QPushButton("Generate QR Code")
        self.generate_qr_button.clicked.connect(self._generate_qr_code)
        password_layout.addWidget(self.generate_qr_button)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # QR Code display
        self.qr_label = QLabel("QR Code will appear here after generating...")
        self.qr_label.setStyleSheet(f"""
            QLabel {{
                border: 2px dashed {COLOR_BORDER};
                border-radius: 4px;
                padding: 20px;
                text-align: center;
                color: {COLOR_TEXT};
                min-height: 200px;
            }}
        """)
        self.qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.qr_label)
        
        # Verification section
        verify_group = QGroupBox("Verify Setup")
        verify_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }}
        """)
        verify_layout = QVBoxLayout()
        
        verify_label = QLabel("Enter 6-digit code from your authenticator app:")
        verify_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 11px;")
        verify_layout.addWidget(verify_label)
        
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setMaxLength(6)
        self.totp_input.setEnabled(False)
        verify_layout.addWidget(self.totp_input)
        
        self.verify_button = QPushButton("Verify & Complete Setup")
        self.verify_button.clicked.connect(self._verify_setup)
        self.verify_button.setEnabled(False)
        verify_layout.addWidget(self.verify_button)
        
        verify_group.setLayout(verify_layout)
        layout.addWidget(verify_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)


        self.setLayout(layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
            }}
            QLineEdit {{
                background-color: {COLOR_SECONDARY};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
                color: {COLOR_TEXT};
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border-color: {COLOR_ACCENT};
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 100px;
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
            
            # Display QR code
            pixmap = QPixmap()
            pixmap.loadFromData(qr_code_bytes)
            scaled_pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
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
                                  "Scan the QR code with your authenticator app, then enter the 6-digit code to verify.")
            
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
                msg.setWindowTitle("Setup Complete")
                msg.setText("TOTP setup completed successfully!\n\nBackup Codes (save these securely):")
                msg.setDetailedText(backup_text)
                msg.exec()
                
                self.accept()
            else:
                QMessageBox.warning(self, "Verification Failed", 
                                  "Invalid code. Please check your authenticator app and try again.")
                
        except TOTPError as e:
            QMessageBox.critical(self, "Verification Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification failed: {str(e)}")


class TOTPLoginDialog(QDialog):
    """Dialog for TOTP authentication"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Two-Factor Authentication")
        self.setModal(True)
        self.setFixedSize(400, 250)
        self.master_password = ""
        self.authenticated = False
        self._setup_ui()
        self._apply_styles()
        self._start_timer()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Two-Factor Authentication")
        title.setStyleSheet(f"color: {COLOR_ACCENT}; font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Master password
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter master password...")
        layout.addWidget(self.password_input)
        
        # TOTP code
        totp_label = QLabel("Authenticator Code:")
        totp_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        layout.addWidget(totp_label)
        
        totp_layout = QHBoxLayout()
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setMaxLength(6)
        totp_layout.addWidget(self.totp_input)
        
        self.time_label = QLabel("30s")
        self.time_label.setStyleSheet(f"color: {COLOR_ACCENT}; font-weight: bold; min-width: 30px;")
        totp_layout.addWidget(self.time_label)
        
        layout.addLayout(totp_layout)
        
        # Backup code option
        self.backup_code_button = QPushButton("Use Backup Code")
        self.backup_code_button.clicked.connect(self._show_backup_code_input)
        self.backup_code_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SECONDARY};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_BORDER};
            }}
        """)
        layout.addWidget(self.backup_code_button)
        
        # Backup code input (hidden initially)
        self.backup_code_input = QLineEdit()
        self.backup_code_input.setPlaceholderText("Enter backup code (XXXX-XXXX)...")
        self.backup_code_input.setVisible(False)
        layout.addWidget(self.backup_code_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self._authenticate)
        self.login_button.setDefault(True)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        

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
                border-radius: 4px;
                padding: 8px;
                color: {COLOR_TEXT};
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border-color: {COLOR_ACCENT};
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
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
                self.time_label.setStyleSheet(f"color: #ff6b6b; font-weight: bold; min-width: 30px;")
            else:
                self.time_label.setStyleSheet(f"color: {COLOR_ACCENT}; font-weight: bold; min-width: 30px;")
        except Exception:
            self.time_label.setText("--")
    
    def _show_backup_code_input(self):
        """Show backup code input field"""
        self.backup_code_input.setVisible(True)
        self.backup_code_input.setFocus()
        self.backup_code_button.setText("Use TOTP Code")
        self.backup_code_button.clicked.disconnect()
        self.backup_code_button.clicked.connect(self._hide_backup_code_input)
    
    def _hide_backup_code_input(self):
        """Hide backup code input field"""
        self.backup_code_input.setVisible(False)
        self.backup_code_input.clear()
        self.totp_input.setFocus()
        self.backup_code_button.setText("Use Backup Code")
        self.backup_code_button.clicked.disconnect()
        self.backup_code_button.clicked.connect(self._show_backup_code_input)
    
    def _authenticate(self):
        """Authenticate user with TOTP or backup code"""
        try:
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter your master password.")
                return
            
            totp_auth = get_totp_authenticator()
            
            # Check if using backup code
            if self.backup_code_input.isVisible() and self.backup_code_input.text().strip():
                backup_code = self.backup_code_input.text().strip()
                if totp_auth.verify_backup_code(backup_code, password):
                    self.master_password = password
                    self.authenticated = True
                    self.accept()
                else:
                    QMessageBox.warning(self, "Authentication Failed", "Invalid backup code or master password.")
            else:
                # Use TOTP code
                totp_code = self.totp_input.text().strip()
                if len(totp_code) != 6 or not totp_code.isdigit():
                    QMessageBox.warning(self, "Warning", "Please enter a valid 6-digit TOTP code.")
                    return
                
                if totp_auth.verify_totp(totp_code, password):
                    self.master_password = password
                    self.authenticated = True
                    self.accept()
                else:
                    QMessageBox.warning(self, "Authentication Failed", "Invalid TOTP code or master password.")
                    
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


class AuditLogDialog(QDialog):
    """Dialog for viewing audit logs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Audit Log")
        self.setModal(True)
        self.resize(800, 600)
        self._setup_ui()
        self._apply_styles()
        self._load_logs()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Security Audit Log")
        header_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # Log table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp", "Action", "Type", "Outcome", "File Hash", "Error"
        ])
        
        # Configure table
        header = self.log_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        layout.addWidget(self.log_table)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._load_logs)
        
        self.export_button = QPushButton("Export Logs")
        self.export_button.clicked.connect(self._export_logs)
        
        self.clear_button = QPushButton("Clear Logs")
        self.clear_button.clicked.connect(self._clear_logs)
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        
        button_layout.addWidget(self.refresh_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
            }}
            QTableWidget {{
                background-color: {COLOR_SECONDARY};
                alternate-background-color: {COLOR_BG};
                gridline-color: {COLOR_BORDER};
                color: {COLOR_TEXT};
                selection-background-color: {COLOR_ACCENT};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ACCENT};
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
        """)
    
    def _load_logs(self):
        """Load and display audit logs"""
        try:
            audit_log = get_audit_log()
            logs = audit_log.get_logs()
            
            self.log_table.setRowCount(len(logs))
            
            for row, log_entry in enumerate(logs):
                self.log_table.setItem(row, 0, QTableWidgetItem(log_entry.get('timestamp', '')))
                self.log_table.setItem(row, 1, QTableWidgetItem(log_entry.get('action', '')))
                self.log_table.setItem(row, 2, QTableWidgetItem(log_entry.get('operation_type', '')))
                self.log_table.setItem(row, 3, QTableWidgetItem(log_entry.get('outcome', '')))
                self.log_table.setItem(row, 4, QTableWidgetItem(log_entry.get('filename_hash', '') or 'N/A'))
                self.log_table.setItem(row, 5, QTableWidgetItem(log_entry.get('error_type', '') or 'N/A'))
                
                # Color code outcomes
                outcome_item = self.log_table.item(row, 3)
                if log_entry.get('outcome') == 'SUCCESS':
                    outcome_item.setBackground(QColor('#2d5a2d'))
                elif log_entry.get('outcome') == 'FAILURE':
                    outcome_item.setBackground(QColor('#5a2d2d'))
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load audit logs: {str(e)}")
    
    def _export_logs(self):
        """Export logs to file"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Audit Logs", "audit_logs.json", "JSON Files (*.json)"
            )
            
            if file_path:
                audit_log = get_audit_log()
                if audit_log.export_logs(file_path):
                    QMessageBox.information(self, "Success", "Audit logs exported successfully.")
                else:
                    QMessageBox.warning(self, "Warning", "Failed to export audit logs.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def _clear_logs(self):
        """Clear all audit logs with confirmation"""
        reply = QMessageBox.question(
            self, "Confirm Clear", 
            "Are you sure you want to clear all audit logs? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            audit_log = get_audit_log()
            audit_log.wipe_logs()
            self._load_logs()
            QMessageBox.information(self, "Success", "Audit logs cleared.")


class TextOperationsWidget(QWidget):
    """Widget for text encryption/decryption operations"""
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Text Operations")
        title.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Input section
        input_layout = QHBoxLayout()
        
        # Text input
        input_group = QVBoxLayout()
        input_label = QLabel("Input:")
        input_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        input_group.addWidget(input_label)
        
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText(TEXT_INPUT_PLACEHOLDER)
        self.text_input.setMaximumHeight(150)
        input_group.addWidget(self.text_input)
        
        # Text output
        output_group = QVBoxLayout()
        output_label = QLabel("Output:")
        output_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        output_group.addWidget(output_label)
        
        self.text_output = QTextEdit()
        self.text_output.setPlaceholderText(TEXT_OUTPUT_PLACEHOLDER)
        self.text_output.setReadOnly(True)
        self.text_output.setMaximumHeight(150)
        output_group.addWidget(self.text_output)
        
        input_layout.addLayout(input_group)
        input_layout.addLayout(output_group)
        layout.addLayout(input_layout)
        
        # Controls section
        controls_layout = QHBoxLayout()
        
        # Operation dropdown
        operation_group = QVBoxLayout()
        operation_label = QLabel("Operation:")
        operation_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        operation_group.addWidget(operation_label)
        
        self.operation_combo = QComboBox()
        self.operation_combo.addItems(OPERATION_OPTIONS)
        operation_group.addWidget(self.operation_combo)
        
        self.operation_button = QPushButton("Process Text")
        self.operation_button.clicked.connect(self._process_text)
        operation_group.addWidget(self.operation_button)
        
        # Output dropdown
        output_group = QVBoxLayout()
        output_label = QLabel("Output Action:")
        output_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        output_group.addWidget(output_label)
        
        self.output_combo = QComboBox()
        self.output_combo.addItems(OUTPUT_OPTIONS)
        output_group.addWidget(self.output_combo)
        
        self.output_button = QPushButton("Execute Action")
        self.output_button.clicked.connect(self._execute_output_action)
        output_group.addWidget(self.output_button)
        
        controls_layout.addLayout(operation_group)
        controls_layout.addLayout(output_group)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        self.setLayout(layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_SECONDARY};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
                color: {COLOR_TEXT};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }}
            QTextEdit:focus {{
                border-color: {COLOR_ACCENT};
            }}
            QComboBox {{
                background-color: white;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 6px;
                color: black;
                font-size: 11px;
                min-width: 120px;
                font-weight: 500;
            }}
            QComboBox:hover {{
                border-color: {COLOR_ACCENT};
                border-width: 2px;
            }}
            QComboBox QAbstractItemView {{
                background-color: white;
                color: black;
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
                border: 1px solid {COLOR_BORDER};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid black;
                margin-right: 5px;
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 100px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
            QPushButton:pressed {{
                background-color: {COLOR_BORDER};
            }}
        """)
    
    def _process_text(self):
        """Process text encryption or decryption"""
        try:
            input_text = self.text_input.toPlainText().strip()
            if not input_text:
                QMessageBox.warning(self, "Warning", "Please enter text to process.")
                return
            
            # Check if TOTP is set up
            totp_auth = get_totp_authenticator()
            if not totp_auth.is_setup_complete():
                # Show TOTP setup dialog
                setup_dialog = ImprovedTOTPSetupDialog(self)
                if setup_dialog.exec() != QDialog.Accepted:
                    return
            
            # Authenticate with TOTP
            login_dialog = TOTPLoginDialog(self)
            if login_dialog.exec() != QDialog.Accepted:
                return
            
            master_password = login_dialog.get_master_password()
            if not master_password:
                return
            
            operation = self.operation_combo.currentText()
            
            try:
                if operation == "Encrypt":
                    result = encrypt_text(input_text, master_password)
                    log_operation("Text Encryption", "SUCCESS", "TEXT")
                else:  # Decrypt
                    result = decrypt_text(input_text, master_password)
                    log_operation("Text Decryption", "SUCCESS", "TEXT")
                
                self.text_output.setPlainText(result)
                
            except CryptographyError as e:
                error_msg = f"{operation} failed: {str(e)}"
                log_operation(f"Text {operation}", "FAILURE", "TEXT", error=e)
                QMessageBox.critical(self, f"{operation} Error", error_msg)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Text processing failed: {str(e)}")
    
    def _execute_output_action(self):
        """Execute the selected output action"""
        try:
            output_text = self.text_output.toPlainText().strip()
            if not output_text:
                QMessageBox.warning(self, "Warning", "No output text to process.")
                return
            
            action = self.output_combo.currentText()
            
            if action == "Copy to Clipboard":
                pyperclip.copy(output_text)
                QMessageBox.information(self, "Success", "Text copied to clipboard.")
                log_operation("Copy to Clipboard", "SUCCESS", "TEXT")
                
            else:  # Copy to File
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save Text to File", "output.txt", "Text Files (*.txt);;All Files (*)"
                )
                
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(output_text)
                    
                    QMessageBox.information(self, "Success", f"Text saved to: {file_path}")
                    log_operation("Save to File", "SUCCESS", "TEXT", os.path.basename(file_path))
                    
        except Exception as e:
            error_msg = f"Output action failed: {str(e)}"
            log_operation(f"Output Action", "FAILURE", "TEXT", error=e)
            QMessageBox.critical(self, "Error", error_msg)


class FileOperationsWidget(QWidget):
    """Widget for file encryption/decryption operations"""
    
    def __init__(self):
        super().__init__()
        self.file_handler = FileHandler(self)
        self.selected_files = []
        self._setup_ui()
        self._apply_styles()
        self._connect_signals()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("File Operations")
        title.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # File list section
        file_section = QVBoxLayout()
        
        # File controls
        file_controls = QHBoxLayout()
        
        self.add_files_button = QPushButton("Add Files")
        self.add_files_button.clicked.connect(self._add_files)
        
        self.remove_selected_button = QPushButton("Remove Selected")
        self.remove_selected_button.clicked.connect(self._remove_selected)
        self.remove_selected_button.setEnabled(False)
        
        file_controls.addWidget(self.add_files_button)
        file_controls.addWidget(self.remove_selected_button)
        file_controls.addStretch()
        
        file_section.addLayout(file_controls)
        
        # File table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(3)
        self.file_table.setHorizontalHeaderLabels(["Filename", "Size", "Type"])
        self.file_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.file_table.itemSelectionChanged.connect(self._on_selection_changed)
        
        # Configure table
        header = self.file_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        self.file_table.setMaximumHeight(200)
        file_section.addWidget(self.file_table)
        
        layout.addLayout(file_section)
        
        # Operation controls
        operation_layout = QHBoxLayout()
        
        # Operation selection
        operation_group = QVBoxLayout()
        operation_label = QLabel("File Operation:")
        operation_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px;")
        operation_group.addWidget(operation_label)
        
        self.file_operation_combo = QComboBox()
        self.file_operation_combo.addItems(OPERATION_OPTIONS)
        operation_group.addWidget(self.file_operation_combo)
        
        # Process button
        self.process_files_button = QPushButton("Process Files")
        self.process_files_button.clicked.connect(self._process_files)
        self.process_files_button.setEnabled(False)
        operation_group.addWidget(self.process_files_button)
        
        operation_layout.addLayout(operation_group)
        operation_layout.addStretch()
        
        # Audit log button
        self.audit_log_button = QPushButton("Audit Log")
        self.audit_log_button.clicked.connect(self._show_audit_log)
        operation_layout.addWidget(self.audit_log_button)
        
        layout.addLayout(operation_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLOR_SECONDARY};
                alternate-background-color: {COLOR_BG};
                gridline-color: {COLOR_BORDER};
                color: {COLOR_TEXT};
                selection-background-color: {COLOR_ACCENT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
            }}
            QHeaderView::section {{
                background-color: {COLOR_ACCENT};
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }}
            QComboBox {{
                background-color: white;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 6px;
                color: black;
                font-size: 11px;
                min-width: 120px;
                font-weight: 500;
            }}
            QComboBox:hover {{
                border-color: {COLOR_ACCENT};
                border-width: 2px;
            }}
            QComboBox QAbstractItemView {{
                background-color: white;
                color: black;
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
                border: 1px solid {COLOR_BORDER};
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 100px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: #888888;
            }}
            QProgressBar {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                text-align: center;
                color: {COLOR_TEXT};
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_ACCENT};
                border-radius: 3px;
            }}
        """)
    
    def _connect_signals(self):
        """Connect file handler signals"""
        self.file_handler.operation_completed.connect(self._on_operation_completed)
        self.file_handler.progress_updated.connect(self._on_progress_updated)
    
    def _add_files(self):
        """Add files to the processing list"""
        try:
            file_paths, _ = QFileDialog.getOpenFileNames(
                self, "Select Files to Process", "", "All Files (*)"
            )
            
            for file_path in file_paths:
                if file_path not in self.selected_files:
                    self.selected_files.append(file_path)
            
            self._update_file_table()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add files: {str(e)}")
    
    def _remove_selected(self):
        """Remove selected files from the list"""
        try:
            selected_rows = set()
            for item in self.file_table.selectedItems():
                selected_rows.add(item.row())
            
            # Remove in reverse order to maintain indices
            for row in sorted(selected_rows, reverse=True):
                if 0 <= row < len(self.selected_files):
                    self.selected_files.pop(row)
            
            self._update_file_table()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove files: {str(e)}")
    
    def _update_file_table(self):
        """Update the file table display"""
        try:
            self.file_table.setRowCount(len(self.selected_files))
            
            for row, file_path in enumerate(self.selected_files):
                # Filename
                filename = os.path.basename(file_path)
                self.file_table.setItem(row, 0, QTableWidgetItem(filename))
                
                # File size
                try:
                    size = os.path.getsize(file_path)
                    size_str = self._format_file_size(size)
                except:
                    size_str = "Unknown"
                self.file_table.setItem(row, 1, QTableWidgetItem(size_str))
                
                # File type
                extension = Path(file_path).suffix.upper() or "Unknown"
                self.file_table.setItem(row, 2, QTableWidgetItem(extension))
            
            # Update button states
            self.process_files_button.setEnabled(len(self.selected_files) > 0)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update file table: {str(e)}")
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def _on_selection_changed(self):
        """Handle file table selection changes"""
        has_selection = len(self.file_table.selectedItems()) > 0
        self.remove_selected_button.setEnabled(has_selection)
    
    def _process_files(self):
        """Process selected files with encryption or decryption"""
        try:
            if not self.selected_files:
                QMessageBox.warning(self, "Warning", "No files selected for processing.")
                return
            
            # Check if TOTP is set up
            totp_auth = get_totp_authenticator()
            if not totp_auth.is_setup_complete():
                # Show TOTP setup dialog
                setup_dialog = ImprovedTOTPSetupDialog(self)
                if setup_dialog.exec() != QDialog.Accepted:
                    return
            
            # Authenticate with TOTP
            operation = self.file_operation_combo.currentText()
            login_dialog = TOTPLoginDialog(self)
            if login_dialog.exec() != QDialog.Accepted:
                return
            
            master_password = login_dialog.get_master_password()
            if not master_password:
                return
            
            # Show progress bar
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Disable controls during processing
            self._set_controls_enabled(False)
            
            # Process files
            if operation == "Encrypt":
                successful, total = self.file_handler.encrypt_multiple_files(self.selected_files, master_password)
            else:  # Decrypt
                successful, total = self.file_handler.decrypt_multiple_files(self.selected_files, master_password)
            
            # Show results
            if successful == total:
                QMessageBox.information(self, "Success", f"All {total} files processed successfully.")
            else:
                QMessageBox.warning(self, "Partial Success", 
                                  f"{successful} of {total} files processed successfully.")
            
            # Clear processed files
            self.selected_files.clear()
            self._update_file_table()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"File processing failed: {str(e)}")
        
        finally:
            # Re-enable controls and hide progress bar
            self._set_controls_enabled(True)
            self.progress_bar.setVisible(False)
    
    def _set_controls_enabled(self, enabled):
        """Enable or disable controls during processing"""
        self.add_files_button.setEnabled(enabled)
        self.remove_selected_button.setEnabled(enabled and len(self.file_table.selectedItems()) > 0)
        self.process_files_button.setEnabled(enabled and len(self.selected_files) > 0)
        self.file_operation_combo.setEnabled(enabled)
    
    def _on_operation_completed(self, message, success):
        """Handle file operation completion"""
        # This is called for individual file operations
        pass
    
    def _on_progress_updated(self, progress):
        """Handle progress updates"""
        self.progress_bar.setValue(progress)
    
    def _show_audit_log(self):
        """Show the audit log dialog"""
        try:
            dialog = AuditLogDialog(self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open audit log: {str(e)}")


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.resize(1000, 700)
        
        self._setup_ui()
        self._apply_styles()

        # Make main window responsive
        self.setMinimumSize(800, 600)
        self.resize(1200, 800)  # Larger default size
        
        # Enable window resizing
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)
        self._center_window()
    
    def _setup_ui(self):
        """Setup the main UI layout"""
        # Create menu bar
        self._create_menu_bar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        # Application title
        title_label = QLabel(WINDOW_TITLE)
        title_label.setStyleSheet(f"""
            color: {COLOR_ACCENT};
            font-size: 18px;
            font-weight: bold;
            margin: 10px;
        """)
        header_layout.addWidget(title_label)
        
        # Version info
        version_label = QLabel("v1.0.0 - Secure Local Encryption with TOTP")
        version_label.setStyleSheet(f"""
            color: {COLOR_TEXT};
            font-size: 10px;
            margin: 10px;
        """)
        header_layout.addStretch()
        header_layout.addWidget(version_label)
        
        main_layout.addLayout(header_layout)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet(f"color: {COLOR_BORDER};")
        main_layout.addWidget(separator)
        
        # Main content area with splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Text operations (top section)
        self.text_widget = TextOperationsWidget()
        text_frame = QFrame()
        text_frame.setFrameStyle(QFrame.Box)
        text_frame.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }}
        """)
        text_layout = QVBoxLayout()
        text_layout.addWidget(self.text_widget)
        text_frame.setLayout(text_layout)
        splitter.addWidget(text_frame)
        
        # File operations (bottom section)
        self.file_widget = FileOperationsWidget()
        file_frame = QFrame()
        file_frame.setFrameStyle(QFrame.Box)
        file_frame.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }}
        """)
        file_layout = QVBoxLayout()
        file_layout.addWidget(self.file_widget)
        file_frame.setLayout(file_layout)
        splitter.addWidget(file_frame)
        
        # Set splitter proportions
        splitter.setSizes([300, 400])
        main_layout.addWidget(splitter)
        
        # Status bar
        self.statusBar().showMessage("Ready - EnigmaEcho SecureComm")
        self.statusBar().setStyleSheet(f"""
            QStatusBar {{
                background-color: {COLOR_SECONDARY};
                color: {COLOR_TEXT};
                border-top: 1px solid {COLOR_BORDER};
            }}
        """)
        
        central_widget.setLayout(main_layout)
    
    def _create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        
        # Security menu
        security_menu = menubar.addMenu("Security")
        
        # TOTP Setup action
        setup_totp_action = QAction("Setup TOTP Authentication", self)
        setup_totp_action.triggered.connect(self._setup_totp)
        security_menu.addAction(setup_totp_action)
        
        # Reset TOTP action
        reset_totp_action = QAction("Reset TOTP Configuration", self)
        reset_totp_action.triggered.connect(self._reset_totp)
        security_menu.addAction(reset_totp_action)
        
        security_menu.addSeparator()
        
        # Regenerate backup codes action
        regen_codes_action = QAction("Regenerate Backup Codes", self)
        regen_codes_action.triggered.connect(self._regenerate_backup_codes)
        security_menu.addAction(regen_codes_action)
        
        # View backup codes action
        view_codes_action = QAction("View Backup Codes", self)
        view_codes_action.triggered.connect(self._view_backup_codes)
        security_menu.addAction(view_codes_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        # Audit log action
        audit_log_action = QAction("View Audit Log", self)
        audit_log_action.triggered.connect(self._show_audit_log)
        tools_menu.addAction(audit_log_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        # About action
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_totp(self):
        """Show TOTP setup dialog"""
        try:
            totp_auth = get_totp_authenticator()
            if totp_auth.is_setup_complete():
                reply = QMessageBox.question(
                    self, "TOTP Already Setup",
                    "TOTP is already configured. Do you want to reconfigure it?\n\n"
                    "Warning: This will invalidate your current authenticator setup.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return
                
                # Reset existing TOTP
                totp_auth.reset_totp()
            
            # Show setup dialog
            setup_dialog = ImprovedTOTPSetupDialog(self)
            setup_dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to setup TOTP: {str(e)}")
    
    def _reset_totp(self):
        """Reset TOTP configuration"""
        try:
            totp_auth = get_totp_authenticator()
            if not totp_auth.is_setup_complete():
                QMessageBox.information(self, "No TOTP Configuration", "TOTP is not currently configured.")
                return
            
            reply = QMessageBox.question(
                self, "Confirm Reset",
                "Are you sure you want to reset TOTP configuration?\n\n"
                "This will:\n"
                "• Remove all TOTP settings\n"
                "• Invalidate backup codes\n"
                "• Require new setup before using the application\n\n"
                "This action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if totp_auth.reset_totp():
                    QMessageBox.information(self, "Reset Complete", "TOTP configuration has been reset.")
                else:
                    QMessageBox.warning(self, "Reset Failed", "Failed to reset TOTP configuration.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset TOTP: {str(e)}")
    
    def _regenerate_backup_codes(self):
        """Regenerate backup codes"""
        try:
            totp_auth = get_totp_authenticator()
            if not totp_auth.is_setup_complete():
                QMessageBox.information(self, "No TOTP Configuration", "TOTP is not currently configured.")
                return
            
            # Authenticate first
            login_dialog = TOTPLoginDialog(self)
            if login_dialog.exec() != QDialog.Accepted:
                return
            
            master_password = login_dialog.get_master_password()
            
            reply = QMessageBox.question(
                self, "Regenerate Backup Codes",
                "Are you sure you want to regenerate backup codes?\n\n"
                "This will invalidate all existing backup codes.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                new_codes = totp_auth.regenerate_backup_codes(master_password)
                backup_text = "\n".join(new_codes)
                
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Information)
                msg.setWindowTitle("New Backup Codes")
                msg.setText("New backup codes generated successfully!\n\nSave these securely:")
                msg.setDetailedText(backup_text)
                msg.exec()
                
        except TOTPError as e:
            QMessageBox.critical(self, "TOTP Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to regenerate backup codes: {str(e)}")
    
    def _view_backup_codes(self):
        """View current backup codes"""
        try:
            totp_auth = get_totp_authenticator()
            if not totp_auth.is_setup_complete():
                QMessageBox.information(self, "No TOTP Configuration", "TOTP is not currently configured.")
                return
            
            # Authenticate first
            login_dialog = TOTPLoginDialog(self)
            if login_dialog.exec() != QDialog.Accepted:
                return
            
            master_password = login_dialog.get_master_password()
            backup_codes = totp_auth.get_backup_codes(master_password)
            
            if not backup_codes:
                QMessageBox.information(self, "No Backup Codes", "No backup codes are available.")
                return
            
            backup_text = "\n".join(backup_codes)
            
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Backup Codes")
            msg.setText(f"Current backup codes ({len(backup_codes)} remaining):")
            msg.setDetailedText(backup_text)
            msg.exec()
            
        except TOTPError as e:
            QMessageBox.critical(self, "TOTP Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to view backup codes: {str(e)}")
    
    def _show_audit_log(self):
        """Show audit log dialog"""
        try:
            dialog = AuditLogDialog(self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open audit log: {str(e)}")
    
    def _show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>EnigmaEcho SecureComm</h2>
        <p><b>Version:</b> 1.0.0</p>
        <p><b>Secure Local Encryption with TOTP Authentication</b></p>
        
        <h3>Security Features:</h3>
        <ul>
        <li>AES-256-GCM Encryption</li>
        <li>PBKDF2-HMAC-SHA256 Key Derivation (480,000+ iterations)</li>
        <li>TOTP Two-Factor Authentication</li>
        <li>HMAC-SHA256 Authentication Tags</li>
        <li>Secure Audit Logging</li>
        </ul>
        
        <h3>Compliance:</h3>
        <ul>
        <li>NIST SP 800-63B Digital Identity Guidelines</li>
        <li>NIST SP 800-57 Cryptographic Key Management</li>
        <li>OWASP Cryptographic Storage Guidelines</li>
        </ul>
        
        <p><b>Local-Only Processing • No Cloud • No Compromise</b></p>
        """
        
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("About EnigmaEcho SecureComm")
        msg.setText(about_text)
        msg.exec()
    
    def _apply_styles(self):
        """Apply the dark theme styles"""
        self.setStyleSheet(f"""

            /* Responsive text areas */
            QTextEdit {
                min-height: 100px;
                max-height: none;
            }
            
            /* Responsive tables */
            QTableWidget {
                min-height: 150px;
            }
            
            /* Responsive buttons */
            QPushButton {
                min-height: 32px;
                padding: 8px 16px;
            }
            
            /* Responsive dropdowns */
            QComboBox {
                min-height: 28px;
                min-width: 100px;
            }
            QMainWindow {{
                background-color: {COLOR_BG};
                color: {COLOR_TEXT};
                font-family: {FONT_FAMILY};
                font-size: {FONT_SIZE}pt;
            }}
            QLabel {{
                color: {COLOR_TEXT};
            }}
            QSplitter::handle {{
                background-color: {COLOR_BORDER};
                height: 3px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """)
    
    def _center_window(self):
        """Center the window on the screen"""
        try:
            screen = QApplication.primaryScreen()
            if screen:
                screen_geometry = screen.availableGeometry()
                window_geometry = self.frameGeometry()
                center_point = screen_geometry.center()
                window_geometry.moveCenter(center_point)
                self.move(window_geometry.topLeft())
        except Exception:
            # Fallback if centering fails
            pass
    
    def closeEvent(self, event):
        """Handle application close event"""
        try:
            # Confirm exit
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Are you sure you want to exit EnigmaEcho SecureComm?\n\nAll audit logs will be securely wiped.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Perform cleanup
                audit_log = get_audit_log()
                audit_log.wipe_logs()
                
                # Log application exit
                log_operation("Application Exit", "SUCCESS", "TEXT")
                
                event.accept()
            else:
                event.ignore()
                
        except Exception as e:
            # If cleanup fails, still allow exit
            print(f"Cleanup error on exit: {str(e)}")
            event.accept()


def create_application():
    """Create and configure the QApplication"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName(WINDOW_TITLE)
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("EnigmaEcho Security")
    
    # Set application font
    font = QFont(FONT_FAMILY, FONT_SIZE)
    app.setFont(font)
    
    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(COLOR_BG))
    palette.setColor(QPalette.WindowText, QColor(COLOR_TEXT))
    palette.setColor(QPalette.Base, QColor(COLOR_SECONDARY))
    palette.setColor(QPalette.AlternateBase, QColor(COLOR_BG))
    palette.setColor(QPalette.ToolTipBase, QColor(COLOR_SECONDARY))
    palette.setColor(QPalette.ToolTipText, QColor(COLOR_TEXT))
    palette.setColor(QPalette.Text, QColor(COLOR_TEXT))
    palette.setColor(QPalette.Button, QColor(COLOR_SECONDARY))
    palette.setColor(QPalette.ButtonText, QColor(COLOR_TEXT))
    palette.setColor(QPalette.BrightText, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.Link, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.Highlight, QColor(COLOR_ACCENT))
    palette.setColor(QPalette.HighlightedText, QColor("white"))
    
    app.setPalette(palette)
    
    return app
