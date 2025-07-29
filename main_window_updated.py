"""
Updated Main Window with responsive layout and session management
Implements proper layout managers and session-based access control
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QFrame, QLabel, QMessageBox, QMenuBar, QMenu, QSizePolicy,
    QTextEdit, QComboBox, QPushButton, QTableWidget, QHeaderView,
    QTableWidgetItem, QFileDialog
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction

from totp_auth import get_totp_authenticator, TOTPError
from session_manager import get_session_manager
from totp_setup_improved import ImprovedTOTPSetupDialog
from totp_login_updated import UpdatedTOTPLoginDialog
from audit_log import get_audit_log
from config import (
    COLOR_BG, COLOR_ACCENT, COLOR_TEXT, COLOR_SECONDARY, COLOR_BORDER,
    WINDOW_TITLE, FONT_FAMILY, FONT_SIZE
)


class TextOperationsWidget(QWidget):
    """Updated text operations widget with session management"""
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Text Operations")
        title.setStyleSheet(f"""
            color: {COLOR_TEXT}; 
            font-size: 16px; 
            font-weight: bold; 
            margin-bottom: 15px;
            padding: 10px;
        """)
        layout.addWidget(title)
        
        # Main content area with splitter for responsive design
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Input section
        input_widget = QWidget()
        input_layout = QVBoxLayout()
        
        input_label = QLabel("Input:")
        input_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; font-weight: bold;")
        input_layout.addWidget(input_label)
        
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt or decrypt...")
        self.text_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        input_layout.addWidget(self.text_input)
        
        input_widget.setLayout(input_layout)
        content_splitter.addWidget(input_widget)
        
        # Output section
        output_widget = QWidget()
        output_layout = QVBoxLayout()
        
        output_label = QLabel("Output:")
        output_label.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 12px; font-weight: bold;")
        output_layout.addWidget(output_label)
        
        self.text_output = QTextEdit()
        self.text_output.setPlaceholderText("Output will appear here...")
        self.text_output.setReadOnly(True)
        self.text_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        output_layout.addWidget(self.text_output)
        
        output_widget.setLayout(output_layout)
        content_splitter.addWidget(output_widget)
        
        # Set equal sizes for input/output
        content_splitter.setSizes([400, 400])
        layout.addWidget(content_splitter)
        
        # Controls section
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(15)
        
        self.operation_combo = QComboBox()
        self.operation_combo.addItems(["Encrypt", "Decrypt"])
        self.operation_combo.setMinimumWidth(120)
        controls_layout.addWidget(self.operation_combo)
        
        self.process_button = QPushButton("Process Text")
        self.process_button.clicked.connect(self._process_text)
        self.process_button.setMinimumHeight(35)
        controls_layout.addWidget(self.process_button)
        
        controls_layout.addStretch()
        
        self.output_combo = QComboBox()
        self.output_combo.addItems(["Copy to Clipboard", "Save to File"])
        self.output_combo.setMinimumWidth(120)
        controls_layout.addWidget(self.output_combo)
        
        self.output_button = QPushButton("Execute Action")
        self.output_button.clicked.connect(self._execute_output_action)
        self.output_button.setMinimumHeight(35)
        controls_layout.addWidget(self.output_button)
        
        layout.addLayout(controls_layout)
        self.setLayout(layout)
    
    def _apply_styles(self):
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_SECONDARY};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 10px;
                color: {COLOR_TEXT};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                min-height: 150px;
            }}
            QTextEdit:focus {{
                border-color: {COLOR_ACCENT};
                border-width: 2px;
            }}
            QComboBox {{
                background-color: white;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
                color: black;
                font-size: 11px;
                font-weight: 500;
            }}
            QComboBox:hover {{
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
                background-color: #5a9fd4;
            }}
        """)
    
    def _process_text(self):
        """Process text with session management"""
        try:
            # Check session first
            session_manager = get_session_manager()
            if not session_manager.is_session_active():
                login_dialog = UpdatedTOTPLoginDialog(self)
                if login_dialog.exec() != login_dialog.Accepted:
                    return
            else:
                session_manager.update_session()
            
            input_text = self.text_input.toPlainText().strip()
            if not input_text:
                QMessageBox.warning(self, "Warning", "Please enter text to process.")
                return
            
            # For demo purposes, show a message
            operation = self.operation_combo.currentText()
            QMessageBox.information(self, "Processing", 
                                  f"Would {operation.lower()} the text here.\n"
                                  "Cryptographic implementation would go here.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Text processing failed: {str(e)}")
    
    def _execute_output_action(self):
        """Execute output action"""
        try:
            output_text = self.text_output.toPlainText().strip()
            if not output_text:
                QMessageBox.warning(self, "Warning", "No output text to process.")
                return
            
            action = self.output_combo.currentText()
            
            if action == "Copy to Clipboard":
                try:
                    import pyperclip
                    pyperclip.copy(output_text)
                    QMessageBox.information(self, "Success", "Text copied to clipboard.")
                except ImportError:
                    QMessageBox.information(self, "Demo", "Would copy text to clipboard.")
            else:  # Save to File
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "Save Text to File", "output.txt", "Text Files (*.txt);;All Files (*)"
                )
                
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(output_text)
                    QMessageBox.information(self, "Success", f"Text saved to: {file_path}")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Output action failed: {str(e)}")


class FileOperationsWidget(QWidget):
    """Updated file operations widget with session management"""
    
    def __init__(self):
        super().__init__()
        self.selected_files = []
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Title
        title = QLabel("File Operations")
        title.setStyleSheet(f"""
            color: {COLOR_TEXT}; 
            font-size: 16px; 
            font-weight: bold; 
            margin-bottom: 15px;
            padding: 10px;
        """)
        layout.addWidget(title)
        
        # File controls
        file_controls = QHBoxLayout()
        file_controls.setSpacing(10)
        
        self.add_files_button = QPushButton("Add Files")
        self.add_files_button.clicked.connect(self._add_files)
        self.add_files_button.setMinimumHeight(35)
        
        self.remove_selected_button = QPushButton("Remove Selected")
        self.remove_selected_button.clicked.connect(self._remove_selected)
        self.remove_selected_button.setEnabled(False)
        self.remove_selected_button.setMinimumHeight(35)
        
        file_controls.addWidget(self.add_files_button)
        file_controls.addWidget(self.remove_selected_button)
        file_controls.addStretch()
        
        layout.addLayout(file_controls)
        
        # File table with responsive design
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(3)
        self.file_table.setHorizontalHeaderLabels(["Filename", "Size", "Type"])
        self.file_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.file_table.itemSelectionChanged.connect(self._on_selection_changed)
        
        # Configure table for responsive design
        header = self.file_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        self.file_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.file_table.setMinimumHeight(200)
        layout.addWidget(self.file_table)
        
        # Operation controls
        operation_layout = QHBoxLayout()
        operation_layout.setSpacing(15)
        
        self.file_operation_combo = QComboBox()
        self.file_operation_combo.addItems(["Encrypt", "Decrypt"])
        self.file_operation_combo.setMinimumWidth(120)
        operation_layout.addWidget(self.file_operation_combo)
        
        self.process_files_button = QPushButton("Process Files")
        self.process_files_button.clicked.connect(self._process_files)
        self.process_files_button.setEnabled(False)
        self.process_files_button.setMinimumHeight(35)
        operation_layout.addWidget(self.process_files_button)
        
        operation_layout.addStretch()
        
        self.audit_log_button = QPushButton("View Audit Log")
        self.audit_log_button.clicked.connect(self._show_audit_log)
        self.audit_log_button.setMinimumHeight(35)
        operation_layout.addWidget(self.audit_log_button)
        
        layout.addLayout(operation_layout)
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
                border-radius: 6px;
            }}
            QHeaderView::section {{
                background-color: {COLOR_ACCENT};
                color: white;
                padding: 10px;
                border: none;
                font-weight: bold;
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
                background-color: #5a9fd4;
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: #888888;
            }}
            QComboBox {{
                background-color: white;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
                color: black;
                font-size: 11px;
                font-weight: 500;
            }}
        """)
    
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
            
            for row in sorted(selected_rows, reverse=True):
                if 0 <= row < len(self.selected_files):
                    self.selected_files.pop(row)
            
            self._update_file_table()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove files: {str(e)}")
    
    def _update_file_table(self):
        """Update the file table display"""
        try:
            import os
            from pathlib import Path
            
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
        """Process files with session management"""
        try:
            if not self.selected_files:
                QMessageBox.warning(self, "Warning", "No files selected for processing.")
                return
            
            # Check session first
            session_manager = get_session_manager()
            if not session_manager.is_session_active():
                login_dialog = UpdatedTOTPLoginDialog(self)
                if login_dialog.exec() != login_dialog.Accepted:
                    return
            else:
                session_manager.update_session()
            
            operation = self.file_operation_combo.currentText()
            
            # Process files (demo)
            QMessageBox.information(self, "Processing", 
                                  f"Would process {len(self.selected_files)} files with {operation} operation.\n"
                                  "File processing implementation would go here.")
            
            # Clear processed files
            self.selected_files.clear()
            self._update_file_table()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"File processing failed: {str(e)}")
    
    def _show_audit_log(self):
        """Show audit log dialog"""
        try:
            QMessageBox.information(self, "Audit Log", "Audit log dialog would open here.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open audit log: {str(e)}")


class UpdatedMainWindow(QMainWindow):
    """Updated main window with responsive layout and session management"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        
        # Responsive window sizing
        self.setMinimumSize(900, 700)
        self.resize(1200, 900)
        
        # Enable window resizing
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)
        
        self._setup_ui()
        self._apply_styles()
        self._setup_session_timer()
        self._center_window()
    
    def _setup_ui(self):
        """Setup the responsive UI layout"""
        # Create menu bar
        self._create_menu_bar()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with better spacing
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        
        # Header with responsive design
        header_layout = QHBoxLayout()
        
        # Application title
        title_label = QLabel(WINDOW_TITLE)
        title_label.setStyleSheet(f"""
            color: {COLOR_ACCENT};
            font-size: 20px;
            font-weight: bold;
            margin: 15px;
        """)
        header_layout.addWidget(title_label)
        
        # Session status
        self.session_status_label = QLabel("Session: Not Active")
        self.session_status_label.setStyleSheet(f"""
            color: {COLOR_TEXT};
            font-size: 11px;
            margin: 15px;
        """)
        header_layout.addStretch()
        header_layout.addWidget(self.session_status_label)
        
        main_layout.addLayout(header_layout)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet(f"color: {COLOR_BORDER};")
        main_layout.addWidget(separator)
        
        # Main content area with responsive splitter
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        
        # Text operations (top section)
        self.text_widget = TextOperationsWidget()
        text_frame = QFrame()
        text_frame.setFrameStyle(QFrame.Box)
        text_frame.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                margin: 5px;
                padding: 15px;
                background-color: {COLOR_BG};
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
                padding: 15px;
                background-color: {COLOR_BG};
            }}
        """)
        file_layout = QVBoxLayout()
        file_layout.addWidget(self.file_widget)
        file_frame.setLayout(file_layout)
        splitter.addWidget(file_frame)
        
        # Set responsive proportions (40% text, 60% files)
        splitter.setSizes([400, 600])
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.statusBar().showMessage("Ready - EnigmaEcho SecureComm")
        self.statusBar().setStyleSheet(f"""
            QStatusBar {{
                background-color: {COLOR_SECONDARY};
                color: {COLOR_TEXT};
                border-top: 1px solid {COLOR_BORDER};
                padding: 5px;
            }}
        """)
        
        central_widget.setLayout(main_layout)
    
    def _create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        
        # Security menu
        security_menu = menubar.addMenu("Security")
        
        setup_totp_action = QAction("Setup TOTP Authentication", self)
        setup_totp_action.triggered.connect(self._setup_totp)
        security_menu.addAction(setup_totp_action)
        
        reset_totp_action = QAction("Reset TOTP Configuration", self)
        reset_totp_action.triggered.connect(self._reset_totp)
        security_menu.addAction(reset_totp_action)
        
        security_menu.addSeparator()
        
        session_menu = security_menu.addMenu("Session")
        
        end_session_action = QAction("End Current Session", self)
        end_session_action.triggered.connect(self._end_session)
        session_menu.addAction(end_session_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        audit_log_action = QAction("View Audit Log", self)
        audit_log_action.triggered.connect(self._show_audit_log)
        tools_menu.addAction(audit_log_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_session_timer(self):
        """Setup timer to monitor session status"""
        self.session_timer = QTimer()
        self.session_timer.timeout.connect(self._update_session_status)
        self.session_timer.start(5000)  # Update every 5 seconds
        self._update_session_status()
    
    def _update_session_status(self):
        """Update session status display"""
        try:
            session_manager = get_session_manager()
            if session_manager.is_session_active():
                remaining = session_manager.get_session_time_remaining()
                minutes = remaining // 60
                seconds = remaining % 60
                self.session_status_label.setText(f"Session: Active ({minutes}:{seconds:02d} remaining)")
                self.session_status_label.setStyleSheet(f"""
                    color: #28a745;
                    font-size: 11px;
                    margin: 15px;
                    font-weight: bold;
                """)
            else:
                self.session_status_label.setText("Session: Not Active")
                self.session_status_label.setStyleSheet(f"""
                    color: #dc3545;
                    font-size: 11px;
                    margin: 15px;
                """)
        except Exception:
            self.session_status_label.setText("Session: Unknown")
    
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
                
                totp_auth.reset_totp()
            
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
                "• End current session\n"
                "• Require new setup before using the application\n\n"
                "This action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if totp_auth.reset_totp():
                    session_manager = get_session_manager()
                    session_manager.end_session()
                    
                    QMessageBox.information(self, "Reset Complete", "TOTP configuration has been reset.")
                else:
                    QMessageBox.warning(self, "Reset Failed", "Failed to reset TOTP configuration.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset TOTP: {str(e)}")
    
    def _end_session(self):
        """End the current session"""
        try:
            session_manager = get_session_manager()
            if session_manager.is_session_active():
                reply = QMessageBox.question(
                    self, "End Session",
                    "Are you sure you want to end the current session?\n\n"
                    "You will need to authenticate again to use the application.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    session_manager.end_session()
                    QMessageBox.information(self, "Session Ended", "Your session has been ended.")
            else:
                QMessageBox.information(self, "No Active Session", "There is no active session to end.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to end session: {str(e)}")
    
    def _show_audit_log(self):
        """Show audit log dialog"""
        try:
            QMessageBox.information(self, "Audit Log", "Audit log dialog would open here.")
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
        <li>TOTP Two-Factor Authentication with Session Management</li>
        <li>HMAC-SHA256 Authentication Tags</li>
        <li>Secure Audit Logging</li>
        <li>30-minute Session Timeout</li>
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
        """Apply the responsive dark theme styles"""
        self.setStyleSheet(f"""
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
            QMenuBar {{
                background-color: {COLOR_SECONDARY};
                color: {COLOR_TEXT};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            QMenuBar::item {{
                background-color: transparent;
                padding: 8px 12
