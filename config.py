"""
Configuration file for EnigmaEcho SecureComm
Contains UI themes, cryptographic settings, and global constants
"""

# UI Theme Colors
COLOR_BG = "#1e1e1e"  # Dark background
COLOR_ACCENT = "#7fb3d5"  # Silver-blue accent
COLOR_DROPDOWN = "#ffffff"  # White dropdown background
COLOR_TEXT = "#ffffff"  # White text
COLOR_SECONDARY = "#2d2d2d"  # Secondary dark color
COLOR_BORDER = "#404040"  # Border color
COLOR_HOVER = "#5a9fd4"  # Hover color (darker blue)

# Cryptographic Settings
AES_MODE = "AES-256-GCM"
PBKDF2_ITERATIONS = 480000  # NIST recommended minimum
SALT_LENGTH = 16  # bytes
NONCE_LENGTH = 12  # bytes for GCM
HMAC_KEY_LENGTH = 32  # bytes for HMAC-SHA256
ENCRYPTION_KEY_LENGTH = 32  # bytes for AES-256

# UI Constants
WINDOW_TITLE = "EnigmaEcho SecureComm"
WINDOW_MIN_WIDTH = 800
WINDOW_MIN_HEIGHT = 600
FONT_FAMILY = "Segoe UI, Arial, sans-serif"
FONT_SIZE = 10

# Text Placeholders
TEXT_INPUT_PLACEHOLDER = "Input here..."
TEXT_OUTPUT_PLACEHOLDER = "Output will appear here..."

# Dropdown Options
OPERATION_OPTIONS = ["Encrypt", "Decrypt"]
OUTPUT_OPTIONS = ["Copy to Clipboard", "Copy to File"]

# File Extensions
ENCRYPTED_FILE_EXTENSION = ".enc"
LOG_FILE_EXTENSION = ".log"

# Security Settings
MAX_LOG_ENTRIES = 1000
AUTO_WIPE_ON_EXIT = True
SECURE_MEMORY_WIPE = True

# Session Management
SESSION_TIMEOUT = 1800  # 30 minutes in seconds

# Application Metadata
APP_VERSION = "1.0.0"
APP_AUTHOR = "EnigmaEcho Security"
