"""
Configuration settings for SecretService
"""
from pathlib import Path
from typing import Dict, Tuple
from pydantic import BaseSettings
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Email Server Settings
    SMTP_SERVERS: Dict[str, Tuple[str, int]] = {
        'gmail': ('smtp.gmail.com', 587),
        'microsoft': ('smtp.office365.com', 587),
        'yahoo': ('smtp.mail.yahoo.com', 587)
    }
    
    IMAP_SERVERS: Dict[str, Tuple[str, int]] = {
        'gmail': ('imap.gmail.com', 993),
        'microsoft': ('outlook.office365.com', 993),
        'yahoo': ('imap.mail.yahoo.com', 993)
    }
    
    # File Paths
    BASE_DIR: Path = Path(__file__).parent
    CHAFFE_FILE: Path = BASE_DIR / 'chaffe.csv'
    PUBKEYS_FILE: Path = BASE_DIR / '.pubkeys'
    SECRET_SERVICE_FILE: Path = BASE_DIR / '.SecretService'
    FONT_FILE: Path = BASE_DIR / 'CaviarDreams.ttf'
    LOGO_FILE: Path = BASE_DIR / 'logo.png'
    
    # UI Settings
    WINDOW_SIZE: Tuple[int, int] = (1920, 1080)
    WINDOW_POSITION: Tuple[int, int] = (0, 0)
    THEME: str = 'Black'
    
    # Security Settings
    MIN_PASSWORD_LENGTH: int = 12
    KEY_EXCHANGE_TIMEOUT: int = 300  # seconds
    MAX_LOGIN_ATTEMPTS: int = 3
    RATE_LIMIT_WINDOW: int = 3600  # seconds
    MAX_REQUESTS_PER_WINDOW: int = 100
    
    # Email Settings
    MAX_SUBJECT_LENGTH: int = 200
    MAX_MESSAGE_LENGTH: int = 10000
    EMAIL_FETCH_DAYS: int = 30
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings() 