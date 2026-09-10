from pathlib import Path
import os

APP_NAME = "Forensic Data Guard"
APP_VERSION = "4.0.3"
DATA_DIR = Path(os.getenv("LOCALAPPDATA", Path.home() / ".forensic_data_guard")) / "ForensicDataGuard"
DB_PATH = DATA_DIR / "forensic_guard.db"
LOG_PATH = DATA_DIR / "logs" / "application.log"
EVIDENCE_DIR = DATA_DIR / "evidence"
LOCKOUT_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PASSWORD_MIN_LENGTH = 8
