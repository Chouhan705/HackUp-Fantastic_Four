import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
QUARANTINE_DIR = BASE_DIR / os.getenv("QUARANTINE_DIR", "quarantine")
DB_PATH = BASE_DIR / os.getenv("DB_PATH", "phish_pipeline.db")

# Ensure quarantine folder exists
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# IMAP Settings
IMAP_SERVER = os.getenv("IMAP_SERVER")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
IMAP_USER = os.getenv("IMAP_USER")
IMAP_PASS = os.getenv("IMAP_PASS")