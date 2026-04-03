import sqlite3
import json
from src.core.config import DB_PATH

def get_db_connection():
    """Returns a dictionary-like SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates the necessary tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Emails table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE,
            sender TEXT,
            subject TEXT,
            date_received TEXT
        )
    """)

    # Attachments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            filename TEXT,
            sha256 TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            risk_score INTEGER DEFAULT 0,
            FOREIGN KEY(email_id) REFERENCES emails(id)
        )
    """)

    # Analysis Results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attachment_sha256 TEXT,
            analyzer_name TEXT,
            is_flagged BOOLEAN,
            raw_output TEXT,
            FOREIGN KEY(attachment_sha256) REFERENCES attachments(sha256)
        )
    """)

    conn.commit()
    conn.close()

# Initialize on import
init_db()