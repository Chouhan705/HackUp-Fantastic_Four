import imaplib
import email
import hashlib
import sqlite3
from datetime import datetime, timedelta
from email.header import decode_header
import logging
from src.core.config import IMAP_SERVER, IMAP_PORT, IMAP_USER, IMAP_PASS, QUARANTINE_DIR
from src.db.database import get_db_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def clean_header(header_value):
    """Decodes email headers (like subjects) into standard strings."""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or 'utf-8', errors='ignore')
        else:
            result += part
    return result


def process_inbox(days_back=3):
    """
    Connects to IMAP, fetches recent unread emails, and extracts attachments safely.
    Only processes emails from the last `days_back` days (default: 3).
    """
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("inbox")

        # Only fetch UNSEEN emails from the last N days
        date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        status, messages = mail.search(None, f'(UNSEEN SINCE {date_since})')

        if status != "OK":
            logger.error("Failed to search emails.")
            return {"error": "Failed to search inbox"}

        email_ids = messages[0].split()
        if not email_ids:
            logger.info("No new emails to process.")
            return {"status": "success", "processed": 0}

        logger.info(f"Found {len(email_ids)} new email(s) since {date_since}.")

        conn = get_db_connection()
        cursor = conn.cursor()
        processed_count = 0

        for e_id in email_ids:
            # Fetch full email body without marking as read yet
            res, msg_data = mail.fetch(e_id, "(BODY.PEEK[])")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    subject = clean_header(msg.get("Subject"))
                    sender = clean_header(msg.get("From"))
                    date_recv = msg.get("Date")

                    uid = e_id.decode('utf-8')
                    logger.info(f"Processing email UID={uid} | From: {sender} | Subject: {subject}")

                    try:
                        cursor.execute(
                            "INSERT INTO emails (uid, sender, subject, date_received) VALUES (?, ?, ?, ?)",
                            (uid, sender, subject, date_recv)
                        )
                        db_email_id = cursor.lastrowid
                    except sqlite3.IntegrityError:
                        logger.info(f"Email {uid} already processed. Skipping.")
                        # Still mark as seen so it doesn't keep showing up
                        mail.store(e_id, '+FLAGS', '\\Seen')
                        continue

                    # Walk through the email parts to find attachments
                    has_attachment = False
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_maintype() == 'multipart':
                                continue
                            if part.get('Content-Disposition') is None:
                                continue

                            filename = part.get_filename()
                            if filename:
                                filename = clean_header(filename)
                                payload = part.get_payload(decode=True)

                                if payload:
                                    has_attachment = True
                                    sha256_hash = hashlib.sha256(payload).hexdigest()
                                    safe_filepath = QUARANTINE_DIR / sha256_hash

                                    # Save to quarantine
                                    with open(safe_filepath, "wb") as f:
                                        f.write(payload)

                                    # Log attachment in DB
                                    try:
                                        cursor.execute(
                                            """INSERT INTO attachments 
                                               (email_id, filename, sha256, status) 
                                               VALUES (?, ?, ?, 'pending_analysis')""",
                                            (db_email_id, filename, sha256_hash)
                                        )
                                        logger.info(f"Quarantined: {filename} -> {sha256_hash}")
                                    except sqlite3.IntegrityError:
                                        logger.info(f"Attachment {sha256_hash} already exists. Skipping.")

                    if not has_attachment:
                        logger.info(f"No attachments found in email UID={uid}.")

                    processed_count += 1

            # Mark email as seen after processing
            mail.store(e_id, '+FLAGS', '\\Seen')

        conn.commit()
        conn.close()
        mail.logout()

        logger.info(f"Done. Processed {processed_count} email(s).")
        return {"status": "success", "processed": processed_count}

    except Exception as e:
        logger.error(f"IMAP Error: {e}")
        return {"error": str(e)}