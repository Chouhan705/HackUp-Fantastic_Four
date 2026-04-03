import imaplib
import email
import hashlib
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

def process_inbox():
    """Connects to IMAP, fetches unread emails, and extracts attachments safely."""
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(IMAP_USER, IMAP_PASS)
        mail.select("inbox")

        # Search for UNREAD emails
        status, messages = mail.search(None, "UNREAD")
        if status != "OK":
            logger.error("Failed to search emails.")
            return {"error": "Failed to search inbox"}

        email_ids = messages[0].split()
        if not email_ids:
            logger.info("No new emails to process.")
            return {"status": "success", "processed": 0}

        conn = get_db_connection()
        cursor = conn.cursor()
        processed_count = 0

        for e_id in email_ids:
            # Fetch the email body
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    subject = clean_header(msg.get("Subject"))
                    sender = clean_header(msg.get("From"))
                    date_recv = msg.get("Date")
                    
                    # Insert email into DB (use the email ID as UID for now)
                    uid = e_id.decode('utf-8')
                    try:
                        cursor.execute(
                            "INSERT INTO emails (uid, sender, subject, date_received) VALUES (?, ?, ?, ?)",
                            (uid, sender, subject, date_recv)
                        )
                        db_email_id = cursor.lastrowid
                    except sqlite3.IntegrityError:
                        logger.info(f"Email {uid} already processed. Skipping.")
                        continue

                    # Walk through the email parts to find attachments
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
                                    # Safety first: Hash the file, use hash as filename
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
                                        logger.info(f"Attachment {sha256_hash} already exists.")

                    processed_count += 1

        conn.commit()
        conn.close()
        mail.logout()
        return {"status": "success", "processed": processed_count}

    except Exception as e:
        logger.error(f"IMAP Error: {e}")
        return {"error": str(e)}