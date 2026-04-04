import imaplib, os
from dotenv import load_dotenv

load_dotenv('d:/Projects/HackUp-Fantastic_Four/test3/.env')
mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
mail.login(os.getenv('IMAP_USER'), os.getenv('IMAP_PASS'))
mail.select('inbox')
status, msgs = mail.search(None, 'ALL')
if msgs[0]:
    recent = msgs[0].split()[-1]
    res, data = mail.fetch(recent, '(X-GM-MSGID)')
    print('Fetched X-GM-MSGID:', data)
