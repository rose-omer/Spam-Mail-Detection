import imaplib
import email
import re
import chardet
import os
import requests
from dotenv import load_dotenv
from email.header import decode_header
from email.utils import parseaddr

load_dotenv()

IMAP_SERVER = 'imap.gmail.com'
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
PASSWORD = os.getenv("EMAIL_PASSWORD")
API_URL = 'http://localhost:5000/predict'


def decode_email_body(raw_bytes):
    try:
        return raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        detected = chardet.detect(raw_bytes)
        encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
        try:
            return raw_bytes.decode(encoding)
        except Exception:
            return raw_bytes.decode('utf-8', errors='ignore')


def extract_url_from_text(text):
    urls = re.findall(r'https?://\S+', text)
    return urls[0] if urls else ""


def decode_mime_words(s):
    decoded_words = decode_header(s)
    return ''.join([
        part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part
        for part, encoding in decoded_words
    ])


def fetch_last_unread_email():
    print("🔐 Giriş yapılıyor...")
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, PASSWORD)
    mail.select('inbox')

    status, data = mail.search(None, '(UNSEEN)')
    mail_ids = data[0].split()

    if not mail_ids:
        print("📭 Hiç yeni mail yok.")
        mail.logout()
        return None

    last_mail_id = mail_ids[-1]

    print(f"📥 Son yeni mail işleniyor: ID {last_mail_id}")
    status, msg_data = mail.fetch(last_mail_id, '(RFC822)')

    email_data = None

    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            raw_headers = ""
            for header, value in msg.items():
                raw_headers += f"{header}: {value}\n"

            subject = decode_mime_words(msg['subject'])
            from_raw = msg['from']
            from_email = parseaddr(from_raw)[1]  # sadece e-posta adresi kısmı alınır

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition'))

                    if content_type == 'text/plain' and 'attachment' not in content_disposition:
                        raw_payload = part.get_payload(decode=True)
                        body = decode_email_body(raw_payload)
                        break
            else:
                raw_payload = msg.get_payload(decode=True)
                body = decode_email_body(raw_payload)

            ek_link = extract_url_from_text(body)

            email_data = {
                'from': from_email,
                'subject': subject,
                'body': body,
                'ek': ek_link,
                'headers': raw_headers
            }

            print(f"✅ Eklendi: {subject}")

    mail.logout()
    return email_data


def send_to_api(mail):
    data = {
        'text': mail['body'],
        'ek': mail.get('ek', ''),
        'sender': mail.get('from', ''),
        'headers': mail.get('headers', ''),
        'subject': mail.get('subject', '')
    }

    try:
        resp = requests.post(API_URL, json=data)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {'error': f'API isteği başarısız: {str(e)}'}


if __name__ == '__main__':
    print("🚀 Mail kontrol başlatılıyor...")
    mail = fetch_last_unread_email()

    if not mail:
        print("📭 Hiç yeni mail yok.")
    else:
        print("=" * 50)
        print(f"From: {mail['from']}")
        print(f"Subject: {mail['subject']}")
        print(f"Body:\n{mail['body']}")

        if mail.get('ek'):
            print(f"Ek var: {mail['ek']}")
        else:
            print("Ek yok.")

        print("\n🛡️ Spam ve Virüs kontrolü yapılıyor...")
        result = send_to_api(mail)
        if 'error' in result:
            print(f"‼️ Hata: {result['error']}")
        else:
            print(f"\n📊 Analiz Sonucu:")
            for key, value in result.items():
                print(f"- {key}: {value}")
            sim = result.get('subject_body_similarity', None)
            if sim and isinstance(sim, float):
                if sim < 0.3:
                    print("⚠️ Mail başlığı ile içerik arasında uyumsuzluk tespit edildi!")
                else:
                    print("✅ Mail başlığı ile içerik uyumlu.")
