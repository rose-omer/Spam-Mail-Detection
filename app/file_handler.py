import os
import uuid
import requests
from app.clamav_scanner import clamav_scan_file
from app.virustotal_checker import virustotal_scan_file

TEMP_DIR = "/tmp"
os.makedirs(TEMP_DIR, exist_ok=True)

def download_and_scan_attachment(url):
    try:
        file_name = os.path.join(TEMP_DIR, f"{uuid.uuid4().hex}")
        headers = {'User-Agent': 'Mozilla/5.0'}
        with requests.get(url, headers=headers, stream=True, timeout=10) as r:
            r.raise_for_status()
            with open(file_name, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        clamav_result = clamav_scan_file(file_name)
        virustotal_result = virustotal_scan_file(file_name)
        os.remove(file_name)
        return {
            "clamav": {"status": clamav_result},
            "virustotal": {"status": virustotal_result}
        }
    except Exception as e:
        return {"error": f"Hata: Dosya indirilemedi veya taranamadı. {str(e)}"}
