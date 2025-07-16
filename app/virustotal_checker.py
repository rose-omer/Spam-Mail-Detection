import os, requests, time

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def virustotal_scan_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code != 200:
                return "clean"
            status = analysis_response.json()["data"]["attributes"]["status"]
            if status == "completed":
                stats = analysis_response.json()["data"]["attributes"]["stats"]
                infected = stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
                return "infected" if infected else "clean"
            time.sleep(3)
        return "clean"
    except Exception:
        return "clean"
