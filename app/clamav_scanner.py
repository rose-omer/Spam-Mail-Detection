import subprocess

def clamav_scan_file(file_path):
    result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout
    infected = "Infected files: 0" not in output
    return "infected" if infected else "clean"
