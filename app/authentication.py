import re

def analyze_authentication(headers_text):
    result = {'spf': 'bilinmiyor', 'dkim': 'bilinmiyor', 'dmarc': 'bilinmiyor'}
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', headers_text, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(pass|fail|neutral|none)', headers_text, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(pass|fail|bestguesspass)', headers_text, re.IGNORECASE)
    if spf_match: result['spf'] = spf_match.group(1).lower()
    if dkim_match: result['dkim'] = dkim_match.group(1).lower()
    if dmarc_match: result['dmarc'] = dmarc_match.group(1).lower()
    return result
