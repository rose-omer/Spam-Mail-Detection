from langdetect import detect
from sklearn.metrics.pairwise import cosine_similarity
from urllib.parse import urlparse
from app import app
from app.spam_model import load_models, get_spam_keywords
from app.authentication import analyze_authentication
from app.file_handler import download_and_scan_attachment
from app.utils import clean_text

model_tr, vect_tr, model_en, vect_en, stopwords_tr, stopwords_en = load_models()
from flask import Blueprint, request, jsonify

predict_bp = Blueprint('predict_bp', __name__)
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    text = data.get('text', '')
    ek_link = data.get('ek', '')
    sender = data.get('sender', '')
    headers = data.get('headers', '')
    subject = data.get('subject', '')

    if not text:
        return jsonify({'error': 'Metin girilmedi'}), 400

    auth_results = analyze_authentication(headers)

    clamav_result = virustotal_result = None
    if ek_link:
        scan_results = download_and_scan_attachment(ek_link)
        if "error" in scan_results:
            return jsonify({'error': scan_results['error']}), 500

        clamav_result = scan_results["clamav"]
        virustotal_result = scan_results["virustotal"]

        if clamav_result["status"] == "infected":
            return jsonify({'error': 'EK dosya ClamAV tarafından virüslü tespit edildi, işlem durduruldu'}), 400
        if virustotal_result["status"] == "infected":
            return jsonify({'error': 'EK dosya Virustotal tarafından virüslü tespit edildi, işlem durduruldu'}), 400

    try:
        lang = detect(text)
    except:
        return jsonify({'error': 'Dil tespiti yapılamadı'}), 400

    if lang == 'tr':
        stop_words, model, vectorizer = stopwords_tr, model_tr, vect_tr
    elif lang == 'en':
        stop_words, model, vectorizer = stopwords_en, model_en, vect_en
    else:
        return jsonify({'error': f'Desteklenmeyen dil: {lang}'}), 400

    cleaned = clean_text(text, stop_words)
    vectorized = vectorizer.transform([cleaned]).toarray()

    prediction = model.predict(vectorized)[0]
    proba = model.predict_proba(vectorized)[0] * 100
    spam_reasons = get_spam_keywords(cleaned, vectorizer, model) if prediction == 1 else []

    subject_cleaned = clean_text(subject, stop_words)
    if subject_cleaned and cleaned:
        vec_subject = vectorizer.transform([subject_cleaned]).toarray()
        similarity = cosine_similarity(vectorized, vec_subject)[0][0]
    else:
        similarity = None

    if similarity is not None and similarity < 0.3 and prediction == 0:
        spam_reasons.append(f"Mail başlığı ile içeriği uyumsuz (benzerlik {similarity:.2f})")
    if (auth_results['spf'] == 'pass' and auth_results['dkim'] == 'pass' and auth_results['dmarc'] == 'pass'):
        proba[0] = min(proba[0] + 15, 100.0)
        proba[1] = max(proba[1] - 15, 0.0)
        if proba[0] > proba[1]:
            prediction = 0
            spam_reasons = []

    domain_mismatch = None
    if ek_link and sender:
        try:
            mail_domain = sender.split('@')[-1].lower().strip()
            link_domain = urlparse(ek_link).hostname or ''
            link_domain = link_domain.lower().strip()
            if mail_domain in link_domain or link_domain in mail_domain:
                domain_mismatch = False
                if prediction == 1:
                    prediction = 0
                    proba[0] = max(proba[0], 90.0)
                    proba[1] = min(proba[1], 10.0)
                    spam_reasons = []
                else:
                    proba[0] = min(proba[0] + 10, 100.0)
                    proba[1] = max(proba[1] - 10, 0.0)
            else:
                domain_mismatch = True
                if prediction == 1:
                    spam_reasons.append(f"Ek link domain ({link_domain}) ile gönderici ({mail_domain}) uyuşmuyor.")
        except:
            domain_mismatch = True

    response = {
        'detected_language': lang,
        'prediction': 'SPAM' if prediction == 1 else 'GERCEK MAIL',
        'probabilities': {
            'GERCEK MAIL': f"{proba[0]:.2f}%",
            'SPAM': f"{proba[1]:.2f}%"
        },
        'spam_reasons': spam_reasons,
        'clamav_status': clamav_result["status"] if clamav_result else "not scanned",
        'virustotal_status': virustotal_result["status"] if virustotal_result else "not scanned",
        'sender_domain_check': (
            "UYUMLU" if domain_mismatch is False
            else "UYUMSUZ" if domain_mismatch is True
            else "EK YOK"
        ),
        'authentication_results': auth_results,
        'subject_body_similarity': similarity if similarity is not None else "hesaplanamadı"
    }

    if ek_link and clamav_result and virustotal_result:
        if clamav_result["status"] == "clean" and virustotal_result["status"] == "clean":
            response['attachment_scan_result'] = "EK dosya temiz"

    return jsonify(response)
