# 📧 SpamMailD — E-Posta Güvenlik Analiz Sistemi

---

## 🏢 Proje Hakkında

Bu proje, **EMAR Proje** şirketinde gerçekleştirdiğim staj süresince geliştirilmiştir.  
Projede, staj sorumlusu **Mehmet Emre Doğan**’ın verdiği onaylar ve yönlendirmeler doğrultusunda ilerlenmiş ve tamamlanmıştır.

---

SpamMailD, gelen e-postaları **spam**, **virüs**, **başlık-gövde tutarsızlığı**, **kimlik doğrulama (SPF, DKIM, DMARC)** ve **ek dosya güvenliği** gibi birçok açıdan analiz eden çok katmanlı bir e-posta güvenlik sistemidir. Sistem, Flask API ve Python altyapısı üzerinde çalışır ve entegre makine öğrenimi modelleriyle desteklenmiştir.

---

## 🚀 Özellikler

- 📦 **Spam tespiti** (Türkçe ve İngilizce destekli)
- 🔍 **Başlık ve içerik tutarlılığı analizi**
- 🛡️ **SPF / DKIM / DMARC kimlik doğrulaması**
- 🧠 **Makine Öğrenimi destekli içerik analizi (SVM + TF-IDF)**
- 📎 **Virüslü ek tespiti (ClamAV + VirusTotal)**
- 📤 **IMAP ile otomatik mail çekme**
- 📊 **Spam nedenlerinin detaylı raporlanması**
- 🐳 **Docker ile kolay kurulum ve dağıtım**

---

## 📁 Proje Yapısı
```bash
├── app/
│ ├── authentication.py # SPF, DKIM, DMARC kontrolü
│ ├── clamav_scanner.py # ClamAV virüs tarayıcı
│ ├── file_handler.py # Ek dosya indirme ve tarama
│ ├── spam_model.py # Makine öğrenimi modelleri ve spam anahtar kelimeleri
│ ├── utils.py # Metin temizleme işlemleri
│ ├── virustotal_checker.py # VirusTotal API entegrasyonu
│ ├── route.py # Flask API uç noktası (/predict)
├── client.py # IMAP ile son maili çekip analiz eden script
├── model/ # Eğitimli ML modelleri (.pkl dosyaları)
├── nltk_data/ # NLTK stopwords ve tokenizer verileri
├── requirements.txt # Python bağımlılıkları
├── Dockerfile # Docker imajı yapılandırması
├── run.py # Flask uygulama başlatıcı script
└── .env # Ortam değişkenleri (API anahtarları, e-posta bilgileri)
```
---

## 🐍 Kurulum

1. Depoyu klonlayın ve sanal ortam oluşturun:

```bash
git clone https://github.com/kullanici/spammaild.git
cd spammaild
python -m venv venv
source venv/bin/activate   # Windows için: venv\Scripts\activate
pip install -r requirements.txt

```
2. NLTK verilerini indirin (ilk kullanımda):

Python konsolunda:

```python
import nltk
nltk.download('punkt')
nltk.download('stopwords')
```

.env dosyasını oluşturun ve aşağıdaki değişkenleri doldurun:

EMAIL_ACCOUNT=youremail@gmail.com
EMAIL_PASSWORD=yourpassword
VIRUSTOTAL_API_KEY=your_virustotal_api_key


## 🐳 Docker ile Çalıştırma

Docker imajını oluşturun:

```bash
docker build -t spammaild .
docker run -d -p 5000:5000 --env-file .env spammaild
```

## 🔧 Teknolojiler ve Kütüphaneler

- Python 3.10  
- Flask  
- scikit-learn (SVM modeli)  
- NLTK (doğal dil işleme)  
- ClamAV (virüs tarama)  
- VirusTotal API  
- imaplib (e-posta alma)  
- Docker  
