FROM python:3.10-slim

WORKDIR /spammaild

# Sistem bağımlılıkları ve ClamAV kurulumu
RUN apt-get update && apt-get install -y clamav clamav-daemon wget curl \
    && freshclam

# Gereksinimleri yükle
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY . .

# NLTK veri klasörünü konteynıra kopyala (eğer varsa, yoksa bu satırı çıkarabilirsin)
COPY nltk_data /root/nltk_data
ENV NLTK_DATA=/root/nltk_data

# ClamAV servisini arka planda başlat ve ardından Flask uygulamasını başlat
CMD ["sh", "-c", "clamd & python run.py"]
