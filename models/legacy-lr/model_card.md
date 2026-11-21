# Model kartı: legacy-lr

- Tür: iki ayrı `LogisticRegression` (C=1.0).
  - TR: `TfidfVectorizer`, 5000 kelime, ASCII'ye katlanmış sözlük.
  - EN: `CountVectorizer`, 44 255 kelime.
- Kaynak: staj sürümündeki `model/*.pkl` dosyaları (scikit-learn 1.2.2 ile kaydedildi).
- Dönüşüm: `training/convert_legacy.py`. Pickle dosyaları sha256 ile doğrulandı, `skops` biçimine çevrildi.
  Yeniden eğitim yapılmadı.
- Ön işleme: TR metni `fold_turkish` ile ASCII'ye katlanır (ç→c, ğ→g, ı/İ/I→i, ö→o, ş→s, ü→u).
  Eski kod bunu yapmıyordu; bu yüzden "fırsat" gibi kelimeler sözlükte bulunmuyordu.
- Dil seçimi: `detect_language` (deterministik sözcük ve harf sayımı). `langdetect` kaldırıldı.
- Eğitim verisi: bilinmiyor. Repoda eğitim kodu ve veri yok.
- Ölçütler: yok. Eski ve yeni model aynı test kümesiyle karşılaştırılamadı.
- Bilinen sınırlar:
  - Kısa metinde dil tahmini yanlış olabilir.
  - EN modeli Enron tarzı spam sözcüklerine ağırlık veriyor; phishing için zayıf.
  - Yerine `baseline-char` (char n-gram) ya da transformer modeli eğitilmeli (`training/`).
