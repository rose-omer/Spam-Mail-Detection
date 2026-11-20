# Arayüz tasarımı: "08 · Büyük Karar"

- Kaynak maket: `tasarimlar/spam-paneli/project/D08.dc.html` (depo dışında).
- Uygulama: `spammaild/web/templates/index.html`, `spammaild/web/static/app.css`, `app.js`, `theme.js`.
- Tokenler `app.css` içinde `:root` üzerinde. Yeni renk ya da boyut yazmadan önce token ekleyin.

## Dil
- Karar, tam genişlikteki tek renkli banttır. Geri kalan her şey sessiz: kart, gölge, degrade, ikon yok.
- Yazı tipleri: Big Shoulders Display 700/900 (karar, skor, bölüm başlığı, etki rakamı), Archivo (gövde), Consolas (adres, dosya adı). Fontlar `static/fonts/` içinden gelir.
- Köşe 2 px. Kontrol yüksekliği 44 px. Odak halkası 3 px `--focus`.
- Bütün durumlar (boş, yükleme, hata, sonuç) `verdict()` iskeletini kullanır.

## Maketten bilinçli sapmalar
- Koyu tema ve Sistem / Açık / Koyu seçici. D08'de yok; uygulamanın önceki sürümünde vardı, korundu. Seçici altbilgide.
- Kontrol kenarı `--control-line` (#7b8390). D08'deki #b5bbc4 beyazda 1,93:1; WCAG 1.4.11 için 3:1 gerekir. #b5bbc4 (`--line-strong`) yalnız ayırıcı çizgide.
- Üç örnek düğmesi (Temiz, Spam, Sahte banka) ikinci satırda. D08'de tek "Örnek" düğmesi giriş satırında.
- Servis durumu (demo modu, ClamAV, VirusTotal, URL itibarı) altbilgide.
- Öne çıkan nedenlerde rakamın yanında kaynak etiketi ("Kimlik", "Ek").
- Boş durumda dört bölüm sütunu: rakam yerine bölüm adı.
- Spam / phishing başlığı en az 52 px (D08 72 px). 375 px'te 72 px taşar.
- Mobilde (≤720 px) ipucunun uzun kısmı gizli; masaüstüne özgü bilgi (sürükle-bırak, Ctrl + Enter).

## Erişilebilirlik kararları
- Sonuç bölgesinde `aria-live` yok. Analizden sonra odak karar başlığına (`h2`, `tabindex="-1"`) geçer. Başlığın `aria-label`'ı karar ve skoru tek cümlede verir ("Sonuç: Spam / phishing, risk 100 / 100").
- Hata bandı `role="alert"` yalnız 401'de alır; o durumda odak anahtar alanına gider.
