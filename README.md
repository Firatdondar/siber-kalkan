# 🛡️ Siber Kalkan: Çift Çekirdekli Proaktif Mobil Tehdit Analizi ve İstihbarat Platformu

Siber Kalkan; uç Android cihaz telemetrisi (Edge Telemetry) ile asenkron backend mimarisini birleştiren, geleneksel imza tabanlı (signature-based) güvenlik sistemlerinin yetersiz kaldığı sıfırıncı gün (Zero-Day) ve oltalama (Phishing) tehditlerini proaktif olarak engelleyen **endüstriyel standartlarda (production-grade)** bir siber güvenlik platformudur.

Platform; mobil cihazlara düşen anlık bildirim verilerini (WhatsApp, SMS, Telegram vb.) veri gizliliği (GDPR/KVKK) standartlarına uyumlu şekilde yakalar, gerçek zamanlı yapay zeka ve OSINT hatlarından geçirerek SOC (Security Operations Center) kanallarına otomatik alarm üretir.

---

## 🏗️ 1. Sistem Mimarisi ve Teknoloji Yığını (Stack)

Siber Kalkan, yüksek yük altında bile minimum gecikme (low-latency) ile çalışacak şekilde gevşek bağlı (loosely coupled) ve asenkron tasarım kalıpları (Design Patterns) üzerine inşa edilmiştir:

* **Backend Çekirdeği (Core API):** Python tabanlı **FastAPI** ASGI mimarisi. Veri doğrulamaları için `Pydantic v2`, IP tabanlı DDoS ve DoS koruması için `SlowAPI` (Rate-Limiting) kullanılmıştır. Tüm ağır analiz süreçleri `asyncio` ile bloklanmayan (non-blocking) thread'ler üzerinde yürütülür.
* **Yapay Zeka Motoru (AI Engine):** Siber güvenlik literatüründeki 50.000+ canlı URL verisiyle eğitilmiş, aşırı öğrenmesi (overfitting) `GridSearchCV` ile engellenmiş **Random Forest Classifier** (150 Bağımsız Karar Ağacı) modeli. URL'ler üzerinde *Shannon Entropi Skoru*, *WHOIS Yaş Analizi* ve *Semantik NLP* dahil 78 farklı yapısal öznitelik çıkarımı gerçek zamanlı hesaplanır.
* **Uç Aygıt Katmanı (Mobile Edge Node):** Android erişilebilirlik (Accessibility) ve bildirim dinleme (Notification Listener) servisleri üzerinde kanca (hooking) işlemi gerçekleştiren otomasyon mekanizması.
* **Veri ve Log Katmanı (Persistence Layer):** ACID prensiplerine tam uyumlu, optimize edilmiş ve indekslenmiş ilişkisel SQL mimarisi.
* **Merkezi Yönetim Paneli (Frontend Dashboard):** WebSocket protokolü destekli, canlı tehdit akış analitiği, risk skorlamaları ve adli bilişim metriklerinin izlenebildiği reaktif web arayüzü.

---

## 🧩 2. Platform Modülleri ve Kabiliyetler

Siber Kalkan, siber tehditlere karşı 360 derece koruma sağlamak adına birbiriyle entegre çalışan 5 ana modülden oluşur:

### ⚡ A. Yapay Zeka Tabanlı Phishing Algılama Hattı
* Şüpheli URL'lerin anlamsal ve matematiksel analizini yapar.
* **İki Aşamalı Doğrulama (Two-Tier Pipeline):** Yapay zeka modelinin arada kaldığı sınır vakalarda (Gri Alan: %50-%70 risk), sistem asenkron olarak **VirusTotal v3 API** küresel tehdit istihbarat sorgusunu tetikler; sezgisel güç ile imza veri tabanını birleştirir.

### 🔍 B. Gelişmiş Dosya Analizi ve Steganografi (Adli Bilişim)
* Sisteme yüklenen dosyaların MD5/SHA-256 hash değerlerini çıkararak statik ve dinamik analize tabi tutar.
* Görüntü dosyalarının (PNG/JPEG) içerisine LSB (Least Significant Bit) yöntemiyle gizlenmiş olası komuta kontrol (C2) kodlarını veya zararlı verileri steganografik olarak ayrıştırır.

### 🛡️ C. Statik Kod Analizi (SAST)
* Yazılımcıların sisteme yüklediği kaynak kodları (Python, JavaScript vb.) özel olarak geliştirilmiş regex tabanlı kural setleriyle tarar.
* Kod içerisine unutulmuş hardcoded API anahtarları, şifreler veya SQL Injection / XSS zafiyeti barındıran güvensiz kod bloklarını tespit edip raporlar.

### 🪤 D. Aktif Savunma: Honeypot (Siber Tuzak)
* Saldırganları ana sistemden uzak tutmak için sahte dizinler (`/wp-admin`, `/api/v1/admin`) ve tuzak portlar açar.
* Bu tuzaklara gelen yetkisiz isteklerin kaynak IP, User-Agent ve Coğrafi Konum (Geolocation) verilerini anında izole edip kara listeye alır.

### 📊 E. Otomatik Raporlama ve Bildirim Entegrasyonları
* Yakalanan kritik tehditleri kurumsal standarda uygun olarak **Discord Webhook** ve **Telegram Bot API** üzerinden güvenlik ekiplerine anlık bildirim olarak iletir.
* Tüm olay silsilesini yasal süreçlere uygun, ISO/IEC 27001 uyumlu resmi bir adli bilişim raporu (`.docx`) olarak otomatik olarak dışa aktarır.

---

## 🛠️ 3. Kurulum ve Dağıtım (Deployment)

### Gereksinimler
* Python 3.10+
* Android OS 5.0+ (Uç cihaz telemetrisi için)

### Sunucu Kurulumu
1. Depoyu yerel bilgisayarınıza kopyalayın:
   ```bash
   git clone [https://github.com/kullanici_adi/siber-kalkan.git](https://github.com/kullanici_adi/siber-kalkan.git)
   cd siber-kalkan
