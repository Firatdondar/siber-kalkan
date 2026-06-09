Markdown
# 🛡️ Siber Kalkan: Çift Çekirdekli Proaktif Mobil Tehdit Analizi ve İstihbarat Platformu

Siber Kalkan; uç Android cihaz telemetrisi (Edge Telemetry) ile asenkron backend mimarisini birleştiren, geleneksel imza tabanlı (signature-based) güvenlik sistemlerinin yetersiz kaldığı sıfırıncı gün (Zero-Day) ve oltalama (Phishing) tehditlerini proaktif olarak engelleyen **endüstriyel standartlarda (production-grade)** bir siber güvenlik platformudur.

Platform; mobil cihazlara düşen anlık bildirim verilerini (WhatsApp, SMS, Telegram vb.) veri gizliliği (GDPR/KVKK) standartlarına uyumlu şekilde yakalar, gerçek zamanlı yapay zeka ve OSINT hatlarından geçirerek SOC (Security Operations Center) kanallarına otomatik alarm üretir.

---

## 🏗️ 1. Sistem Mimarisi ve Teknoloji Yığını (Stack)

Siber Kalkan, yüksek yük altında bile minimum gecikme (low-latency) ile çalışacak şekilde gevşek bağlı (loosely coupled) ve asenkron tasarım kalıpları (Design Patterns) üzerine inşa edilmiştir:

* [cite_start]**Backend Çekirdeği (Core API):** Python tabanlı **FastAPI** ASGI mimarisi[cite: 117]. [cite_start]Veri doğrulamaları için `Pydantic v2`, IP tabanlı DDoS ve DoS koruması için `SlowAPI` (Rate-Limiting) kullanılmıştır[cite: 102, 117]. [cite_start]Tüm ağır analiz süreçleri `asyncio` ile bloklanmayan (non-blocking) thread'ler üzerinde yürütülür[cite: 154, 156].
* [cite_start]**Yapay Zeka Motoru (AI Engine):** Siber güvenlik literatüründeki 50.000+ canlı URL verisiyle eğitilmiş [cite: 121][cite_start], aşırı öğrenmesi (overfitting) `GridSearchCV` ile engellenmiş **Random Forest Classifier** (150 Bağımsız Karar Ağacı) modeli[cite: 117, 121]. URL'ler üzerinde *Shannon Entropi Skoru*, *WHOIS Yaş Analizi* ve *Semantik NLP* dahil 78 farklı yapısal öznitelik çıkarımı gerçek zamanlı hesaplanır.
* [cite_start]**Uç Aygıt Katmanı (Mobile Edge Node):** Android erişilebilirlik (Accessibility) ve bildirim dinleme (Notification Listener) servisleri üzerinde kanca (hooking) işlemi gerçekleştiren otomasyon mekanizması.
* **Veri ve Log Katmanı (Persistence Layer):** ACID prensiplerine tam uyumlu, optimize edilmiş ve indekslenmiş ilişkisel SQL mimarisi.
* [cite_start]**Merkezi Yönetim Paneli (Frontend Dashboard):** WebSocket protokolü destekli, canlı tehdit akış analitiği, risk skorlamaları ve adli bilişim metriklerinin izlenebildiği reaktif web arayüzü[cite: 105, 111].

---

## 🧩 2. Platform Modülleri ve Kabiliyetler

Siber Kalkan, siber tehditlere karşı 360 derece koruma sağlamak adına birbiriyle entegre çalışan 5 ana modülden oluşur:

### ⚡ A. Yapay Zeka Tabanlı Phishing Algılama Hattı
* [cite_start]Şüpheli URL'lerin anlamsal ve matematiksel analizini yapar[cite: 122].
* [cite_start]**İki Aşamalı Doğrulama (Two-Tier Pipeline):** Yapay zeka modelinin arada kaldığı sınır vakalarda (Gri Alan: %50-%70 risk), sistem asenkron olarak **VirusTotal v3 API** küresel tehdit istihbarat sorgusunu tetikler; sezgisel güç ile imza veri tabanını birleştirir[cite: 134, 136].

### 🔍 B. Gelişmiş Dosya Analizi ve Steganografi (Adli Bilişim)
* [cite_start]Sisteme yüklenen dosyaların MD5/SHA-256 hash değerlerini çıkararak statik ve dinamik analize tabi tutar[cite: 136].
* [cite_start]Görüntü dosyalarının (PNG/JPEG) içerisine LSB (Least Significant Bit) yöntemiyle gizlenmiş olası komuta kontrol (C2) kodlarını veya zararlı verileri steganografik olarak ayrıştırır[cite: 140].

### 🛡️ C. Statik Kod Analizi (SAST)
* [cite_start]Yazılımcıların sisteme yüklediği kaynak kodları (Python, JavaScript vb.) özel olarak geliştirilmiş regex tabanlı kural setleriyle tarar[cite: 144].
* [cite_start]Kod içerisine unutulmuş hardcoded API anahtarları, şifreler veya SQL Injection / XSS zafiyeti barındıran güvensiz kod bloklarını tespit edip raporlar[cite: 146].

### 🪤 D. Aktif Savunma: Honeypot (Siber Tuzak)
* [cite_start]Saldırganları ana sistemden uzak tutmak için sahte dizinler (`/wp-admin`, `/api/v1/admin`) ve tuzak portlar açar[cite: 177, 178].
* [cite_start]Bu tuzaklara gelen yetkisiz isteklerin kaynak IP, User-Agent ve Coğrafi Konum (Geolocation) verilerini anında izole edip kara listeye alır[cite: 179].

### 📊 E. Otomatik Raporlama ve Bildirim Entegrasyonları
* [cite_start]Yakalanan kritik tehditleri kurumsal standarda uygun olarak **Discord Webhook** ve **Telegram Bot API** üzerinden güvenlik ekiplerine anlık bildirim olarak iletir[cite: 163, 164].
* Tüm olay silsilesini yasal süreçlere uygun, ISO/IEC 27001 uyumlu resmi bir adli bilişim raporu (`.docx`) olarak otomatik olarak dışa aktarır.

---

## 🛠️ 3. Kurulum, Dağıtım ve Bağımlılıklar (Deployment)

### 📋 Geliştirme ve Üretim Bağımlılıkları (`requirements.txt`)

Sistem mimarisinin production-grade performans kararlılığı sunması adına kullanılan kütüphanelerin kilit versiyonları aşağıda belirtilmiştir:

```text
fastapi==0.110.0
uvicorn[standard]==0.28.0
pydantic==2.6.4
slowapi==0.1.9
scikit-learn==1.4.1.post1
numpy==1.26.4
pandas==2.2.1
requests==2.31.0
python-docx==1.1.0
aiohttp==3.9.3
🐳 Docker ve Mikroservis Konteyner Dağıtımı
Siber Kalkan altyapısı, izole edilmiş ve platform bağımsız çalışabilen mikroservis konteyner yapısını (Dockerization) yerel ve bulut dağıtımları için varsayılan olarak destekler.

1. Dockerfile (Backend & AI Inference Engine)
Dockerfile
# Hafif ve optimize edilmiş Python imajı taban alınmıştır
FROM python:3.11-slim

# Sistem bağımlılıklarının kurulması ve temizlenmesi
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizininin izole edilmesi
WORKDIR /app

# Bağımlılık matrisinin kopyalanması ve in-cache kurulumu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje kaynak kodlarının ve eğitilmiş ML model vektörlerinin aktarılması
COPY . .

# ASGI sunucusunun dış dünyaya açacağı port mimarisi
EXPOSE 8000

# API ağ geçidinin production modunda başlatılması
CMD ["uvicorn", "main.py:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
2. docker-compose.yml (Orkestrasyon Katmanı)
YAML
version: '3.8'

services:
  siber_kalkan_api:
    build: .
    container_name: siber_kalkan_core
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - RATE_LIMIT_PER_MINUTE=60
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
🔑 4. Çevre Değişkenleri ve Gizlilik Yönetimi (.env.example)
Üretim ortamında API anahtarlarının ve gizli anahtarların güvenliği için python-dotenv modülü entegre edilmiştir. Dağıtım öncesi proje kök dizininde bir .env dosyası oluşturulmalı ve aşağıdaki şemaya göre yapılandırılmalıdır:

Ini, TOML
# --- SUNUCU YAPILANDIRMASI ---
SECRET_KEY=super_secret_forensic_hash_key_654321
ENVIRONMENT=production

# --- HARİCİ TEHDİT İSTİHBARATI API ENTEGRASYONLARI ---
VIRUSTOTAL_API_KEY=your_actual_virustotal_v3_api_token_here
XPOSEDORNOT_API_KEY=your_xposedornot_data_breach_token_here

# --- BİLDİRİM VE SOC KANAL AYARLARI ---
TELEGRAM_BOT_TOKEN=8638671453:AAF_br_0utQzdK315ht7ZmZIg_0wosX0zVc
DISCORD_WEBHOOK_URL=[https://discord.com/api/webhooks/your_webhook_id/your_webhook_token](https://discord.com/api/webhooks/your_webhook_id/your_webhook_token)
🚀 5. Manuel Sunucu Kurulumu
Depoyu yerel bilgisayarınıza kopyalayın:

Bash
git clone [https://github.com/kullanici_adi/siber-kalkan.git](https://github.com/kullanici_adi/siber-kalkan.git)
cd siber-kalkan
Gerekli bağımlılıkları yükleyin:

Bash
pip install -r requirements.txt
Sunucuyu yerel modda başlatın:

Bash
python main.py
📱 6. Mobil Entegrasyon (Edge Config)
Mobil otomasyon script'i (SiberKalkan.macro) cihaza yüklendikten sonra, erişilebilirlik ve bildirim dinleme izinleri verilerek hedef sunucu endpoint'i (https://siber-kalkan.onrender.com/api/v1/analiz/mobil/) API Gateway olarak tanımlanır. Giriş sinyalleri TLS 1.3 şifreleme katmanı üzerinden sunucuya güvenli bir şekilde POST edilmeye hazırdır.
