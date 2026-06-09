Markdown
# 🛡️ Siber Kalkan
### *Çift Çekirdekli Proaktif Mobil Tehdit Analizi ve İstihbarat Platformu*

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/AI%20Engine-scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

[cite_start]Siber Kalkan; uç Android cihaz telemetrisi (**Edge Telemetry**) ile asenkron backend mimarisini bütünleştiren, geleneksel imza tabanlı güvenlik sistemlerinin yetersiz kaldığı sıfırıncı gün (**Zero-Day**) ve gelişmiş oltalama (**Phishing**) tehditlerini engelleyen endüstriyel standartlarda bir proaktif siber güvenlik platformudur[cite: 65, 96, 216].

> [cite_start]🔒 **Gizlilik Politikası (GDPR / KVKK):** Mobil cihazlara düşen anlık bildirim verileri (WhatsApp, SMS, Telegram), kullanıcı veri gizliliği standartlarına tam uyumlu şekilde işlenerek gerçek zamanlı yapay zeka hatlarından geçirilir ve SOC kanallarına aktarılır[cite: 114, 115, 158].

---

## 🏗️ 1. Sistem Mimarisi ve Teknoloji Yığını

[cite_start]Platform, yüksek yük altında minimum gecikme (**low-latency**) ve maksimum hata toleransı ile çalışacak şekilde gevşek bağlı (**loosely coupled**) tasarım kalıpları üzerine inşa edilmiştir[cite: 94, 95]:

| Katman | Teknoloji / Çerçeve | Mimari Rol ve İşleyiş |
| :--- | :--- | :--- |
| **Backend Çekirdeği** | `FastAPI (Python)` | [cite_start]ASGI uyumlu omurga[cite: 117]. [cite_start]`Pydantic v2` ile veri doğrulaması, `SlowAPI` ile hız sınırlama süreçlerini asenkron yönetir[cite: 102, 117]. |
| **Yapay Zeka Motoru** | `Scikit-learn` | [cite_start]50.000+ canlı URL ile eğitilmiş `Random Forest Classifier`[cite: 117, 121]. 78 farklı yapısal özniteliği milisaniyeler içinde çıkarır. |
| **Uç Aygıt Katmanı** | `Android OS` | [cite_start]Erişilebilirlik ve Bildirim Dinleme servisleri üzerinden veri akışını yakalayan otomasyon kancası[cite: 117]. |
| **Veri & Loglama** | `İlişkisel SQL` | ACID prensiplerine tam uyumlu, optimize edilmiş ve indekslenmiş kalıcı veri mimarisi. |
| **Yönetim Paneli** | `Vanilla JS / WebSockets` | [cite_start]Canlı tehdit akış analitiği ve adli bilişim metriklerinin izlenebildiği reaktif Dashboard[cite: 105, 111]. |

---

## 🧩 2. Platform Modülleri ve Kabiliyetler

                              [ GELEN VERİ AKIŞI ]
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
   Yapay Zeka Phishing Hattı                       Gelişmiş Dosya & SAST
(Random Forest & Shannon Entropy)                (SHA-256 Hash / Regex Rules)
│                                             │
v                                             v
[ Gri Alan Kontrolü: %50-%70 Risk ]               [ VM Sandbox / İzolasyon Hattı ]
│                                             │
v                                             v
VirusTotal v3 Küresel API                       Honeypot & Aktif Savunma


### ⚡ A. Yapay Zeka Tabanlı Phishing Algılama Hattı
* **Öznitelik Mühendisliği:** URL'ler üzerinde *Shannon Entropi Skoru*, *WHOIS Alan Adı Yaş Analizi* ve *Semantik NLP* hesaplamaları yürütülür[cite: 122].
* **İki Aşamalı Doğrulama (Two-Tier Pipeline):** Modelin sınırda kaldığı şüpheli vakalarda (Gri Alan: %50-%70 risk), sistem arka planda asenkron olarak **VirusTotal v3 API** sorgusunu tetikler ve sezgisel güç ile imza veri tabanını birleştirir[cite: 134, 136].

### 🔍 B. Gelişmiş Dosya Analizi ve Steganografi
* Sisteme yüklenen dosyaların SHA-256 hash değerlerini çıkararak küresel tehdit istihbarat ağlarında taratır[cite: 136].
* Görüntü dosyalarının (PNG/JPEG) içerisine **LSB (Least Significant Bit)** yöntemiyle gizlenmiş olası komuta kontrol (C2) sızıntılarını adli bilişim teknikleriyle ayrıştırır[cite: 140].

### 🛡️ C. Statik Kod Analizi (SAST)
* Kaynak kodları regex tabanlı kural setleriyle tarayarak hardcoded unutulmuş API anahtarlarını, şifrelerı, SQL Injection ve XSS zafiyetlerini geliştirme aşamasında yakalar[cite: 144, 146].

### 🪤 D. Aktif Savunma: Honeypot (Siber Tuzak)
* Saldırganları ana sistemden uzak tutmak için sahte dizinler (`/wp-admin`, `/api/v1/admin`) açar[cite: 177, 178]. Yetkisiz erişim sağlayan IP'lerin coğrafi konum verilerini (Geolocation) çıkararak otomatik kara listeye alır[cite: 179].

### 📊 E. Otomatik Adli Raporlama
* Olay silsilesini ve analiz çıktılarını yasal süreçlere uygun, ISO/IEC 27001 uyumlu resmi bir adli bilişim raporu (`.docx`) olarak otomatik üretir ve **Discord/Telegram API** üzerinden SOC ekiplerine anlık iletir[cite: 163, 164].

---

## 🛠️ 3. Kurulum ve Konteyner Dağıtımı (Deployment)

### 📋 Geliştirme Bağımlılıkları (`requirements.txt`)
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
🐳 Dockerizasyon Yapısı
1. Dockerfile
Dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main.py:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
2. docker-compose.yml
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
🔑 4. Çevre Değişkenleri Yönetimi (.env.example)
Güvenlik standartları gereği hassas veriler kod bloklarından izole edilerek .env dosyasında saklanır:

Ini, TOML
# --- SUNUCU YAPILANDIRMASI ---
SECRET_KEY=super_secret_forensic_hash_key_654321
ENVIRONMENT=production

# --- HARİCİ API ENTEGRASYONLARI ---
VIRUSTOTAL_API_KEY=your_actual_virustotal_v3_api_token_here
XPOSEDORNOT_API_KEY=your_xposedornot_data_breach_token_here

# --- SOC KANAL AYARLARI ---
TELEGRAM_BOT_TOKEN=8638671453:AAF_br_0utQzdK315ht7ZmZIg_0wosX0zVc
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_id/your_token
🚀 5. Hızlı Başlangıç
Manuel Kurulum
Bash
# 1. Depoyu klonlayın
git clone https://github.com/kullanici_adi/siber-kalkan.git
cd siber-kalkan

# 2. Bağımlılıkları kurun
pip install -r requirements.txt

# 3. API Gateway'i tetikleyin
python main.py
📱 6. Mobil Entegrasyon (Edge Config)
SiberKalkan.macro betiği uç cihaza import edildikten sonra gerekli servis izinleri tanımlanır. Mobil otomasyon, yakaladığı sinyalleri TLS 1.3 şifreleme katmanı üzerinden doğrudan merkezi sunucunun https://siber-kalkan.onrender.com/api/v1/analiz/mobil/ uç noktasına güvenli bir şekilde ulaştırır.
