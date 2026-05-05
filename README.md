# Siber Kalkan - Çift Çekirdekli Tehdit Analiz ve Koruma Sistemi

Siber Kalkan, telefon bildirimlerini (WhatsApp, SMS vb.) saniyeler içinde analiz eden ve içerisinde OSINT (Açık Kaynak İstihbaratı) araçları barındıran tam kapsamlı bir güvenlik projesidir.

## 🚀 Proje Yapısı

*   `main.py`: Projenin ana sunucusu (Backend - FastAPI/Flask)
*   `index.html`: Web Kullanıcı Arayüzü (Frontend)
*   `siber_guvenlik_analiz.db`: Tüm log ve analizlerin tutulduğu veritabanı.
*   `SiberKalkan.macro`: Telefona yüklenecek olan otomatik MacroDroid script'i.
*   `raporlari_olustur.py`: Verileri alıp otomatik Word (.docx) raporları üreten harici araç.

---

## 📱 MacroDroid ile Siber Kalkan Entegrasyon Rehberi

### 🎯 Amaç
Bu rehber, MacroDroid uygulamasını kullanarak telefonunuzdaki WhatsApp, Instagram, SMS gibi uygulamaların bildirimlerini Siber Kalkan sistemine otomatik olarak nasıl göndereceğinizi adım adım anlatır.

### ⚡ Gereksinimler
- Android telefon (Android 5.0+)
- İnternet bağlantısı
- Siber Kalkan sunucusu çalışıyor olmalı
- MacroDroid uygulaması (Google Play Store'dan ücretsiz)

### 📋 Kurulum Adımları

#### ADIM 1: MacroDroid'u İndirin ve Kurun
1. Google Play Store'dan "MacroDroid - Automation and Task" uygulamasını indirin
2. Uygulamayı açın ve gerekli izinleri verin
3. Ana ekranda "Add Macro" (Makro Ekle) butonuna tıklayın

#### ADIM 2: İzinleri Yapılandırın
MacroDroid'un çalışması için şu izinleri vermelisiniz:
- ✅ **Erişilebilirlik**: Bildirimleri okuyabilmek için
- ✅ **İnternet**: API'ye veri gönderebilmek için  
- ✅ **Depolama**: Logları kaydedebilmek için
- ✅ **Arka Planda Çalışma**: Sürekli izleme için

**İzin Verme Adımları:**
1. Telefon Ayarları > Uygulamalar > MacroDroid > İzinler
2. Tüm izinleri "İzin Ver" olarak ayarlayın
3. Pil optimizasyonunu MacroDroid için devre dışı bırakın

#### ADIM 3: Tetikleyici (Trigger) Ayarları
1. **Makro Adı**: "Siber Kalkan Bildirim Tarayıcısı" yazın
2. **Tetikleyici Ekle** (+) butonuna tıklayın
3. **Bağlantı (Connectivity)** kategorisini seçin
4. **Cihaz Bildirimi (Device Notification)** seçeneğini tıklayın
5. İzlemek istediğiniz uygulamaları seçin: (WhatsApp, Instagram, SMS, vb.)

#### ADIM 4: Eylem (Action) Ayarları
1. **Eylem Ekle** (+) butonuna tıklayın
2. **Bağlantı (Connectivity)** kategorisini seçin
3. **HTTP İsteği Gönder (Send HTTP Request)** seçeneğini tıklayın

**HTTP Ayarları:**
```
Yöntem (Method): POST
URL: https://siber-kalkan.onrender.com/api/v1/analiz/mobil/
Content-Type: application/json
İstek Gövdesi (Body): {"message": "[not_title] - [not_text]"}
```

#### ADIM 5: Makroyu Kaydedin ve Aktifleştirin
1. Sağ üstteki onay ✅ butonuna tıklayın ve makro adını onaylayın.
2. Ana ekranda makronun aktif olduğundan emin olun.

### 🧪 Test Etme
WhatsApp'ta kendinize şu test mesajını gönderin:
`Hesabınız kısıtlandı! Açmak için: http://test-phishing-site.com`

**Beklenen Sonuç:**
MacroDroid bildirimi yakalamalı, API'ye göndermeli ve sistem "ZARARLI" olarak analiz edip size uyarı vermelidir.

### 🔧 Sorun Giderme
- **MacroDroid Çalışmıyorsa:** Erişilebilirlik, Pil Optimizasyonu ve Arka Plan izinlerini kontrol edin.
- **API Gönderimi Başarısız Olursa:** URL adresinin doğru olduğundan (kendi sunucunuz) ve internetinizin olduğundan emin olun.
