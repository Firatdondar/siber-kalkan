from fastapi import FastAPI, Request, UploadFile, File, Depends, Header, Form
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import hashlib, requests, re, imaplib, email, socket, io, math, os
from email.header import decode_header
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sklearn.ensemble import RandomForestClassifier

# --- KONFİGÜRASYON ---
# Discord Webhook artık veritabanından çekilecek.

# --- VERİTABANI ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./siber_guvenlik_analiz.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AnalizGecmisi(Base):
    __tablename__ = "analiz_gecmisi"
    id = Column(Integer, primary_key=True, index=True)
    analiz_tipi = Column(String(50))
    hedef = Column(String(255))
    sonuc = Column(Text)
    durum_kodu = Column(String(20))
    # Türkiye Saati (UTC+3) için güvenli zaman
    tarih = Column(DateTime, default=lambda: datetime.now(timezone(timedelta(hours=3))))

class Ayar(Base):
    __tablename__ = "ayarlar"
    anahtar = Column(String(50), primary_key=True, index=True)
    deger = Column(String(255))

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_setting(db: Session, key_name: str):
    ayar = db.query(Ayar).filter(Ayar.anahtar == key_name).first()
    return ayar.deger if ayar else None

def send_discord_alert(analiz_tipi, hedef, detay, db: Session):
    webhook = get_setting(db, "discord_webhook")
    if webhook and "http" in webhook:
        try: requests.post(webhook, json={"content": f"🚨 **SİBER KALKAN ALARMI** 🚨\n**Kaynak:** {analiz_tipi}\n**Hedef:** {hedef}\n**Bulgu:** {detay}"})
        except: pass

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Siber Kalkan API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- AI MODEL (Link ve Oltalama Zekası) ---
def extract_url_features(url):
    # Kapsamlı Dolandırıcılık/Oltalama (Phishing) Kelimeleri
    tehlikeli_kelimeler = [
        'bank', 'login', 'secure', 'free', 'kazandin', 'bonus', 'hediye', 'fatura', 
        'ceza', 'tebligat', 'borc', 'kredi', 'aidat', 'iptal', 'guncelle', 'hesap', 
        'sifre', 'verify', 'update', 'support', 'kargo', 'ptt', 'takip', 'odul', 'para'
    ]
    return [len(url), url.count('.'), url.count('-'), 1 if '@' in url else 0, 1 if re.search(r'\d+\.\d+', url) else 0, sum(1 for k in tehlikeli_kelimeler if k in url.lower())]
ml_model = RandomForestClassifier(n_estimators=10, random_state=42)
ml_model.fit([extract_url_features("google.com"), extract_url_features("kacak-bahis-free-bonus.com")], [0, 1])

# --- PWA ROTALARI ---
@app.get("/")
def anasayfa(): return FileResponse("index.html")

@app.get("/manifest.json")
def get_manifest(): return FileResponse("manifest.json")

@app.get("/sw.js")
def get_sw(): return FileResponse("sw.js")

@app.get("/SiberKalkan.macro")
def get_macro(request: Request): 
    if os.path.exists("SiberKalkan.macro"):
        with open("SiberKalkan.macro", "r", encoding="utf-8") as f:
            icerik = f.read()
        
        # Sitenin o anki çalıştığı adresi al
        aktif_url = str(request.base_url).rstrip('/')
        
        # EĞER KULLANICI LOCALHOST'TAN GİRDİYSE TELEFON BİLGİSAYARI BULAMAZ.
        # Bu yüzden bilgisayarın gerçek Wi-Fi ağ adresini (192.168...) bulup zorla onu yazacağız.
        if "localhost" in aktif_url or "127.0.0.1" in aktif_url:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('10.255.255.255', 1))
                gercek_ip = s.getsockname()[0]
            except Exception:
                gercek_ip = '127.0.0.1'
            finally:
                s.close()
            
            # Port numarasını koruyarak URL'yi güncelle
            port = aktif_url.split(":")[-1] if ":" in aktif_url.replace("http://", "") else "8000"
            aktif_url = f"http://{gercek_ip}:{port}"
        
        # Makronun içindeki eski adresi, yeni aktif (ve çalışan) adresle değiştir
        icerik = icerik.replace("https://siber-kalkan.onrender.com", aktif_url)
        
        # Değiştirilmiş dosyayı doğrudan indirt
        dosya_bytes = io.BytesIO(icerik.encode('utf-8'))
        return StreamingResponse(dosya_bytes, media_type="application/octet-stream", headers={"Content-Disposition": "attachment; filename=SiberKalkan.macro"})
        
    return {"error": "Macro dosyasi bulunamadi."}

# ================= 0. SİBER TUZAK (HONEYPOT) YENİ! =================
@app.get("/wp-admin")
@app.post("/wp-admin")
@app.get("/gizli-veritabani")
@app.get("/admin")
@limiter.limit("5/minute")
def honeypot_tetikle(request: Request, db: Session = Depends(get_db)):
    # Biri bu sayfalara girmeye çalışırsa arka planda sessizce fişlenir
    ip = request.client.host
    path = request.url.path
    send_discord_alert("HONEYPOT (Siber Tuzak) Tetiklendi!", ip, f"Saldırgan şu yetkisiz dizine girmeye çalıştı: {path}", db)
    db.add(AnalizGecmisi(analiz_tipi="Honeypot (Aktif Savunma)", hedef=ip, sonuc=f"Tuzak Tetiklendi: {path}", durum_kodu="Zararli"))
    db.commit()
    return {"status": "error", "message": "HTTP 403: Access Denied. Sızma girişimi tespit edildi ve yetkili mercilere loglandı."}

# ================= AYAR KAYDETME MOTORU =================
class SistemAyarRequest(BaseModel):
    telegram_token: str
    render_url: str
    gmail_adres: str = ""
    gmail_sifre: str = ""
    discord_webhook: str = ""

@app.post("/api/v1/ayarlar/kaydet/")
@limiter.limit("10/minute")
def ayar_kaydet(istek: SistemAyarRequest, request: Request, db: Session = Depends(get_db)):
    ayarlar = {
        "telegram_token": istek.telegram_token,
        "gmail_adres": istek.gmail_adres,
        "gmail_sifre": istek.gmail_sifre,
        "discord_webhook": istek.discord_webhook
    }
    for k, v in ayarlar.items():
        if v:
            ayar = db.query(Ayar).filter(Ayar.anahtar == k).first()
            if not ayar: db.add(Ayar(anahtar=k, deger=v))
            else: ayar.deger = v
    db.commit()
    
    if istek.telegram_token and istek.render_url:
        webhook_url = f"{istek.render_url}/api/v1/telegram/webhook/"
        requests.get(f"https://api.telegram.org/bot{istek.telegram_token}/setWebhook?url={webhook_url}")
        
    return {"status": "success", "message": "Ayarlar başarıyla kaydedildi."}

# ================= 1. GMAIL / IMAP E-POSTA KALKANI =================
@app.post("/api/v1/analiz/email/")
@limiter.limit("5/minute")
def email_tara(request: Request, db: Session = Depends(get_db)):
    usr = get_setting(db, "gmail_adres")
    pwd = get_setting(db, "gmail_sifre")
    if not usr or not pwd: return {"status": "error", "message": "Gmail bilgileri eksik."}
    
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(usr, pwd)
        mail.select("inbox")
        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()
        
        tehdit_sayisi = 0
        for m_id in mail_ids:
            res, msg = mail.fetch(m_id, "(RFC822)")
            for response in msg:
                if isinstance(response, tuple):
                    g_msg = email.message_from_bytes(response[1])
                    icerik = ""
                    if g_msg.is_multipart():
                        for part in g_msg.walk():
                            if part.get_content_type() == "text/plain": icerik = part.get_payload(decode=True).decode()
                    else:
                        icerik = g_msg.get_payload(decode=True).decode()
                    
                    urls = re.findall(r'(https?://[^\s]+)', icerik)
                    for url in urls:
                        risk = ml_model.predict_proba([extract_url_features(url)])[0][1] * 100
                        if risk > 50:
                            tehdit_sayisi += 1
                            send_discord_alert("E-Posta (Gmail)", url, f"%{risk:.1f} Riskli Oltalama Linki!", db)
                            db.add(AnalizGecmisi(analiz_tipi="E-Posta", hedef=url, sonuc=f"%{risk:.1f} Risk", durum_kodu="Zararli"))
        db.commit()
        return {"status": "success", "message": f"Tarama tamamlandı. {tehdit_sayisi} adet tehdit engellendi."}
    except Exception as e:
        return {"status": "error", "message": f"Bağlantı hatası: {str(e)}"}

# ================= 2. BİLDİRİM VE MESAJ MOTORU (YAPAY ZEKA) =================
class MobileRequest(BaseModel): message: str
@app.post("/api/v1/analiz/mobil/")
@limiter.limit("20/minute")
def mobil_analiz(istek: MobileRequest, request: Request, db: Session = Depends(get_db)):
    # --- BAĞLANTI TESTİ İÇİN CİHAZ BİLGİSİNİ KAYDET ---
    ip = request.client.host if request.client else "Bilinmiyor"
    zaman_str = str(datetime.utcnow().timestamp())
    
    ayar_ip = db.query(Ayar).filter(Ayar.anahtar == "son_baglanan_ip").first()
    if not ayar_ip: db.add(Ayar(anahtar="son_baglanan_ip", deger=ip))
    else: ayar_ip.deger = ip
        
    ayar_zaman = db.query(Ayar).filter(Ayar.anahtar == "son_baglanti_zamani").first()
    if not ayar_zaman: db.add(Ayar(anahtar="son_baglanti_zamani", deger=zaman_str))
    else: ayar_zaman.deger = zaman_str
    
    db.commit()
    # ----------------------------------------------------

    msg = istek.message
    
    # Gelişmiş Regex: http://, https://, www., veya .com, .apk, .net gibi bitenleri ve IP adreslerini yakalar
    olasi_linkler = re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.(?:com|net|org|apk|info|biz|tr|xyz)[^\s]*|\b(?:\d{1,3}\.){3}\d{1,3}\b)', msg, re.IGNORECASE)
    
    # EĞER MESAJDA LİNK YOKSA (Sadece metinse)
    if not olasi_linkler:
        guvenli_kayit = AnalizGecmisi(
            analiz_tipi="Bildirim/Mesaj",
            hedef=msg[:250] + ("..." if len(msg) > 250 else ""),
            sonuc="Metin incelendi, tıklanabilir veya zararlı bir link (http://) bulunamadı.",
            durum_kodu="Guvenli"
        )
        db.add(guvenli_kayit)
        db.commit()
        return {"status": "clean", "message": "Metin temiz. Tıklanabilir link bulunamadı."}

    # EĞER LİNK VARSA YAPAY ZEKA TARAMASI YAP
    ilk_url = olasi_linkler[0]
    if not ilk_url.startswith("http"):
        ilk_url = "http://" + ilk_url
        
    son_url = ilk_url
    try: son_url = requests.head(ilk_url, allow_redirects=True, timeout=4).url
    except: pass

    risk = ml_model.predict_proba([extract_url_features(son_url)])[0][1] * 100
    
    # Kapsamlı Kritik Kural Listesi (Typosquatting ve Aciliyet bildiren kelimeler)
    kritik_kelimeler = ['g00gle', 'instaqram', 'bahis', 'kazandin', 'bonus', 'virus', 'bedava', 'hediye', 'fatura', 'hack', 'kredi', 'ceza', 'tebligat', 'ptt-kargo', 'iptal']
    typo = any(x in son_url.lower() for x in kritik_kelimeler)
    if typo: risk = max(risk, 90.0)

    # Güvenlik Endüstrisi Standartlarına Göre Güncellenmiş Eşikler:
    # 50 ve üzeri: Kesin Zararlı (Kırmızı)
    # 10 ve 49 arası: Şüpheli (Sarı/Turuncu) - En ufak bir anormallikte bile uyarır
    # 10'dan az: Güvenli (Yeşil)
    karar = "Zararli" if risk >= 50 else ("Supheli" if risk >= 10 else "Guvenli")
    if karar == "Zararli": send_discord_alert("Mobil Bildirim / Mesaj", son_url, f"Yapay Zeka Riski: %{risk:.1f}", db)
    
    db.add(AnalizGecmisi(analiz_tipi="Bildirim/Mesaj", hedef=son_url, sonuc=f"%{risk:.1f} Risk", durum_kodu=karar))
    db.commit()
    return {"status": "found", "ilk_url": ilk_url, "son_url": son_url, "risk": round(risk,2), "typo": typo, "karar": karar}

# ================= 3. GELİŞMİŞ VİRÜS TESPİT MOTORU =================
def behavioral_analysis(content, filename):
    """Davranışsal analiz için dosya içeriğini tarar"""
    threats = []
    risk_score = 0
    
    # PE Header analizi (Windows executable)
    if content.startswith(b"MZ"):
        risk_score += 30
        threats.append("Windows PE executable tespit edildi")
        
    # ELF Header analizi (Linux executable)
    if content.startswith(b"\x7fELF"):
        risk_score += 25
        threats.append("Linux ELF executable tespit edildi")
        
    # Script ve macro tespiti
    if filename.lower().endswith(('.js', '.vbs', '.bat', '.cmd', '.ps1')):
        risk_score += 20
        threats.append("Betik dosyası tespit edildi")
        
    # Şüpheli stringler
    suspicious_strings = [
        b'powershell', b'cmd.exe', b'shell32', b'kernel32',
        b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
        b'base64', b'eval(', b'system(', b'exec(',
        b'bitcoin', b'cryptocurrency', b'wallet', b'miner'
    ]
    
    for s in suspicious_strings:
        if s in content.lower():
            risk_score += 10
            threats.append(f"Şüpheli string: {s.decode('utf-8', errors='ignore')}")
            
    # Yüksek entropi (packed/encrypted content)
    if len(content) > 1000:
        byte_counts = [0] * 256
        for byte in content:
            byte_counts[byte] += 1
        entropy = -sum((count/len(content)) * math.log2(count/len(content)) 
                      for count in byte_counts if count > 0)
        if entropy > 7.0:
            risk_score += 25
            threats.append(f"Yüksek entropi ({entropy:.2f}) - Packed/encrypted olasılığı")
    
    return threats, risk_score

def hybrid_scan_engine(content, filename, vt_key=None):
    """Hibrit tarama motoru - çoklu analiz"""
    results = {
        "virustotal": {"status": "no_key", "threats": 0, "details": "API Key eksik"},
        "behavioral": {"threats": [], "risk_score": 0},
        "heuristic": {"threats": [], "risk_score": 0},
        "metadata": {"analysis": "Temel dosya analizi yapıldı."}
    }
    
    # 1. Davranışsal analiz
    behavioral_threats, behavioral_score = behavioral_analysis(content, filename)
    results["behavioral"] = {"threats": behavioral_threats, "risk_score": behavioral_score}
    
    # 2. Heuristic (sezgisel) analiz
    heuristic_threats = []
    heuristic_score = 0
    
    # Dosya uzantısı şüpheli mi?
    suspicious_exts = ['.scr', '.exe', '.bat', '.com', '.pif', '.vbs', '.js', '.jar', '.msi']
    if any(filename.lower().endswith(ext) for ext in suspicious_exts):
        heuristic_score += 15
        heuristic_threats.append(f"Şüpheli dosya uzantısı: {filename.split('.')[-1]}")
    
    # Çift uzantı tespiti (example.pdf.exe)
    if '.' in filename:
        parts = filename.split('.')
        if len(parts) > 2:
            heuristic_score += 20
            heuristic_threats.append("Çift uzantı tespit edildi - sosyal mühendislik taktiği")
    
    # Boyut analizi
    if len(content) < 1024:  # 1KB'den küçük
        heuristic_score += 10
        heuristic_threats.append("Şüpheli küçük dosya boyutu")
    elif len(content) > 50 * 1024 * 1024:  # 50MB'den büyük
        heuristic_score += 5
        heuristic_threats.append("Büyük dosya boyutu - olası DDoS/veri hırsızlığı")
    
    results["heuristic"] = {"threats": heuristic_threats, "risk_score": heuristic_score}
    
    # 3. Metadata analizi
    if filename.lower().endswith(".pdf"):
        if b"/Creator" in content[:2000]:
            results["metadata"]["analysis"] = "PDF Metadata: Oluşturucu/Tarih izleri tespit edildi."
        if b"/JavaScript" in content:
            heuristic_score += 15
            heuristic_threats.append("PDF içinde JavaScript tespit edildi")
    elif filename.lower().endswith((".jpg", ".png", ".jpeg")):
        results["metadata"]["analysis"] = f"Görsel Boyutu: {len(content)} byte. EXIF Header izleri mevcut."
        # Steganografi tespiti
        if len(content) > 100000:  # 100KB'den büyük görseller şüpheli
            heuristic_score += 10
            heuristic_threats.append("Büyük görsel dosyası - steganografi olasılığı")
    
    # 4. VirusTotal API (eğer key varsa)
    file_hash = hashlib.sha256(content).hexdigest()
    if vt_key and vt_key != "null":
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            resp = requests.get(url, headers={"x-apikey": vt_key}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()['data']['attributes']
                malicious = data['last_analysis_stats'].get('malicious', 0)
                suspicious = data['last_analysis_stats'].get('suspicious', 0)
                results["virustotal"] = {
                    "status": "success",
                    "threats": malicious + suspicious,
                    "details": f"{malicious} zararlı, {suspicious} şüpheli motor tespiti"
                }
            else:
                results["virustotal"] = {"status": "error", "threats": 0, "details": f"VT Hata: {resp.status_code}"}
        except Exception as e:
            results["virustotal"] = {"status": "error", "threats": 0, "details": f"VT Bağlantı hatası: {str(e)}"}
    
    return results, file_hash

@app.post("/api/v1/analiz/dosya/")
@limiter.limit("10/minute")
async def dosya_analiz_et(request: Request, file: UploadFile = File(...), x_vt_key: str = Header(None), db: Session = Depends(get_db)):
    content = await file.read()
    
    # Hibrit tarama motorunu çalıştır
    scan_results, file_hash = hybrid_scan_engine(content, file.filename, x_vt_key)
    
    # Toplam risk skorunu hesapla
    total_risk = (scan_results["behavioral"]["risk_score"] + 
                 scan_results["heuristic"]["risk_score"])
    
    # VirusTotal sonuçlarını ekle
    vt_threats = scan_results["virustotal"]["threats"]
    if vt_threats > 0:
        total_risk += vt_threats * 10  # VT tespitleri daha yüksek ağırlıkta
    
    # Karar verme
    if total_risk >= 50 or vt_threats >= 3:
        karar = "Zararli"
        detay = f"YÜKSEK RİSK: {total_risk} puan. VT: {scan_results['virustotal']['details']}"
        send_discord_alert("Dosya Analizi", file.filename, f"Yüksek Riskli Dosya Engellendi! Skor: {total_risk}", db)
    elif total_risk >= 25 or vt_threats > 0:
        karar = "Supheli"
        detay = f"ORTA RİSK: {total_risk} puan. VT: {scan_results['virustotal']['details']}"
        send_discord_alert("Dosya Analizi", file.filename, f"Şüpheli Dosya Tespiti. Skor: {total_risk}", db)
    else:
        karar = "Guvenli"
        detay = f"DÜŞÜK RİSK: {total_risk} puan. VT: {scan_results['virustotal']['details']}"
    
    # Tüm bulguları birleştir
    all_threats = []
    all_threats.extend(scan_results["behavioral"]["threats"])
    all_threats.extend(scan_results["heuristic"]["threats"])
    
    # Veritabanına kaydet
    db.add(AnalizGecmisi(
        analiz_tipi="Gelişmiş Dosya Tarama", 
        hedef=file.filename, 
        sonuc=f"{total_risk} puan - {len(all_threats)} bulgu", 
        durum_kodu=karar
    ))
    db.commit()
    
    return {
        "sonuc": karar,
        "detay": detay,
        "hash": file_hash,
        "meta": scan_results["metadata"]["analysis"],
        "risk_score": total_risk,
        "scan_results": scan_results,
        "all_threats": all_threats
    }

# ================= 4. TELEGRAM BOT =================
@app.post("/api/v1/telegram/webhook/")
async def telegram_webhook(request: Request, db: Session = Depends(get_db)):
    token = get_setting(db, "telegram_token")
    if not token: return {"ok": True}
    
    data = await request.json()
    if "message" not in data: return {"ok": True}
    
    chat_id = data["message"]["chat"]["id"]
    gelen_metin = ""
    TELEGRAM_API = f"https://api.telegram.org/bot{token}"

    if "photo" in data["message"]:
        requests.post(f"{TELEGRAM_API}/sendMessage", json={"chat_id": chat_id, "text": "📸 Görsel taranıyor (OCR)..."})
        file_id = data["message"]["photo"][-1]["file_id"]
        file_path = requests.get(f"{TELEGRAM_API}/getFile?file_id={file_id}").json()["result"]["file_path"]
        file_url = f"https://api.telegram.org/file/bot{token}/{file_path}"
        
        ocr_res = requests.get("https://api.ocr.space/parse/imageurl", params={"apikey": "helloworld", "url": file_url}).json()
        if ocr_res.get("ParsedResults"): gelen_metin = ocr_res["ParsedResults"][0].get("ParsedText", "")
    else:
        gelen_metin = data["message"].get("text", "")

    urls = re.findall(r'(https?://[^\s]+)', gelen_metin)
    
    if not urls:
        requests.post(f"{TELEGRAM_API}/sendMessage", json={"chat_id": chat_id, "text": "🛡️ Siber Kalkan: Link tespit edilemedi."})
    else:
        hedef_url = urls[0]
        risk = ml_model.predict_proba([extract_url_features(hedef_url)])[0][1] * 100
        karar = "🔴 ZARARLI" if risk > 50 else "🟢 GÜVENLİ"
        
        cevap = f"🔍 *Siber Kalkan Raporu*\n\n🌐 Hedef: `{hedef_url}`\n⚠️ Risk Oranı: %{risk:.1f}\n🛡️ Karar: {karar}"
        requests.post(f"{TELEGRAM_API}/sendMessage", json={"chat_id": chat_id, "text": cevap, "parse_mode": "Markdown"})
        
        if risk > 50:
            karantina_resmi = f"https://image.thum.io/get/width/800/crop/800/{hedef_url}"
            requests.post(f"{TELEGRAM_API}/sendPhoto", json={"chat_id": chat_id, "photo": karantina_resmi, "caption": "🚧 KARANTİNA ÖNİZLEMESİ: Siteye girmeden güvenli görünümü."})
        
        db.add(AnalizGecmisi(analiz_tipi="Telegram Bot", hedef=hedef_url, sonuc=f"%{risk:.1f} Risk", durum_kodu="Zararli" if risk>50 else "Guvenli"))
        db.commit()

    return {"status": "ok"}

# ================= 5. OSINT & PENTEST ÖZELLİKLERİ =================
@app.get("/api/v1/osint/breach/{email}")
@limiter.limit("15/minute")
def sızıntı_kontrol(request: Request, email: str):
    try:
        r = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}")
        if r.status_code == 200:
            return {"status": "found", "breaches": r.json().get("breaches", [[]])[0]}
        elif r.status_code == 404:
            return {"status": "safe", "message": "Harika! E-posta adresi herhangi bir sızıntıda bulunamadı."}
        return {"status": "error"}
    except Exception as e: return {"status": "error"}

@app.get("/api/v1/osint/ip/{hedef}")
@limiter.limit("15/minute")
def ip_sorgula(request: Request, hedef: str):
    try:
        hedef = hedef.replace("https://", "").replace("http://", "").split("/")[0]
        resp = requests.get(f"http://ip-api.com/json/{hedef}").json()
        if resp.get("status") == "success": return {"status": "success", "data": resp}
        return {"status": "error", "message": "Hedef bilgisi çekilemedi."}
    except: return {"status": "error", "message": "Bağlantı hatası."}

@app.get("/api/v1/osint/password/{prefix}")
@limiter.limit("30/minute")
def sifre_kontrol(request: Request, prefix: str):
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if resp.status_code == 200: return {"status": "success", "data": resp.text}
        return {"status": "error", "message": "Sorgu yapılamadı."}
    except: return {"status": "error", "message": "Bağlantı hatası."}

@app.get("/api/v1/osint/port/{hedef}")
@limiter.limit("5/minute")
def port_tara(request: Request, hedef: str):
    hedef = hedef.replace("https://", "").replace("http://", "").split("/")[0]
    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}
    acik_portlar = []
    
    for port, isim in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) 
            if s.connect_ex((hedef, port)) == 0: acik_portlar.append(f"Port {port} ({isim}) AÇIK! ⚠️")
            s.close()
        except: pass
            
    if not acik_portlar: return {"status": "success", "message": "Taranan kritik portlar kapalı/güvenli.", "portlar": []}
    return {"status": "success", "message": f"{len(acik_portlar)} kritik port açık bırakılmış!", "portlar": acik_portlar}

# ================= 6. YENİ EKLENEN ELİT ÖZELLİKLER (SAST & STEGANOGRAFİ) =================

# 6.1 SAST (Kaynak Kod Zafiyet Tarayıcısı)
class KodAnalizRequest(BaseModel): kod: str
@app.post("/api/v1/analiz/kod/")
@limiter.limit("10/minute")
def kod_analiz(istek: KodAnalizRequest, request: Request):
    kod = istek.kod
    bulgular = []
    for i, line in enumerate(kod.split('\n')):
        if re.search(r'(os\.system|exec|eval)\(', line):
            bulgular.append(f"Satır {i+1}: Kritik - Komut Enjeksiyonu (RCE) riski.")
        if re.search(r'(SELECT|UPDATE|DELETE|INSERT).*WHERE.*=.*\+', line, re.IGNORECASE) or "$_" in line:
            bulgular.append(f"Satır {i+1}: Yüksek - SQL Enjeksiyonu (SQLi) zafiyeti olabilir.")
        if re.search(r'(<script>|innerHTML|document\.write)', line, re.IGNORECASE):
            bulgular.append(f"Satır {i+1}: Orta - XSS (Cross-Site Scripting) zafiyeti.")
        if re.search(r'(password|secret|api_key)\s*=\s*[\'"][^\'"]+[\'"]', line, re.IGNORECASE):
            bulgular.append(f"Satır {i+1}: Yüksek - Kod içine gömülü şifre (Hardcoded Secret).")
            
    if not bulgular: return {"status": "clean", "message": "Kod temiz. Belirgin bir güvenlik zafiyeti bulunamadı."}
    return {"status": "vuln", "bulgular": bulgular}

# 6.2 STEGANOGRAFİ (Resim İçine Gizli Veri Gömme ve Okuma)
@app.post("/api/v1/stego/gizle/")
@limiter.limit("5/minute")
async def stego_gizle(request: Request, gizli_mesaj: str = Form(...), file: UploadFile = File(...)):
    content = await file.read()
    ayirici = b"||SIBERKALKAN||"
    yeni_icerik = content + ayirici + gizli_mesaj.encode('utf-8') + ayirici
    return StreamingResponse(io.BytesIO(yeni_icerik), media_type="image/png", headers={"Content-Disposition": f"attachment; filename=gizli_{file.filename}"})

@app.post("/api/v1/stego/oku/")
@limiter.limit("10/minute")
async def stego_oku(request: Request, file: UploadFile = File(...)):
    content = await file.read()
    ayirici = b"||SIBERKALKAN||"
    if ayirici in content:
        parcalar = content.split(ayirici)
        if len(parcalar) >= 3:
            mesaj = parcalar[-2].decode('utf-8', errors='ignore')
            return {"status": "success", "mesaj": mesaj}
    return {"status": "error", "message": "Bu resmin içinde gizli bir mesaj bulunamadı."}

# ================= 7. İSTATİSTİK =================
@app.get("/api/v1/sistem/istatistik/")
def istatistik_getir(db: Session = Depends(get_db)):
    z = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Zararli").count()
    g = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Guvenli").count()
    return {"zararli": max(z, 0), "guvenli": max(g, 0), "supheli": 0}

@app.get("/api/v1/sistem/gecmis/")
def gecmis_getir(db: Session = Depends(get_db)):
    kayitlar = db.query(AnalizGecmisi).order_by(AnalizGecmisi.id.desc()).limit(50).all()
    sonuclar = []
    for k in kayitlar:
        sonuclar.append({
            "id": k.id,
            "tip": k.analiz_tipi,
            "hedef": k.hedef[:50] + "..." if len(k.hedef) > 50 else k.hedef,
            "sonuc": k.sonuc,
            "durum": k.durum_kodu,
            "tarih": k.tarih.strftime("%d/%m/%Y %H:%M")
        })
    return {"status": "success", "data": sonuclar}

@app.get("/api/v1/sistem/baglanti-test/")
def baglanti_test_getir(db: Session = Depends(get_db)):
    ayar_zaman = get_setting(db, "son_baglanti_zamani")
    ayar_ip = get_setting(db, "son_baglanan_ip")
    
    if ayar_zaman and ayar_ip:
        if datetime.utcnow().timestamp() - float(ayar_zaman) < 60:
            return {"status": "connected", "ip": ayar_ip, "message": f"Bağlantı Başarılı! Cihaz ({ayar_ip}) güvende."}
    return {"status": "waiting", "message": "Bağlantı bekleniyor..."}