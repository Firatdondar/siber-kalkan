from fastapi import FastAPI, Request, UploadFile, File, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel
import hashlib, requests, re, imaplib, email
from email.header import decode_header
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sklearn.ensemble import RandomForestClassifier

# --- KONFİGÜRASYON ---
DISCORD_WEBHOOK_URL = "BURAYA_DISCORD_WEBHOOK_URL_YAPISTIR" 

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
    tarih = Column(DateTime, default=datetime.utcnow)

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

def send_discord_alert(analiz_tipi, hedef, detay):
    if "http" in DISCORD_WEBHOOK_URL:
        try: requests.post(DISCORD_WEBHOOK_URL, json={"content": f"🚨 **SİBER KALKAN ALARMI** 🚨\n**Kaynak:** {analiz_tipi}\n**Hedef:** {hedef}\n**Bulgu:** {detay}"})
        except: pass

app = FastAPI(title="Siber Kalkan API")
app.state.limiter = Limiter(key_func=get_remote_address)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- AI MODEL (Link ve Oltalama Zekası) ---
def extract_url_features(url):
    return [len(url), url.count('.'), url.count('-'), 1 if '@' in url else 0, 1 if re.search(r'\d+\.\d+', url) else 0, sum(1 for k in ['bank','login','secure','free','kazandiniz','bonus','hediye','fatura'] if k in url.lower())]
ml_model = RandomForestClassifier(n_estimators=10, random_state=42)
ml_model.fit([extract_url_features("google.com"), extract_url_features("kacak-bahis-free-bonus.com")], [0, 1])

# --- PWA ROTALARI ---
@app.get("/")
def anasayfa(): return FileResponse("index.html")

@app.get("/manifest.json")
def get_manifest(): return FileResponse("manifest.json")

@app.get("/sw.js")
def get_sw(): return FileResponse("sw.js")

# ================= AYAR KAYDETME MOTORU =================
class SistemAyarRequest(BaseModel):
    telegram_token: str
    render_url: str
    gmail_adres: str = ""
    gmail_sifre: str = ""

@app.post("/api/v1/ayarlar/kaydet/")
def ayar_kaydet(istek: SistemAyarRequest, db: Session = Depends(get_db)):
    ayarlar = {
        "telegram_token": istek.telegram_token,
        "gmail_adres": istek.gmail_adres,
        "gmail_sifre": istek.gmail_sifre
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
def email_tara(db: Session = Depends(get_db)):
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
                            send_discord_alert("E-Posta (Gmail)", url, f"%{risk:.1f} Riskli Oltalama Linki!")
                            db.add(AnalizGecmisi(analiz_tipi="E-Posta", hedef=url, sonuc=f"%{risk:.1f} Risk", durum_kodu="Zararli"))
        db.commit()
        return {"status": "success", "message": f"Tarama tamamlandı. {tehdit_sayisi} adet tehdit engellendi."}
    except Exception as e:
        return {"status": "error", "message": f"Bağlantı hatası: {str(e)}"}

# ================= 2. BİLDİRİM VE MESAJ MOTORU (YAPAY ZEKA) =================
class MobileRequest(BaseModel): message: str
@app.post("/api/v1/analiz/mobil/")
def mobil_analiz(istek: MobileRequest, db: Session = Depends(get_db)):
    msg = istek.message
    urls = re.findall(r'(https?://[^\s]+)', msg)
    if not urls: return {"status": "clean", "message": "Metin temiz. Tıklanabilir link bulunamadı."}
    
    ilk_url = urls[0]
    son_url = ilk_url
    try: son_url = requests.head(ilk_url, allow_redirects=True, timeout=4).url
    except: pass

    risk = ml_model.predict_proba([extract_url_features(son_url)])[0][1] * 100
    typo = any(x in son_url.lower() for x in ['g00gle', 'instaqram', 'bahis', 'kazandiniz', 'bonus'])
    if typo: risk = max(risk, 90.0)

    karar = "Zararli" if risk > 50 else "Guvenli"
    if karar == "Zararli": send_discord_alert("Mobil Bildirim", son_url, f"Yapay Zeka Riski: %{risk:.1f}")
    
    db.add(AnalizGecmisi(analiz_tipi="Bildirim/Mesaj", hedef=son_url, sonuc=f"%{risk:.1f} Risk", durum_kodu=karar))
    db.commit()
    return {"status": "found", "ilk_url": ilk_url, "son_url": son_url, "risk": round(risk,2), "typo": typo, "karar": karar}

# ================= 3. VIRUSTOTAL DOSYA ANALİZ MOTORU =================
@app.post("/api/v1/analiz/dosya/")
async def dosya_analiz_et(file: UploadFile = File(...), x_vt_key: str = Header(None), db: Session = Depends(get_db)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    if not x_vt_key or x_vt_key == "null": return {"sonuc": "Bilinmiyor", "detay": "API Key eksik!"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        resp = requests.get(url, headers={"x-apikey": x_vt_key})
        if resp.status_code == 200:
            malicious = resp.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            karar = "Zararli" if malicious > 0 else "Guvenli"
            db.add(AnalizGecmisi(analiz_tipi="Dosya Tarama", hedef=file.filename, sonuc=f"{malicious} Uyarı", durum_kodu=karar))
            db.commit()
            return {"sonuc": karar, "detay": f"{malicious} motor dosyayı ZARARLI buldu.", "hash": file_hash}
        return {"sonuc": "Hata", "detay": f"VT Hata Kodu: {resp.status_code}", "hash": file_hash}
    except Exception as e: return {"sonuc": "Hata", "detay": str(e), "hash": file_hash}

# ================= 4. TELEGRAM BOT (OCR VE KARANTİNA DESTEKLİ) =================
@app.post("/api/v1/telegram/webhook/")
async def telegram_webhook(request: Request, db: Session = Depends(get_db)):
    token = get_setting(db, "telegram_token")
    if not token: return {"ok": True}
    
    data = await request.json()
    if "message" not in data: return {"ok": True}
    
    chat_id = data["message"]["chat"]["id"]
    gelen_metin = ""
    TELEGRAM_API = f"https://api.telegram.org/bot{token}"

    # OCR GÖRÜNTÜ İŞLEME: Eğer fotoğraf gönderildiyse
    if "photo" in data["message"]:
        requests.post(f"{TELEGRAM_API}/sendMessage", json={"chat_id": chat_id, "text": "📸 Görsel taranıyor (OCR)..."})
        file_id = data["message"]["photo"][-1]["file_id"]
        file_path = requests.get(f"{TELEGRAM_API}/getFile?file_id={file_id}").json()["result"]["file_path"]
        file_url = f"https://api.telegram.org/file/bot{token}/{file_path}"
        
        # Ücretsiz OCR API (Görselden metin çıkarma)
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
        
        # KARANTİNA ODASI: Eğer zararlıysa güvenli ekran görüntüsünü (screenshot) at
        if risk > 50:
            karantina_resmi = f"https://image.thum.io/get/width/800/crop/800/{hedef_url}"
            requests.post(f"{TELEGRAM_API}/sendPhoto", json={"chat_id": chat_id, "photo": karantina_resmi, "caption": "🚧 KARANTİNA ÖNİZLEMESİ: Siteye girmeden güvenli görünümü."})
        
        db.add(AnalizGecmisi(analiz_tipi="Telegram Bot", hedef=hedef_url, sonuc=f"%{risk:.1f} Risk", durum_kodu="Zararli" if risk>50 else "Guvenli"))
        db.commit()

    return {"status": "ok"}

# ================= 5. İSTATİSTİK =================
@app.get("/api/v1/sistem/istatistik/")
def istatistik_getir(db: Session = Depends(get_db)):
    z = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Zararli").count()
    g = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Guvenli").count()
    return {"zararli": max(z, 0), "guvenli": max(g, 0), "supheli": 0}