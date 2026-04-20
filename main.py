from fastapi import FastAPI, Request, UploadFile, File, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel
import hashlib, requests, re
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

Base.metadata.create_all(bind=engine)
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def send_discord_alert(analiz_tipi, hedef, detay):
    if "http" in DISCORD_WEBHOOK_URL:
        try: requests.post(DISCORD_WEBHOOK_URL, json={"content": f"🚨 **OTOMASYON ALARMI** 🚨\n**Tür:** {analiz_tipi}\n**Hedef:** {hedef}\n**Bulgu:** {detay}"})
        except: pass

app = FastAPI(title="Siber Kalkan API")
app.state.limiter = Limiter(key_func=get_remote_address)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- AI MODEL (Link ve Oltalama Zekası) ---
def extract_url_features(url):
    return [len(url), url.count('.'), url.count('-'), 1 if '@' in url else 0, 1 if re.search(r'\d+\.\d+', url) else 0, sum(1 for k in ['bank','login','secure','free','kazandiniz','bonus','hediye'] if k in url.lower())]
ml_model = RandomForestClassifier(n_estimators=10, random_state=42)
ml_model.fit([extract_url_features("google.com"), extract_url_features("kacak-bahis-free-bonus.com")], [0, 1])

# --- PWA ROTALARI ---
@app.get("/")
def anasayfa(): return FileResponse("index.html")

@app.get("/manifest.json")
def get_manifest(): return FileResponse("manifest.json")

@app.get("/sw.js")
def get_sw(): return FileResponse("sw.js")

# ================= 1. BİLDİRİM VE MESAJ MOTORU (YAPAY ZEKA) =================
class MobileRequest(BaseModel): message: str
@app.post("/api/v1/analiz/mobil/")
def mobil_analiz(istek: MobileRequest, db: Session = Depends(get_db)):
    msg = istek.message
    urls = re.findall(r'(https?://[^\s]+)', msg)
    if not urls: 
        return {"status": "clean", "message": "Metin temiz. Tıklanabilir link bulunamadı."}
    
    ilk_url = urls[0]
    son_url = ilk_url
    
    try:
        resp = requests.head(ilk_url, allow_redirects=True, timeout=4)
        son_url = resp.url
    except: pass

    risk = ml_model.predict_proba([extract_url_features(son_url)])[0][1] * 100
    typo = any(x in son_url.lower() for x in ['g00gle', 'instaqram', 'bahis', 'kazandiniz', 'bonus'])
    if typo: risk = max(risk, 90.0)

    karar = "Zararli" if risk > 50 else "Guvenli"
    if karar == "Zararli": 
        send_discord_alert("Şüpheli Mesaj Tespit Edildi", son_url, f"Yapay Zeka Riski: %{risk:.1f}")
    
    db.add(AnalizGecmisi(analiz_tipi="Bildirim/Mesaj", hedef=son_url, sonuc=f"%{risk:.1f} Risk", durum_kodu=karar))
    db.commit()
    
    return {"status": "found", "ilk_url": ilk_url, "son_url": son_url, "risk": round(risk,2), "typo": typo, "karar": karar}

# ================= 2. VIRUSTOTAL DOSYA ANALİZ MOTORU =================
@app.post("/api/v1/analiz/dosya/")
async def dosya_analiz_et(file: UploadFile = File(...), x_vt_key: str = Header(None), db: Session = Depends(get_db)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    if not x_vt_key or x_vt_key == "null":
        return {"sonuc": "Bilinmiyor", "detay": "API Key eksik! Lütfen VirusTotal Dosya & Link Analizi bölümünden kendi VirusTotal Key'inizi girin.", "hash": file_hash}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": x_vt_key}
    
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            karar = "Zararli" if malicious > 0 else "Guvenli"
            
            db.add(AnalizGecmisi(analiz_tipi="Dosya Tarama", hedef=file.filename, sonuc=f"{malicious}/{total} Motor Uyarı Verdi", durum_kodu=karar))
            db.commit()
            
            return {"sonuc": karar, "detay": f"VirusTotal Raporu: {malicious} / {total} güvenlik motoru dosyayı ZARARLI buldu.", "hash": file_hash}
        elif resp.status_code == 404:
            return {"sonuc": "Temiz / Bilinmiyor", "detay": "Bu dosya VirusTotal veritabanında hiç görülmedi. Tamamen zararsız veya çok yeni bir dosya olabilir.", "hash": file_hash}
        elif resp.status_code == 401:
            return {"sonuc": "Hata", "detay": "Girdiğiniz VirusTotal API Key geçersiz veya süresi dolmuş.", "hash": file_hash}
        else:
            return {"sonuc": "Hata", "detay": f"VT Bağlantı Hatası: Kodu {resp.status_code}", "hash": file_hash}
    except Exception as e:
        return {"sonuc": "Hata", "detay": "Sistem Hatası: " + str(e), "hash": file_hash}

# ================= 3. İSTATİSTİK (Arayüz İçin) =================
@app.get("/api/v1/sistem/istatistik/")
def istatistik_getir(db: Session = Depends(get_db)):
    z = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Zararli").count()
    g = db.query(AnalizGecmisi).filter(AnalizGecmisi.durum_kodu == "Guvenli").count()
    return {"zararli": max(z, 0), "guvenli": max(g, 0), "supheli": 0}