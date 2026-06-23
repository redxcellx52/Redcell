"""
REDCELL AR-GE — Backend API (Güvenlik Güncellemesi)
Tüm 12 güvenlik katmanı entegre edildi.
"""

import os
import json
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import asyncpg
from pywebpush import webpush, WebPushException

# Güvenlik modülleri
from backend.security.auth import (
    sifre_hashle, sifre_dogrula,
    token_olustur, token_coz,
    giris_denemesi_kontrol, giris_basarisiz, giris_basarili,
    tfa_secret_olustur, tfa_qr_olustur, tfa_dogrula,
)
from backend.security.logger import logger_kur, IstekLogMiddleware
from backend.monitoring.izleme import PerformansMiddleware, sentry_baslat, router as izleme_router
from backend.monitoring.sistem_durumu import router as sistem_router
from backend.routes.konsol import router as konsol_router
from backend.routes.eksik_rotalar import router as eksik_router
from backend.i18n import t
from backend.middleware.security import (
    RateLimitMiddleware, WAFMiddleware, GuvenlikHeaderlariMiddleware,
    IZINLI_ORIGINLER,
)

# ---------------------------------------------------------------------------
# Logger başlat
# ---------------------------------------------------------------------------
logger_kur()
sentry_baslat()
logger = logging.getLogger("REDCELL")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
FRONTEND_DIR  = Path(__file__).parent.parent / "frontend"
DB_DSN        = os.getenv("DATABASE_URL", "postgresql://postgres:changeme@postgres:5432/redcell")
VAPID_PRIVATE = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC  = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_EMAIL   = os.getenv("VAPID_EMAIL", "mailto:admin@redxcell.com")

# ---------------------------------------------------------------------------
# DB Pool
# ---------------------------------------------------------------------------
db_pool: asyncpg.Pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    db_pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=10)
    logger.info("DB bağlantı havuzu hazır.")
    # Migration'ları uygula
    try:
        from backend.migrations.migrate import migrate
        await migrate()
    except Exception as e:
        logger.warning("Migration hatası (ilk kurulumda normal): %s", e)
    yield
    await db_pool.close()

async def get_db():
    async with db_pool.acquire() as conn:
        yield conn

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="REDCELL API",
    docs_url=None,    # Production'da Swagger kapalı
    redoc_url=None,
    lifespan=lifespan,
)

# Middleware sırası önemli (dıştan içe çalışır)
app.add_middleware(GuvenlikHeaderlariMiddleware)
app.add_middleware(WAFMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(IstekLogMiddleware)
app.add_middleware(PerformansMiddleware)
app.add_middleware(CORSMiddleware,
    allow_origins=IZINLI_ORIGINLER,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
)

security = HTTPBearer(auto_error=False)

# Ek router'lar
app.include_router(izleme_router)
app.include_router(eksik_router)
app.include_router(sistem_router)
app.include_router(konsol_router)

# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token gerekli")
    try:
        return token_coz(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş token")

# ---------------------------------------------------------------------------
# SAYFALAR (.html yok)
# ---------------------------------------------------------------------------
@app.get("/",             response_class=HTMLResponse)
async def anasayfa():     return (FRONTEND_DIR / "index.html").read_text("utf-8")

@app.get("/admin",        response_class=HTMLResponse)
async def admin_panel():  return (FRONTEND_DIR / "admin.html").read_text("utf-8")

@app.get("/portal",       response_class=HTMLResponse)
async def musteri():      return (FRONTEND_DIR / "portal.html").read_text("utf-8")

@app.get("/ekip",         response_class=HTMLResponse)
async def ekip():         return (FRONTEND_DIR / "ekip.html").read_text("utf-8")

@app.get("/rapor-motoru", response_class=HTMLResponse)
async def rapor():        return (FRONTEND_DIR / "rapor-motoru.html").read_text("utf-8")

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# ---------------------------------------------------------------------------
# 1-2-4-5-9. AUTH (Bcrypt + JWT + Brute Force + 2FA)
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(body: dict, request: Request, db=Depends(get_db)):
    ip = request.client.host

    # 9. Brute force kontrolü
    izin_var, kalan = giris_denemesi_kontrol(ip)
    if not izin_var:
        raise HTTPException(
            status_code=429,
            detail=f"Çok fazla başarısız deneme. {kalan} saniye bekleyin."
        )

    kullanici = body.get("kullanici", "").strip()
    sifre     = body.get("sifre", "").strip()
    rol       = body.get("rol", "admin")
    tfa_kod   = body.get("tfa_kodu", "")

    row = await db.fetchrow(
        "SELECT id, ad, sifre_hash, tfa_aktif, tfa_secret FROM kullanicilar "
        "WHERE kullanici=$1 AND rol=$2",
        kullanici, rol
    )

    # 2. Bcrypt doğrulama
    if not row or not sifre_dogrula(sifre, row["sifre_hash"]):
        giris_basarisiz(ip)
        logger.warning("[Auth] Başarısız giriş: %s | IP: %s", kullanici, ip)
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı")

    # 12. 2FA kontrolü (aktifse)
    if row["tfa_aktif"]:
        if not tfa_kod:
            return JSONResponse({"tfa_gerekli": True, "mesaj": "2FA kodu gerekli"})
        if not tfa_dogrula(row["tfa_secret"], tfa_kod):
            giris_basarisiz(ip)
            raise HTTPException(status_code=401, detail="Geçersiz 2FA kodu")

    giris_basarili(ip)

    # 5. Güçlü JWT
    token = token_olustur({"id": row["id"], "ad": row["ad"], "rol": rol})
    logger.info("[Auth] Başarılı giriş: %s (%s) | IP: %s", kullanici, rol, ip)
    return {"token": token, "ad": row["ad"], "rol": rol, "tfa_aktif": row["tfa_aktif"]}


# ---------------------------------------------------------------------------
# 12. 2FA YÖNETİMİ (Açıp Kapanabilir)
# ---------------------------------------------------------------------------
@app.post("/api/auth/2fa/aktifles")
async def tfa_aktifles(user=Depends(get_current_user), db=Depends(get_db)):
    """2FA'yı aktif eder. QR kodu döner, kullanıcı Authenticator'a ekler."""
    secret = tfa_secret_olustur()
    qr_b64 = tfa_qr_olustur(secret, user["ad"])

    await db.execute(
        "UPDATE kullanicilar SET tfa_secret=$1, tfa_aktif=false WHERE id=$2",
        secret, user["id"]
    )
    return {
        "secret":   secret,
        "qr_kodu":  qr_b64,
        "mesaj":    "QR kodu Authenticator uygulamasına tara, sonra doğrula"
    }

@app.post("/api/auth/2fa/dogrula")
async def tfa_dogrula_endpoint(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    """İlk kurulumda QR tarandıktan sonra kodu doğrular ve 2FA'yı aktif eder."""
    row = await db.fetchrow("SELECT tfa_secret FROM kullanicilar WHERE id=$1", user["id"])
    if not row or not tfa_dogrula(row["tfa_secret"], body.get("kod", "")):
        raise HTTPException(status_code=400, detail="Geçersiz kod. Tekrar dene.")
    await db.execute("UPDATE kullanicilar SET tfa_aktif=true WHERE id=$1", user["id"])
    return {"mesaj": "2FA aktif edildi"}

@app.post("/api/auth/2fa/kapat")
async def tfa_kapat(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    """2FA'yı kapatır. Mevcut şifre gerekli."""
    row = await db.fetchrow("SELECT sifre_hash FROM kullanicilar WHERE id=$1", user["id"])
    if not sifre_dogrula(body.get("sifre", ""), row["sifre_hash"]):
        raise HTTPException(status_code=401, detail="Şifre hatalı")
    await db.execute(
        "UPDATE kullanicilar SET tfa_aktif=false, tfa_secret=NULL WHERE id=$1",
        user["id"]
    )
    return {"mesaj": "2FA devre dışı bırakıldı"}

@app.get("/api/auth/2fa/durum")
async def tfa_durum(user=Depends(get_current_user), db=Depends(get_db)):
    row = await db.fetchrow("SELECT tfa_aktif FROM kullanicilar WHERE id=$1", user["id"])
    return {"tfa_aktif": row["tfa_aktif"] if row else False}

# ---------------------------------------------------------------------------
# TALEPLER
# ---------------------------------------------------------------------------
@app.get("/api/talepler")
async def talepler_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch("SELECT * FROM talepler ORDER BY tarih DESC")
    return [dict(r) for r in rows]

@app.post("/api/talepler")
async def talep_ekle(body: dict, db=Depends(get_db)):
    talep_id = "T" + str(int(datetime.utcnow().timestamp()))[-6:]
    await db.execute("""
        INSERT INTO talepler (id, ad, email, hizmet, ozet, hedef, oncelik, kapsam, durum, tarih)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'bekleyen',NOW()::date)
    """, talep_id, body["ad"], body["email"], body["hizmet"],
        body.get("ozet",""), body.get("hedef",""),
        body.get("oncelik","Normal"), json.dumps(body.get("kapsam",[])))
    await _bildirim_ekle(db, "talep", "🆕 Yeni Talep",
        f"{body['ad']} — {body['hizmet']}", {"talep_id": talep_id})
    await _push_gonder(db, "🆕 Yeni Talep", f"{body['ad']} — {body['hizmet']}")
    return {"id": talep_id}

@app.patch("/api/talepler/{talep_id}/durum")
async def talep_durum(talep_id: str, body: dict,
                      user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("UPDATE talepler SET durum=$1 WHERE id=$2", body["durum"], talep_id)
    return {"ok": True}

@app.delete("/api/talepler/{talep_id}")
async def talep_sil(talep_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("DELETE FROM talepler WHERE id=$1", talep_id)
    await db.execute("DELETE FROM gorevler WHERE talep_id=$1", talep_id)
    return {"ok": True}

# ---------------------------------------------------------------------------
# RAPORLAR
# ---------------------------------------------------------------------------
@app.get("/api/raporlar")
async def raporlar_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch("SELECT * FROM raporlar ORDER BY tarih DESC")
    return [dict(r) for r in rows]

@app.post("/api/raporlar")
async def rapor_kaydet(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    rapor_id = "R" + str(int(datetime.utcnow().timestamp()))[-6:]
    await db.execute("""
        INSERT INTO raporlar (id, talep_id, ad, hizmet, icerik, tip, tarih)
        VALUES ($1,$2,$3,$4,$5,$6,NOW()::date)
    """, rapor_id, body["talep_id"], body.get("ad",""),
        body.get("hizmet",""), body["icerik"], body.get("tip","text"))
    await db.execute("UPDATE talepler SET durum='tamamlandi' WHERE id=$1", body["talep_id"])
    return {"id": rapor_id}

@app.delete("/api/raporlar/{rapor_id}")
async def rapor_sil(rapor_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("DELETE FROM raporlar WHERE id=$1", rapor_id)
    return {"ok": True}

# ---------------------------------------------------------------------------
# EKİP
# ---------------------------------------------------------------------------
@app.get("/api/ekip")
async def ekip_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch(
        "SELECT id,ad,rol,cert,uzmanlik,durum,eposta,kayit_tarih FROM kullanicilar WHERE rol='ekip'")
    return [dict(r) for r in rows]

@app.post("/api/ekip")
async def uye_ekle(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    uye_id = "U" + str(int(datetime.utcnow().timestamp()))[-6:]
    # 2. Bcrypt ile şifrele
    hash_deger = sifre_hashle(body["sifre"])
    await db.execute("""
        INSERT INTO kullanicilar
          (id, ad, kullanici, sifre_hash, rol, eposta, cert, uzmanlik, durum, kayit_tarih)
        VALUES ($1,$2,$3,$4,'ekip',$5,$6,$7,'available',NOW()::date)
    """, uye_id, body["ad"], body["kullanici"], hash_deger,
        body.get("eposta",""),
        json.dumps(body.get("cert",[])),
        json.dumps(body.get("uzmanlik",[])))
    return {"id": uye_id}

@app.delete("/api/ekip/{uye_id}")
async def uye_sil(uye_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("DELETE FROM kullanicilar WHERE id=$1 AND rol='ekip'", uye_id)
    return {"ok": True}

# ---------------------------------------------------------------------------
# GÖREVLER
# ---------------------------------------------------------------------------
@app.get("/api/gorevler")
async def gorevler_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch("SELECT * FROM gorevler ORDER BY baslangic_tarih DESC")
    return [dict(r) for r in rows]

@app.patch("/api/gorevler/{gorev_id}")
async def gorev_guncelle(gorev_id: str, body: dict,
                         user=Depends(get_current_user), db=Depends(get_db)):
    izinli = {"notlar","bulgular","ilerleme","durum"}
    sets, vals = [], [gorev_id]
    for k, v in body.items():
        if k in izinli:
            sets.append(f"{k}=${len(vals)+1}")
            vals.append(v)
    if sets:
        await db.execute(f"UPDATE gorevler SET {','.join(sets)} WHERE id=$1", *vals)
    return {"ok": True}

# ---------------------------------------------------------------------------
# BİLDİRİMLER
# ---------------------------------------------------------------------------
@app.get("/api/bildirimler")
async def bildirimler_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch("SELECT * FROM bildirimler ORDER BY tarih DESC LIMIT 100")
    return [dict(r) for r in rows]

@app.post("/api/bildirimler/oku/{bid}")
async def bildirim_oku(bid: str, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("UPDATE bildirimler SET okundu=true WHERE id=$1", bid)
    return {"ok": True}

@app.post("/api/bildirimler/tumunu-oku")
async def tumunu_oku(user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("UPDATE bildirimler SET okundu=true")
    return {"ok": True}

@app.post("/api/bildirim/sistem")
async def sistem_bildirim(body: dict, db=Depends(get_db)):
    """Ajan sistemi ve backup script'i bu endpoint'i kullanır."""
    await _bildirim_ekle(db, body.get("tip","sistem"),
        body["baslik"], body["mesaj"], {})
    return {"ok": True}

# ---------------------------------------------------------------------------
# WEB PUSH
# ---------------------------------------------------------------------------
@app.get("/api/push/vapid-key")
async def vapid_key():
    return {"publicKey": VAPID_PUBLIC}

@app.post("/api/push/abone")
async def push_abone(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("""
        INSERT INTO push_aboneler (endpoint, p256dh, auth, kullanici_id, kayit_tarih)
        VALUES ($1,$2,$3,$4,NOW())
        ON CONFLICT (endpoint) DO UPDATE SET p256dh=$2, auth=$3
    """, body["endpoint"], body["keys"]["p256dh"], body["keys"]["auth"], user["id"])
    return {"ok": True}

# ---------------------------------------------------------------------------
# ADMİN ONAY (Ajan Sistemi)
# ---------------------------------------------------------------------------
_bekleyen_onaylar: dict = {}

@app.post("/api/admin-onay/talep")
async def onay_talep(body: dict, db=Depends(get_db)):
    proje_id = body["proje_id"]
    ozet     = body.get("ozet", "")
    _bekleyen_onaylar[proje_id] = {"status": "pending"}

    await _bildirim_ekle(db, "onay", "🔐 Admin Onayı Gerekli", ozet,
        {"proje_id": proje_id, "tip": "admin_onay"})
    await _push_gonder(db, "🔐 Admin Onayı Gerekli",
        f"Proje {proje_id}: {ozet}", f"/admin?onay={proje_id}")
    return {"ok": True}

@app.post("/api/admin-onay/karar")
async def onay_karar(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    if user["rol"] != "admin":
        raise HTTPException(status_code=403)
    proje_id = body["proje_id"]
    karar    = body["karar"]
    if proje_id not in _bekleyen_onaylar:
        raise HTTPException(status_code=404, detail="Bekleyen onay yok")
    _bekleyen_onaylar[proje_id]["status"] = karar
    logger.info("[Onay] %s → %s | Admin: %s", proje_id, karar, user["ad"])
    return {"ok": True}

@app.get("/api/ajan/onay/{proje_id}")
async def ajan_onay(proje_id: str):
    durum = _bekleyen_onaylar.get(proje_id, {}).get("status", "not_found")
    return {"approved": durum == "approved", "status": durum}

@app.post("/api/ajan/bulgu")
async def ajan_bulgu(body: dict, db=Depends(get_db)):
    await db.execute("""
        INSERT INTO vulnerability_scans
          (project_id, target_ip_domain, vulnerability_title, severity, cve_id, description)
        VALUES ($1,$2,$3,$4,$5,$6)
    """, body["proje_id"], body["hedef"], body["baslik"],
        body["severity"], body.get("cve_id"), body.get("aciklama"))
    return {"ok": True}

# ---------------------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# ---------------------------------------------------------------------------
async def _bildirim_ekle(db, tip, baslik, mesaj, meta):
    bid = "B" + str(int(datetime.utcnow().timestamp()))[-8:]
    await db.execute("""
        INSERT INTO bildirimler (id, tip, baslik, mesaj, meta, tarih, okundu)
        VALUES ($1,$2,$3,$4,$5,NOW(),false)
    """, bid, tip, baslik, mesaj, json.dumps(meta))

async def _push_gonder(db, baslik, govde, url="/admin"):
    if not VAPID_PRIVATE:
        return
    rows = await db.fetch("SELECT endpoint, p256dh, auth FROM push_aboneler")
    payload = json.dumps({"title": baslik, "body": govde, "url": url})
    for row in rows:
        try:
            webpush(
                subscription_info={"endpoint": row["endpoint"],
                                   "keys": {"p256dh": row["p256dh"], "auth": row["auth"]}},
                data=payload,
                vapid_private_key=VAPID_PRIVATE,
                vapid_claims={"sub": VAPID_EMAIL},
            )
        except WebPushException as e:
            logger.warning("[Push] Gönderilemedi: %s", e)
