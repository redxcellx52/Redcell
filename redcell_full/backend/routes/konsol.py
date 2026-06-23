"""
backend/routes/konsol.py
-------------------------
Admin konsol backend.
- 2FA KAPALI → sadece whitelist komutlar çalışır
- 2FA AÇIK   → onaylı serbest shell erişimi
Her komut audit_logs'a yazılır, geri alınamaz işlemler onay ister.
"""

import os
import asyncio
import logging
import subprocess
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.security.auth import token_coz, tfa_dogrula

logger = logging.getLogger("REDCELL.konsol")
router = APIRouter(prefix="/api/konsol")
security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# WHITELIST KOMUTLAR (2FA olmadan çalışır)
# ---------------------------------------------------------------------------
WHITELIST_KOMUTLAR = {

    # Sistem durumu
    "/status": {
        "aciklama": "Sistem servis durumu",
        "komut":    ["docker", "compose", "ps"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": False,
    },
    "/logs backend": {
        "aciklama": "Backend son 50 log satırı",
        "komut":    ["docker", "compose", "logs", "--tail=50", "web"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": False,
    },
    "/logs agents": {
        "aciklama": "Ajan sistemi son 50 log satırı",
        "komut":    ["docker", "compose", "logs", "--tail=50", "agents"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": False,
    },
    "/db stats": {
        "aciklama": "Veritabanı tablo istatistikleri",
        "komut":    ["psql", os.getenv("DATABASE_URL",""), "-c",
                     "SELECT schemaname,tablename,n_live_tup AS satir "
                     "FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"],
        "cwd":      "/",
        "onay_gerekli": False,
    },
    "/backup now": {
        "aciklama": "Manuel yedek al",
        "komut":    ["python3", "scripts/backup.py"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": False,
    },
    "/restart web": {
        "aciklama": "Web servisini yeniden başlat",
        "komut":    ["docker", "compose", "restart", "web"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": True,
    },
    "/restart agents": {
        "aciklama": "Ajan sistemini yeniden başlat",
        "komut":    ["docker", "compose", "restart", "agents"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": True,
    },
    "/update": {
        "aciklama": "Git'ten güncelle ve deploy et",
        "komut":    ["bash", "-c", "git pull origin main && docker compose up -d --build"],
        "cwd":      "/opt/redcell",
        "onay_gerekli": True,
    },
    "/disk": {
        "aciklama": "Disk kullanımı",
        "komut":    ["df", "-h"],
        "cwd":      "/",
        "onay_gerekli": False,
    },
    "/processes": {
        "aciklama": "En çok CPU kullanan 10 process",
        "komut":    ["ps", "aux", "--sort=-%cpu"],
        "cwd":      "/",
        "onay_gerekli": False,
    },
    "/nginx status": {
        "aciklama": "Nginx durum kontrolü",
        "komut":    ["systemctl", "status", "nginx", "--no-pager"],
        "cwd":      "/",
        "onay_gerekli": False,
    },
    "/help": {
        "aciklama": "Kullanılabilir komutlar",
        "komut":    None,  # Özel işlem
        "cwd":      "/",
        "onay_gerekli": False,
    },
}

# Tehlikeli komut desenleri (serbest modda bile engellenir)
TEHLIKELI_DESENLER = [
    "rm -rf", "dd if=", "mkfs", "> /dev/",
    ":(){ :|:& };:", "chmod -R 777 /",
    "DROP TABLE", "DELETE FROM", "TRUNCATE",
    "passwd root", "useradd root",
]


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

async def get_db():
    from backend.main import db_pool
    async with db_pool.acquire() as conn:
        yield conn


def get_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401)
    try:
        return token_coz(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Geçersiz token")


async def audit_yaz(db, user_id: str, komut: str, cikti: str, tip: str = "konsol"):
    import json
    try:
        await db.execute("""
            INSERT INTO audit_logs
              (triggered_by, action_type, target_table, degisiklik, tarih)
            VALUES ($1, $2, $3, $4::jsonb, NOW())
        """, user_id, "KONSOL",
            tip,
            json.dumps({"komut": komut[:500], "cikti_uzunluk": len(cikti)},
                       ensure_ascii=False))
    except Exception as e:
        logger.warning("[Konsol] Audit yazılamadı: %s", e)


async def komutu_calistir(komut_listesi: list, cwd: str, timeout: int = 30) -> str:
    """Komutu güvenli subprocess ile çalıştırır."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *komut_listesi,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd if os.path.exists(cwd) else "/tmp",
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode("utf-8", errors="replace")[:10000]
        except asyncio.TimeoutError:
            proc.kill()
            return f"⏰ Zaman aşımı ({timeout}s)"
    except FileNotFoundError:
        return "❌ Komut bulunamadı"
    except Exception as e:
        return f"❌ Hata: {e}"


# ---------------------------------------------------------------------------
# KOMUT LİSTESİ
# ---------------------------------------------------------------------------

@router.get("/komutlar")
async def komut_listesi(user=Depends(get_user)):
    """Kullanılabilir whitelist komutları döner."""
    if user["rol"] != "admin":
        raise HTTPException(status_code=403)
    return [
        {"komut": k, "aciklama": v["aciklama"], "onay": v["onay_gerekli"]}
        for k, v in WHITELIST_KOMUTLAR.items()
    ]


# ---------------------------------------------------------------------------
# WHITELIST KOMUT ÇALIŞTIR
# ---------------------------------------------------------------------------

@router.post("/calistir")
async def komut_calistir(body: dict, user=Depends(get_user), db=Depends(get_db)):
    """
    Whitelist komut çalıştırır.
    2FA zorunlu değil. Onay gerektiren komutlar için onay_token lazım.
    """
    if user["rol"] != "admin":
        raise HTTPException(status_code=403)

    komut_str = body.get("komut", "").strip()
    onay      = body.get("onaylandi", False)

    # /help özel işlem
    if komut_str == "/help":
        satirlar = ["REDCELL Admin Konsol — Komutlar\n" + "─"*40]
        for k, v in WHITELIST_KOMUTLAR.items():
            onay_ik = " ⚠️ Onay" if v["onay_gerekli"] else ""
            satirlar.append(f"{k:<20} → {v['aciklama']}{onay_ik}")
        satirlar.append("\n2FA aktifken serbest komut da çalıştırabilirsiniz.")
        return {"cikti": "\n".join(satirlar), "durum": "ok"}

    if komut_str not in WHITELIST_KOMUTLAR:
        return {
            "cikti": f"❌ '{komut_str}' tanınmayan komut. /help yazın.",
            "durum": "hata"
        }

    tanim = WHITELIST_KOMUTLAR[komut_str]

    # Onay gerektiren komutlar
    if tanim["onay_gerekli"] and not onay:
        return {
            "cikti":         f"⚠️ Bu komut onay gerektirir: {tanim['aciklama']}",
            "onay_gerekli":  True,
            "komut":         komut_str,
            "durum":         "onay_bekle"
        }

    logger.info("[Konsol] Whitelist komut: %s | Admin: %s", komut_str, user["id"])
    cikti = await komutu_calistir(tanim["komut"], tanim["cwd"])
    await audit_yaz(db, user["id"], komut_str, cikti, "whitelist")

    return {"cikti": cikti, "durum": "ok"}


# ---------------------------------------------------------------------------
# SERBEST KOMUT (2FA ZORUNLU)
# ---------------------------------------------------------------------------

@router.post("/serbest")
async def serbest_komut(body: dict, user=Depends(get_user), db=Depends(get_db)):
    """
    Serbest shell komutu.
    2FA aktif VE anlık 2FA kodu doğrulanmalı.
    Tehlikeli desenler her zaman engellenir.
    """
    if user["rol"] != "admin":
        raise HTTPException(status_code=403)

    tfa_kod  = body.get("tfa_kodu", "")
    komut_str = body.get("komut", "").strip()

    if not komut_str:
        raise HTTPException(status_code=400, detail="Komut boş olamaz")

    # 2FA durumu kontrol
    row = await db.fetchrow(
        "SELECT tfa_aktif, tfa_secret FROM kullanicilar WHERE id=$1", user["id"]
    )
    if not row or not row["tfa_aktif"]:
        return {
            "cikti": "🔒 Serbest komut için önce 2FA'yı aktif edin (Ayarlar → 2FA).",
            "durum": "2fa_gerekli"
        }

    if not tfa_dogrula(row["tfa_secret"], tfa_kod):
        logger.warning("[Konsol] Geçersiz 2FA: %s | Komut: %s", user["id"], komut_str[:50])
        raise HTTPException(status_code=401, detail="Geçersiz 2FA kodu")

    # Tehlikeli desen kontrolü
    komut_kucuk = komut_str.lower()
    for tehlikeli in TEHLIKELI_DESENLER:
        if tehlikeli.lower() in komut_kucuk:
            logger.warning("[Konsol] TEHLİKELİ KOMUT ENGELLENDİ: %s | %s",
                           user["id"], komut_str[:100])
            await audit_yaz(db, user["id"],
                            f"[ENGELLENDİ] {komut_str}", "Tehlikeli desen", "tehlikeli")
            return {
                "cikti": f"🚫 Engellendi: Tehlikeli desen tespit edildi.",
                "durum": "engellendi"
            }

    logger.info("[Konsol] Serbest komut: %s | Admin: %s", komut_str[:80], user["id"])
    cikti = await komutu_calistir(
        ["bash", "-c", komut_str], cwd="/opt/redcell", timeout=60
    )
    await audit_yaz(db, user["id"], komut_str, cikti, "serbest_2fa")

    return {"cikti": cikti, "durum": "ok"}
