"""
backend/monitoring/sistem_durumu.py
-------------------------------------
Dashboard widget'ları için sistem durumu API'si.
- CPU, RAM, Disk kullanımı
- Sunucu sıcaklığı (Linux sensors)
- Aktif proje / ekip / ajan sayıları
- Ajan sistemi sağlığı
- Anlık bildirim sayısı
"""

import os
import subprocess
import logging
from datetime import datetime

import psutil
from fastapi import APIRouter, Depends

logger = logging.getLogger("REDCELL.sistem")
router = APIRouter()


# ---------------------------------------------------------------------------
# Sıcaklık Okuma
# ---------------------------------------------------------------------------

def sicaklik_oku() -> dict:
    """
    Linux sensors veya psutil ile CPU sıcaklığını okur.
    Docker içinde host erişimi için /sys/class/thermal bağlanmalı.
    """
    try:
        sicakliklar = psutil.sensors_temperatures()
        if sicakliklar:
            for isim, girisler in sicakliklar.items():
                for giris in girisler:
                    if giris.current and giris.current > 0:
                        return {
                            "deger":  round(giris.current, 1),
                            "max":    giris.high or 85,
                            "kaynak": isim,
                            "durum":  "kritik" if giris.current > 80 else
                                      "uyari"   if giris.current > 70 else "normal"
                        }
    except Exception:
        pass

    # Fallback: Linux thermal zone
    try:
        sonuc = subprocess.run(
            ["cat", "/sys/class/thermal/thermal_zone0/temp"],
            capture_output=True, text=True, timeout=2
        )
        if sonuc.returncode == 0:
            celsius = int(sonuc.stdout.strip()) / 1000
            return {
                "deger":  round(celsius, 1),
                "max":    85,
                "kaynak": "thermal_zone0",
                "durum":  "kritik" if celsius > 80 else
                          "uyari"   if celsius > 70 else "normal"
            }
    except Exception:
        pass

    return {"deger": None, "max": 85, "kaynak": "unknown", "durum": "bilinmiyor"}


# ---------------------------------------------------------------------------
# Sistem Durumu Endpoint
# ---------------------------------------------------------------------------

async def get_db():
    from backend.main import db_pool
    async with db_pool.acquire() as conn:
        yield conn


@router.get("/api/sistem/durum")
async def sistem_durum(db=Depends(get_db)):
    """
    Dashboard widget'ları için anlık sistem durumu.
    Her 15 saniyede bir frontend tarafından çekilir.
    """

    # CPU & Bellek & Disk
    cpu_yuzde    = psutil.cpu_percent(interval=0.2)
    bellek       = psutil.virtual_memory()
    disk         = psutil.disk_usage("/")
    sicaklik     = sicaklik_oku()

    # Uptime
    boot_ts      = psutil.boot_time()
    uptime_sn    = int(datetime.utcnow().timestamp() - boot_ts)
    uptime_str   = _sure_formatla(uptime_sn)

    # Veritabanı sayımları
    try:
        talepler_row = await db.fetchrow("""
            SELECT
                COUNT(*) AS toplam,
                COUNT(*) FILTER (WHERE durum='bekleyen') AS bekleyen,
                COUNT(*) FILTER (WHERE durum='devam')    AS devam,
                COUNT(*) FILTER (WHERE durum='tamamlandi') AS tamamlandi
            FROM talepler
        """)

        ekip_row = await db.fetchrow("""
            SELECT
                COUNT(*) AS toplam,
                COUNT(*) FILTER (WHERE durum='busy')      AS aktif,
                COUNT(*) FILTER (WHERE durum='available') AS musait
            FROM kullanicilar WHERE rol='ekip'
        """)

        bildirim_row = await db.fetchrow(
            "SELECT COUNT(*) AS sayi FROM bildirimler WHERE okundu=false"
        )

        raporlar_sayi = await db.fetchval("SELECT COUNT(*) FROM raporlar")

        # Aktif ödeme (son 30 gün)
        gelir_row = await db.fetchrow("""
            SELECT COALESCE(SUM(genel_toplam), 0) AS toplam
            FROM odemeler
            WHERE durum='tamamlandi'
              AND tarih >= NOW() - INTERVAL '30 days'
        """) if await _tablo_var(db, "odemeler") else None

    except Exception as e:
        logger.warning("[SistemDurum] DB hatası: %s", e)
        talepler_row = ekip_row = bildirim_row = gelir_row = None
        raporlar_sayi = 0

    # Ajan sistemi durumu
    ajan_durum = await _ajan_durumu_kontrol()

    return {
        "zaman": datetime.utcnow().isoformat() + "Z",
        "donanim": {
            "cpu":     {"yuzde": round(cpu_yuzde, 1),
                        "durum": "kritik" if cpu_yuzde > 90 else
                                 "uyari"   if cpu_yuzde > 70 else "normal"},
            "bellek":  {"yuzde":     round(bellek.percent, 1),
                        "kullanilan": _byte_formatla(bellek.used),
                        "toplam":     _byte_formatla(bellek.total),
                        "durum":     "kritik" if bellek.percent > 90 else
                                     "uyari"   if bellek.percent > 75 else "normal"},
            "disk":    {"yuzde":     round(disk.percent, 1),
                        "kullanilan": _byte_formatla(disk.used),
                        "toplam":     _byte_formatla(disk.total),
                        "durum":     "kritik" if disk.percent > 90 else
                                     "uyari"   if disk.percent > 75 else "normal"},
            "sicaklik": sicaklik,
            "uptime":   uptime_str,
        },
        "projeler": {
            "toplam":      int(talepler_row["toplam"])     if talepler_row else 0,
            "bekleyen":    int(talepler_row["bekleyen"])   if talepler_row else 0,
            "devam":       int(talepler_row["devam"])      if talepler_row else 0,
            "tamamlandi":  int(talepler_row["tamamlandi"]) if talepler_row else 0,
            "raporlar":    int(raporlar_sayi) if raporlar_sayi else 0,
        },
        "ekip": {
            "toplam": int(ekip_row["toplam"]) if ekip_row else 0,
            "aktif":  int(ekip_row["aktif"])  if ekip_row else 0,
            "musait": int(ekip_row["musait"]) if ekip_row else 0,
        },
        "bildirimler": {
            "okunmamis": int(bildirim_row["sayi"]) if bildirim_row else 0,
        },
        "gelir": {
            "bu_ay_tl": float(gelir_row["toplam"]) if gelir_row else 0,
        },
        "ajanlar": ajan_durum,
    }


async def _tablo_var(db, tablo: str) -> bool:
    try:
        row = await db.fetchrow(
            "SELECT EXISTS (SELECT FROM information_schema.tables "
            "WHERE table_name=$1) AS var", tablo
        )
        return row["var"] if row else False
    except Exception:
        return False


async def _ajan_durumu_kontrol() -> dict:
    """Ajan sisteminin çalışıp çalışmadığını kontrol eder."""
    try:
        import httpx
        ajan_url = os.getenv("AJAN_HEALTH_URL", "http://agents:8001/health")
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get(ajan_url)
            return {"calisıyor": r.status_code == 200, "durum": "aktif"}
    except Exception:
        return {"calisiyor": False, "durum": "pasif"}


def _byte_formatla(bayt: int) -> str:
    for birim in ["B", "KB", "MB", "GB", "TB"]:
        if bayt < 1024:
            return f"{bayt:.1f} {birim}"
        bayt /= 1024
    return f"{bayt:.1f} PB"


def _sure_formatla(saniye: int) -> str:
    gun  = saniye // 86400
    saat = (saniye % 86400) // 3600
    dk   = (saniye % 3600) // 60
    if gun:
        return f"{gun}g {saat}s {dk}d"
    if saat:
        return f"{saat}s {dk}d"
    return f"{dk}d"
