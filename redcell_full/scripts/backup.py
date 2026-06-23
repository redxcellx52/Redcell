#!/usr/bin/env python3
"""
scripts/backup.py
-----------------
7. Otomatik Yedekleme
   - PostgreSQL dump
   - ChromaDB snapshot
   - Son 7 günü sakla, eskiyi sil
   - Yedek tamamlanınca admin paneline bildirim gönder

Cron ile çalıştır:
  0 2 * * * /opt/redcell/scripts/backup.py >> /var/log/redcell_backup.log 2>&1
"""

import os
import sys
import subprocess
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("REDCELL.backup")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
YEDEK_DIZIN    = Path(os.getenv("BACKUP_DIR", "/opt/redcell/backups"))
SAKLA_GUN      = int(os.getenv("BACKUP_KEEP_DAYS", 7))
DB_HOST        = os.getenv("DB_HOST", "postgres")
DB_PORT        = os.getenv("DB_PORT", "5432")
DB_NAME        = os.getenv("DB_NAME", "redcell")
DB_USER        = os.getenv("DB_USER", "postgres")
DB_PASSWORD    = os.getenv("DB_PASSWORD", "")
CHROMA_DIR     = Path(os.getenv("CHROMA_DB_PATH", "/opt/redcell/chroma_db"))
BILDIRIM_API   = os.getenv("BACKUP_NOTIFY_API", "http://web:8000/api/bildirim/sistem")


def zaman_damgasi() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def yedek_dizin_hazirla():
    YEDEK_DIZIN.mkdir(parents=True, exist_ok=True)
    (YEDEK_DIZIN / "postgres").mkdir(exist_ok=True)
    (YEDEK_DIZIN / "chroma").mkdir(exist_ok=True)


def postgresql_yedekle() -> Path | None:
    """pg_dump ile veritabanını sıkıştırılmış dosyaya yazar."""
    damga   = zaman_damgasi()
    dosya   = YEDEK_DIZIN / "postgres" / f"redcell_{damga}.sql.gz"
    env     = {**os.environ, "PGPASSWORD": DB_PASSWORD}

    komut = (
        f"pg_dump -h {DB_HOST} -p {DB_PORT} -U {DB_USER} {DB_NAME} "
        f"| gzip > {dosya}"
    )

    try:
        subprocess.run(komut, shell=True, env=env, check=True, timeout=300)
        boyut_mb = dosya.stat().st_size / 1024 / 1024
        logger.info("PostgreSQL yedeği tamamlandı: %s (%.1f MB)", dosya.name, boyut_mb)
        return dosya
    except Exception as exc:
        logger.error("PostgreSQL yedeği BAŞARISIZ: %s", exc)
        return None


def chroma_yedekle() -> Path | None:
    """ChromaDB dizinini zip'ler."""
    if not CHROMA_DIR.exists():
        logger.warning("ChromaDB dizini bulunamadı: %s", CHROMA_DIR)
        return None

    damga  = zaman_damgasi()
    hedef  = YEDEK_DIZIN / "chroma" / f"chroma_{damga}"

    try:
        arsiv = shutil.make_archive(str(hedef), "zip", str(CHROMA_DIR))
        boyut_mb = Path(arsiv).stat().st_size / 1024 / 1024
        logger.info("ChromaDB yedeği tamamlandı: %s (%.1f MB)", Path(arsiv).name, boyut_mb)
        return Path(arsiv)
    except Exception as exc:
        logger.error("ChromaDB yedeği BAŞARISIZ: %s", exc)
        return None


def eski_yedekleri_sil():
    """SAKLA_GUN günden eski yedekleri siler."""
    sinir = datetime.now() - timedelta(days=SAKLA_GUN)
    silinen = 0

    for klasor in ["postgres", "chroma"]:
        for dosya in (YEDEK_DIZIN / klasor).glob("*"):
            if dosya.is_file():
                dosya_tarih = datetime.fromtimestamp(dosya.stat().st_mtime)
                if dosya_tarih < sinir:
                    dosya.unlink()
                    silinen += 1
                    logger.info("Eski yedek silindi: %s", dosya.name)

    if silinen:
        logger.info("Toplam %d eski yedek silindi.", silinen)


def bildirim_gonder(basari: bool, detay: str):
    """Admin paneline yedekleme sonucunu bildirir."""
    try:
        requests.post(BILDIRIM_API, json={
            "tip":    "sistem",
            "baslik": "✅ Yedekleme Tamamlandı" if basari else "❌ Yedekleme Başarısız",
            "mesaj":  detay,
        }, timeout=5)
    except Exception:
        pass  # Bildirim gitmese de yedek tamam


def main():
    logger.info("=" * 50)
    logger.info("REDCELL Otomatik Yedekleme Başladı")
    logger.info("=" * 50)

    yedek_dizin_hazirla()

    pg_dosya     = postgresql_yedekle()
    chroma_dosya = chroma_yedekle()
    eski_yedekleri_sil()

    basari = pg_dosya is not None
    detay  = (
        f"PostgreSQL: {'✅' if pg_dosya else '❌'} | "
        f"ChromaDB: {'✅' if chroma_dosya else '❌'} | "
        f"Tarih: {datetime.now().strftime('%d.%m.%Y %H:%M')}"
    )

    bildirim_gonder(basari, detay)
    logger.info("Yedekleme tamamlandı: %s", detay)

    return 0 if basari else 1


if __name__ == "__main__":
    sys.exit(main())
