"""
backend/monitoring/izleme.py
-----------------------------
Hata izleme ve performans monitörü.
- Sentry entegrasyonu (hata izleme)
- Endpoint bazlı yanıt süresi takibi
- Sistem sağlık kontrolü (/health)
- Basit metrik toplama (Prometheus uyumlu format)
"""

import os
import time
import logging
import platform
import psutil
from datetime import datetime
from collections import defaultdict, deque

from fastapi import APIRouter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("REDCELL.monitoring")

router = APIRouter()

# ---------------------------------------------------------------------------
# Sentry (Opsiyonel — SENTRY_DSN env ile aktif olur)
# ---------------------------------------------------------------------------
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

def sentry_baslat():
    if not SENTRY_DSN:
        logger.info("[İzleme] Sentry DSN yok, hata izleme pasif.")
        return
    try:
        import sentry_sdk
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            traces_sample_rate=0.1,
            profiles_sample_rate=0.1,
            environment=os.getenv("ENV", "production"),
            release=os.getenv("APP_VERSION", "1.0.0"),
        )
        logger.info("[İzleme] Sentry aktif.")
    except ImportError:
        logger.warning("[İzleme] sentry-sdk kurulu değil: pip install sentry-sdk")


# ---------------------------------------------------------------------------
# Metrik Toplama (Bellek içi, hafif)
# ---------------------------------------------------------------------------

class MetrikToplama:
    """Endpoint bazlı istek sayısı ve yanıt süresini tutar."""

    def __init__(self, pencere: int = 3600):
        self._istek_sayisi: dict = defaultdict(int)
        self._yanit_sureleri: dict = defaultdict(lambda: deque(maxlen=100))
        self._hatalar: dict = defaultdict(int)
        self._baslangic = datetime.utcnow()

    def kaydet(self, yol: str, metod: str, durum_kodu: int, sure_ms: float):
        anahtar = f"{metod}:{yol[:50]}"
        self._istek_sayisi[anahtar] += 1
        self._yanit_sureleri[anahtar].append(sure_ms)
        if durum_kodu >= 400:
            self._hatalar[anahtar] += 1

    def ozet(self) -> dict:
        calisma_suresi = (datetime.utcnow() - self._baslangic).total_seconds()
        en_yavash = sorted(
            [(k, sum(v)/len(v)) for k, v in self._yanit_sureleri.items() if v],
            key=lambda x: x[1], reverse=True
        )[:5]
        return {
            "calisma_suresi_sn": int(calisma_suresi),
            "toplam_istek":      sum(self._istek_sayisi.values()),
            "toplam_hata":       sum(self._hatalar.values()),
            "en_yavash_5":       [{"endpoint": k, "ort_ms": round(v, 1)}
                                   for k, v in en_yavash],
        }


metrikler = MetrikToplama()


# ---------------------------------------------------------------------------
# Performans Middleware
# ---------------------------------------------------------------------------

class PerformansMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/static"):
            return await call_next(request)

        baslangic = time.perf_counter()
        yanit     = await call_next(request)
        sure_ms   = (time.perf_counter() - baslangic) * 1000

        metrikler.kaydet(
            request.url.path,
            request.method,
            yanit.status_code,
            sure_ms,
        )

        # Yavaş istek uyarısı (>2 saniye)
        if sure_ms > 2000:
            logger.warning("[Perf] Yavaş istek: %s %s → %.0fms",
                           request.method, request.url.path, sure_ms)

        yanit.headers["X-Response-Time"] = f"{sure_ms:.1f}ms"
        return yanit


# ---------------------------------------------------------------------------
# Sağlık Kontrolü ve Metrik Endpoint'leri
# ---------------------------------------------------------------------------

@router.get("/health")
async def saglik_kontrol():
    """Sistem sağlık kontrolü. Load balancer ve uptime izleme için."""
    try:
        cpu    = psutil.cpu_percent(interval=0.1)
        bellek = psutil.virtual_memory()
        disk   = psutil.disk_usage("/")

        durum = "ok"
        if cpu > 90 or bellek.percent > 90:
            durum = "warn"

        return {
            "durum":   durum,
            "zaman":   datetime.utcnow().isoformat() + "Z",
            "versiyon": os.getenv("APP_VERSION", "1.0.0"),
            "sistem":  {
                "cpu_yuzde":    round(cpu, 1),
                "bellek_yuzde": round(bellek.percent, 1),
                "disk_yuzde":   round(disk.percent, 1),
                "platform":     platform.system(),
            },
        }
    except Exception as exc:
        return {"durum": "error", "hata": str(exc)}


@router.get("/metrics")
async def metrik_ozet():
    """Prometheus uyumlu basit metrik özeti."""
    sistem = {
        "cpu":    psutil.cpu_percent(),
        "bellek": psutil.virtual_memory().percent,
        "disk":   psutil.disk_usage("/").percent,
    }
    return {**metrikler.ozet(), "sistem": sistem}
