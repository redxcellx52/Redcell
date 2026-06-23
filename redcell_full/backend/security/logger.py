"""
backend/security/logger.py
--------------------------
8. Merkezi Log Sistemi
   - Tüm API istekleri loglanır
   - Güvenlik olayları ayrı dosyaya yazılır
   - Yapılandırılmış JSON formatı (log analiz araçlarıyla uyumlu)
   - Hassas veriler (şifre, token) otomatik maskelenir
"""

import os
import re
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Log Dizini
# ---------------------------------------------------------------------------
LOG_DIR = Path(os.getenv("LOG_DIR", "/app/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Hassas Alan Maskesi
# ---------------------------------------------------------------------------
HASSAS_ALANLAR = re.compile(
    r'"(sifre|password|token|secret|key|auth|p256dh|authorization)":\s*"[^"]*"',
    re.IGNORECASE
)


def maskele(metin: str) -> str:
    """JSON içindeki hassas alanları maskeler."""
    return HASSAS_ALANLAR.sub(r'"\1": "***"', metin)


# ---------------------------------------------------------------------------
# JSON Log Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log = {
            "zaman":   datetime.utcnow().isoformat() + "Z",
            "seviye":  record.levelname,
            "modül":   record.name,
            "mesaj":   maskele(record.getMessage()),
        }
        if record.exc_info:
            log["hata"] = self.formatException(record.exc_info)
        return json.dumps(log, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Logger Kurulum Fonksiyonu
# ---------------------------------------------------------------------------

def logger_kur():
    """
    Uygulama başlarken bir kez çağrılır.
    Üç çıktı: konsol + uygulama log dosyası + güvenlik log dosyası
    """
    # Kök logger
    kok = logging.getLogger()
    kok.setLevel(logging.INFO)

    json_fmt  = JSONFormatter()
    text_fmt  = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # 1. Konsol (geliştirme için)
    konsol = logging.StreamHandler()
    konsol.setFormatter(text_fmt)
    konsol.setLevel(logging.INFO)

    # 2. Uygulama log dosyası (günlük rotasyon, 30 gün sakla)
    uygulama_handler = logging.handlers.TimedRotatingFileHandler(
        filename=LOG_DIR / "redcell.log",
        when="midnight",
        backupCount=30,
        encoding="utf-8",
    )
    uygulama_handler.setFormatter(json_fmt)
    uygulama_handler.setLevel(logging.INFO)

    # 3. Güvenlik log dosyası (sadece WARNING ve üstü)
    guvenlik_handler = logging.handlers.TimedRotatingFileHandler(
        filename=LOG_DIR / "security.log",
        when="midnight",
        backupCount=90,
        encoding="utf-8",
    )
    guvenlik_handler.setFormatter(json_fmt)
    guvenlik_handler.setLevel(logging.WARNING)

    kok.addHandler(konsol)
    kok.addHandler(uygulama_handler)
    kok.addHandler(guvenlik_handler)

    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn").setLevel(logging.WARNING)

    logging.info("Log sistemi başlatıldı. Dizin: %s", LOG_DIR)


# ---------------------------------------------------------------------------
# 8. İSTEK LOG MIDDLEWARE
# ---------------------------------------------------------------------------

class IstekLogMiddleware(BaseHTTPMiddleware):
    """Her HTTP isteğini ve yanıtını loglar."""

    HASSAS_YOLLAR = {"/api/auth/login", "/api/auth/sifre"}

    async def dispatch(self, request: Request, call_next):
        import time
        baslangic = time.time()

        # Statik dosyaları loglama
        if request.url.path.startswith("/static"):
            return await call_next(request)

        yanit = await call_next(request)
        sure_ms = int((time.time() - baslangic) * 1000)

        seviye = logging.WARNING if yanit.status_code >= 400 else logging.INFO
        logging.getLogger("REDCELL.http").log(seviye,
            "%s %s → %d (%dms) | IP: %s",
            request.method,
            request.url.path,
            yanit.status_code,
            sure_ms,
            request.client.host,
        )

        return yanit
