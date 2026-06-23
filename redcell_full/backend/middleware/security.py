"""
backend/middleware/security.py
------------------------------
3.  Güvenlik header'ları (XSS, Clickjacking, MIME sniffing koruması)
4.  CORS (sadece izin verilen originler)
9.  Rate limiting (IP bazlı istek sınırı)
11. WAF (Web Application Firewall - SQL injection, XSS, path traversal tespiti)
"""

import re
import time
import logging
from collections import defaultdict

from fastapi import Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("REDCELL.middleware")

# ---------------------------------------------------------------------------
# İZİN VERİLEN ORİGİNLER (CORS)
# ---------------------------------------------------------------------------
IZINLI_ORIGINLER = [
    "https://redxcell.com",
    "https://www.redxcell.com",
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1",
]

# ---------------------------------------------------------------------------
# RATE LIMIT AYARLARI
# ---------------------------------------------------------------------------
# (endpoint_prefix → (istek_sayisi, pencere_saniye))
RATE_LIMITLER = {
    "/api/auth":     (10,  60),   # Auth: dakikada 10 istek
    "/api/talepler": (60,  60),   # Talepler: dakikada 60
    "/api/":         (120, 60),   # Genel API: dakikada 120
    "/":             (300, 60),   # Sayfa: dakikada 300
}

# ---------------------------------------------------------------------------
# WAF — ENGELLENECEĞİ DESENLER
# ---------------------------------------------------------------------------
WAF_DESENLERI = [
    # SQL Injection
    (re.compile(
        r"(\b(union|select|insert|update|delete|drop|alter|exec|execute)\b.*\b(from|into|where|table)\b"
        r"|--|;--|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)",
        re.IGNORECASE
    ), "SQL Injection"),

    # XSS
    (re.compile(
        r"<script[\s>]|javascript:|on\w+\s*=|<iframe|<object|<embed|eval\(|expression\(",
        re.IGNORECASE
    ), "XSS"),

    # Path Traversal
    (re.compile(
        r"\.\./|\.\.\\|%2e%2e|%252e",
        re.IGNORECASE
    ), "Path Traversal"),

    # Komut Enjeksiyonu
    (re.compile(
        r";\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|php)\s|`[^`]+`|\$\([^)]+\)",
        re.IGNORECASE
    ), "Command Injection"),

    # Prompt Injection (Ajan sistemi için)
    (re.compile(
        r"ignore previous instructions|forget your|you are now|disregard all|"
        r"pretend you are|act as if|your new instructions",
        re.IGNORECASE
    ), "Prompt Injection"),
]


# ---------------------------------------------------------------------------
# 9. RATE LIMITING MIDDLEWARE
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """IP + endpoint bazlı istek sınırlayıcı."""

    def __init__(self, app):
        super().__init__(app)
        # {ip_endpoint_key: [(timestamp), ...]}
        self._pencereler: dict = defaultdict(list)

    def _limit_bul(self, path: str) -> tuple[int, int]:
        for prefix, limit in RATE_LIMITLER.items():
            if path.startswith(prefix):
                return limit
        return (300, 60)

    async def dispatch(self, request: Request, call_next):
        ip   = request.client.host
        path = request.url.path
        simdi = time.time()

        maks_istek, pencere = self._limit_bul(path)
        anahtar = f"{ip}:{path[:20]}"

        # Eski kayıtları temizle
        self._pencereler[anahtar] = [
            t for t in self._pencereler[anahtar]
            if simdi - t < pencere
        ]

        if len(self._pencereler[anahtar]) >= maks_istek:
            logger.warning("[RateLimit] Blok: %s → %s", ip, path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Çok fazla istek. Lütfen bekleyin."},
                headers={"Retry-After": str(pencere)},
            )

        self._pencereler[anahtar].append(simdi)
        return await call_next(request)


# ---------------------------------------------------------------------------
# 11. WAF MIDDLEWARE
# ---------------------------------------------------------------------------

class WAFMiddleware(BaseHTTPMiddleware):
    """
    Web Application Firewall.
    URL, query string ve istek gövdesini zararlı desenlere karşı tarar.
    """

    async def dispatch(self, request: Request, call_next):
        # Statik dosyaları atla
        if request.url.path.startswith("/static"):
            return await call_next(request)

        # URL + Query string tara
        tam_url = str(request.url)
        tespit = self._tara(tam_url)
        if tespit:
            logger.warning("[WAF] %s tespit edildi: %s | IP: %s",
                           tespit, tam_url[:100], request.client.host)
            return JSONResponse(
                status_code=403,
                content={"detail": f"İstek engellendi: {tespit}"},
            )

        # POST/PUT/PATCH gövdesini tara
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                govde = await request.body()
                govde_str = govde.decode("utf-8", errors="ignore")
                tespit = self._tara(govde_str)
                if tespit:
                    logger.warning("[WAF] Gövdede %s: %s | IP: %s",
                                   tespit, govde_str[:100], request.client.host)
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"İstek içeriği engellendi: {tespit}"},
                    )
            except Exception:
                pass

        return await call_next(request)

    def _tara(self, metin: str) -> str | None:
        for desen, isim in WAF_DESENLERI:
            if desen.search(metin):
                return isim
        return None


# ---------------------------------------------------------------------------
# 3. GÜVENLİK HEADER'LARI MIDDLEWARE
# ---------------------------------------------------------------------------

class GuvenlikHeaderlariMiddleware(BaseHTTPMiddleware):
    """
    Her HTTP yanıtına güvenlik header'ları ekler.
    XSS, Clickjacking, MIME sniffing, bilgi sızıntısı koruması.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # XSS koruması
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Clickjacking koruması
        response.headers["X-Frame-Options"] = "DENY"

        # MIME sniffing koruması
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer politikası
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # İzinler politikası (kamera, mikrofon vb. engelle)
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # CSP (Content Security Policy)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Server bilgisini gizle
        response.headers["Server"] = "REDCELL"

        # HTTPS zorla (production'da)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        return response
