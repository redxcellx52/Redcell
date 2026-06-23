"""
backend/security/auth.py
------------------------
1. Bcrypt şifre hash (güvenli)
2. JWT token üretme/doğrulama
3. 2FA (TOTP - Google Authenticator uyumlu, açıp kapanabilir)
4. Brute force koruması (başarısız giriş sayacı)
"""

import os
import time
import secrets
import logging
from datetime import datetime, timedelta
from collections import defaultdict

import bcrypt
import jwt
import pyotp
import qrcode
import io
import base64

logger = logging.getLogger("REDCELL.auth")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(64))
JWT_ALGO     = "HS256"
JWT_EXPIRE_H = int(os.getenv("JWT_EXPIRE_H", 24))

# Brute force ayarları
MAX_DENEME       = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
BLOK_SURE_SN     = int(os.getenv("LOGIN_BLOCK_SECONDS", 900))  # 15 dakika

# ---------------------------------------------------------------------------
# 1. BCRYPT ŞİFRE
# ---------------------------------------------------------------------------

def sifre_hashle(sifre: str) -> str:
    """Şifreyi bcrypt ile hashler. Veritabanına bu yazılır."""
    return bcrypt.hashpw(sifre.encode(), bcrypt.gensalt(rounds=12)).decode()


def sifre_dogrula(sifre: str, hash_deger: str) -> bool:
    """Girilen şifreyi veritabanındaki hash ile karşılaştırır."""
    try:
        return bcrypt.checkpw(sifre.encode(), hash_deger.encode())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 2. JWT TOKEN
# ---------------------------------------------------------------------------

def token_olustur(payload: dict) -> str:
    """JWT token üretir. payload: {id, ad, rol}"""
    data = {
        **payload,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H),
        "iat": datetime.utcnow(),
        "jti": secrets.token_hex(16),  # Token tekil ID (replay attack koruması)
    }
    return jwt.encode(data, SECRET_KEY, algorithm=JWT_ALGO)


def token_coz(token: str) -> dict:
    """JWT token'ı doğrular ve payload'ı döner. Hatalıysa exception fırlatır."""
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])


# ---------------------------------------------------------------------------
# 3. BRUTE FORCE KORUMASI
# ---------------------------------------------------------------------------

# Bellekte tutulan başarısız giriş sayaçları
# Production'da Redis'e taşı: from redis import Redis
_deneme_sayaci: dict = defaultdict(lambda: {"sayi": 0, "blok_bitis": 0})


def giris_denemesi_kontrol(ip: str) -> tuple[bool, int]:
    """
    IP'nin giriş yapmasına izin var mı?
    Returns: (izin_var, kalan_saniye)
    """
    kayit = _deneme_sayaci[ip]
    simdi = time.time()

    if kayit["blok_bitis"] > simdi:
        kalan = int(kayit["blok_bitis"] - simdi)
        return False, kalan

    return True, 0


def giris_basarisiz(ip: str):
    """Başarısız giriş denemesini kaydeder. Limite ulaşılırsa IP'yi bloklar."""
    kayit = _deneme_sayaci[ip]
    kayit["sayi"] += 1

    if kayit["sayi"] >= MAX_DENEME:
        kayit["blok_bitis"] = time.time() + BLOK_SURE_SN
        kayit["sayi"] = 0
        logger.warning("[BruteForce] IP bloklandı: %s (%d dk)", ip, BLOK_SURE_SN // 60)


def giris_basarili(ip: str):
    """Başarılı girişte sayacı sıfırlar."""
    _deneme_sayaci[ip] = {"sayi": 0, "blok_bitis": 0}


# ---------------------------------------------------------------------------
# 4. 2FA — TOTP (Google Authenticator uyumlu)
# ---------------------------------------------------------------------------

def tfa_secret_olustur() -> str:
    """Kullanıcı için benzersiz 2FA secret üretir. Veritabanına şifreli sakla."""
    return pyotp.random_base32()


def tfa_qr_olustur(secret: str, kullanici_adi: str) -> str:
    """
    Google Authenticator'da taranacak QR kodu base64 PNG olarak döner.
    Frontend'de <img src="data:image/png;base64,..."> ile göster.
    """
    issuer = "REDCELL AR-GE"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=kullanici_adi,
        issuer_name=issuer,
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def tfa_dogrula(secret: str, kod: str) -> bool:
    """
    Kullanıcının girdiği 6 haneli kodu doğrular.
    30 saniyelik pencere + 1 önceki/sonraki kod kabul edilir (clock skew).
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(kod, valid_window=1)
    except Exception:
        return False
