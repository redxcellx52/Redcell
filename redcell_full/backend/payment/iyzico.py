"""
backend/payment/iyzico.py
-------------------------
İyzico ödeme entegrasyonu.
- Ödeme formu oluşturma
- Ödeme doğrulama (webhook)
- İade işlemi
- Ödeme geçmişi
Türkiye'de TL ile tahsilat, tüm kartlar desteklenir.
"""

import os
import json
import hashlib
import hmac
import logging
import random
import string
from datetime import datetime

import httpx

logger = logging.getLogger("REDCELL.payment")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IYZICO_API_KEY    = os.getenv("IYZICO_API_KEY", "")
IYZICO_SECRET_KEY = os.getenv("IYZICO_SECRET_KEY", "")
IYZICO_BASE_URL   = os.getenv("IYZICO_BASE_URL", "https://sandbox-api.iyzipay.com")
# Production: https://api.iyzipay.com
SITE_URL          = os.getenv("SITE_URL", "https://redxcell.com")


# ---------------------------------------------------------------------------
# İmza Üretici (İyzico PKI)
# ---------------------------------------------------------------------------

def _imza_uret(istek_gövdesi: str) -> str:
    """İyzico PKI string ve HMAC-SHA256 imzası üretir."""
    pki = f"apiKey:{IYZICO_API_KEY}&randomKey:{_rastgele_str()}&signature:"
    imza = hmac.new(
        IYZICO_SECRET_KEY.encode("utf-8"),
        (pki + istek_gövdesi).encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return imza


def _rastgele_str(uzunluk: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=uzunluk))


def _ortak_headers() -> dict:
    rastgele = _rastgele_str()
    return {
        "Authorization": f"IYZWS {IYZICO_API_KEY}:{rastgele}",
        "Content-Type":  "application/json",
        "x-iyzi-rnd":    rastgele,
        "Accept":        "application/json",
    }


# ---------------------------------------------------------------------------
# 1. ÖDEME FORMU OLUŞTUR
# ---------------------------------------------------------------------------

async def odeme_formu_olustur(
    talep_id: str,
    musteri: dict,
    tutar: float,
    aciklama: str,
) -> dict:
    """
    İyzico ödeme formu oluşturur.
    Dönen 'checkoutFormContent' frontend'de iframe olarak gösterilir.
    
    musteri: {ad, soyad, email, telefon, adres, sehir, ulke, posta_kodu}
    """
    if not IYZICO_API_KEY:
        logger.warning("[Ödeme] İyzico yapılandırılmamış, test modu.")
        return {
            "status":       "success",
            "token":        f"test_token_{talep_id}",
            "checkoutFormContent": "<p style='color:#27ae60'>TEST MODU: Ödeme simüle edildi</p>",
            "tokenExpireTime": 1800,
        }

    sepet = [{
        "id":       talep_id,
        "name":     aciklama[:100],
        "category1": "Siber Güvenlik",
        "itemType": "VIRTUAL",
        "price":    f"{tutar:.2f}",
    }]

    istek = {
        "locale":           "tr",
        "conversationId":   talep_id,
        "price":            f"{tutar:.2f}",
        "paidPrice":        f"{tutar:.2f}",
        "currency":         "TRY",
        "basketId":         talep_id,
        "paymentGroup":     "PRODUCT",
        "callbackUrl":      f"{SITE_URL}/api/odeme/callback",
        "enabledInstallments": [1, 2, 3, 6, 9, 12],
        "buyer": {
            "id":                  musteri.get("id", talep_id),
            "name":                musteri.get("ad", ""),
            "surname":             musteri.get("soyad", ""),
            "email":               musteri.get("email", ""),
            "identityNumber":      musteri.get("tc", "11111111111"),
            "registrationAddress": musteri.get("adres", "Türkiye"),
            "ip":                  musteri.get("ip", "127.0.0.1"),
            "city":                musteri.get("sehir", "İstanbul"),
            "country":             musteri.get("ulke", "Turkey"),
        },
        "shippingAddress": {
            "contactName": f"{musteri.get('ad','')} {musteri.get('soyad','')}",
            "city":        musteri.get("sehir", "İstanbul"),
            "country":     musteri.get("ulke", "Turkey"),
            "address":     musteri.get("adres", "Türkiye"),
        },
        "billingAddress": {
            "contactName": f"{musteri.get('ad','')} {musteri.get('soyad','')}",
            "city":        musteri.get("sehir", "İstanbul"),
            "country":     musteri.get("ulke", "Turkey"),
            "address":     musteri.get("adres", "Türkiye"),
        },
        "basketItems": sepet,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            yanit = await client.post(
                f"{IYZICO_BASE_URL}/payment/iyzipos/checkoutform/initialize/auth/ecommerce",
                headers=_ortak_headers(),
                json=istek,
            )
            veri = yanit.json()
            if veri.get("status") == "success":
                logger.info("[Ödeme] Form oluşturuldu: %s", talep_id)
            else:
                logger.error("[Ödeme] Form hatası: %s", veri.get("errorMessage"))
            return veri
    except Exception as exc:
        logger.error("[Ödeme] İyzico bağlantı hatası: %s", exc)
        return {"status": "error", "errorMessage": str(exc)}


# ---------------------------------------------------------------------------
# 2. ÖDEME DOĞRULA (Callback / Webhook)
# ---------------------------------------------------------------------------

async def odeme_dogrula(token: str) -> dict:
    """İyzico callback'ten gelen token ile ödemeyi doğrular."""
    istek = {
        "locale":         "tr",
        "conversationId": token,
        "token":          token,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            yanit = await client.post(
                f"{IYZICO_BASE_URL}/payment/iyzipos/checkoutform/auth/ecommerce/detail",
                headers=_ortak_headers(),
                json=istek,
            )
            veri = yanit.json()
            basarili = (
                veri.get("status") == "success" and
                veri.get("paymentStatus") == "SUCCESS"
            )
            logger.info("[Ödeme] Doğrulama: %s → %s",
                        token[:12], "BAŞARILI" if basarili else "BAŞARISIZ")
            return {
                "basarili":        basarili,
                "odeme_id":        veri.get("paymentId"),
                "tutar":           veri.get("price"),
                "para_birimi":     veri.get("currency"),
                "taksit_sayisi":   veri.get("installment"),
                "ham":             veri,
            }
    except Exception as exc:
        logger.error("[Ödeme] Doğrulama hatası: %s", exc)
        return {"basarili": False, "hata": str(exc)}


# ---------------------------------------------------------------------------
# 3. İADE
# ---------------------------------------------------------------------------

async def iade_yap(odeme_id: str, tutar: float, sebep: str = "") -> dict:
    """Kısmi veya tam iade işlemi."""
    istek = {
        "locale":         "tr",
        "conversationId": f"iade_{odeme_id}",
        "paymentTransactionId": odeme_id,
        "price":          f"{tutar:.2f}",
        "currency":       "TRY",
        "ip":             "127.0.0.1",
        "description":    sebep[:100] if sebep else "Müşteri talebi",
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            yanit = await client.post(
                f"{IYZICO_BASE_URL}/payment/refund",
                headers=_ortak_headers(),
                json=istek,
            )
            veri = yanit.json()
            logger.info("[Ödeme] İade: %s → %s", odeme_id, veri.get("status"))
            return veri
    except Exception as exc:
        logger.error("[Ödeme] İade hatası: %s", exc)
        return {"status": "error", "errorMessage": str(exc)}
