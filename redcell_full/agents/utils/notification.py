"""
utils/notification.py
---------------------
Admin onay mekanizması — Telegram YOK.
Kendi web panelimize bildirim gönderir.
Admin panelde ONAYLA/REDDET butonuna basınca karar gelir,
aynı zamanda admin'in telefonuna Web Push bildirimi düşer.
"""

import os
import time
import logging
import requests

logger = logging.getLogger(__name__)

ADMIN_NOTIFY_API   = os.getenv("ADMIN_NOTIFY_API",   "http://web:8000/api/admin-onay/talep")
ADMIN_APPROVAL_API = os.getenv("ADMIN_APPROVAL_API", "http://web:8000/api/ajan/onay")
POLL_INTERVAL      = int(os.getenv("POLL_INTERVAL", 10))
DEFAULT_TIMEOUT    = int(os.getenv("ADMIN_TIMEOUT_SN", 900))  # 15 dakika


def bekle_admin_onay(
    proje_id: str,
    operation_summary: str = "",
    timeout_sn: int = DEFAULT_TIMEOUT,
) -> bool:
    """
    Admin paneline bildirim gönderir, onay bekler.

    Akış:
    1. TEST modunda (ADMIN_APPROVAL=true) anında True döner.
    2. Web paneline POST → admin'in telefonuna Web Push bildirimi gider.
    3. Polling döngüsü: admin ONAYLA veya REDDET butonuna basana kadar bekler.
    4. timeout_sn içinde karar gelmezse False döner (güvenli varsayılan).

    Returns:
        bool: True = onaylandı, False = reddedildi veya zaman aşımı.
    """

    # --- Test Modu ---
    if os.getenv("ADMIN_APPROVAL", "false").lower() == "true":
        logger.info("[Onay] TEST MODU: %s için otomatik onay verildi.", proje_id)
        return True

    # --- Bildirim Gönder ---
    try:
        r = requests.post(
            ADMIN_NOTIFY_API,
            json={"proje_id": proje_id, "ozet": operation_summary},
            timeout=10,
        )
        r.raise_for_status()
        logger.info("[Onay] Admin paneline bildirim gönderildi: %s", proje_id)
    except Exception as exc:
        logger.error("[Onay] Bildirim gönderilemedi: %s → güvenli ret.", exc)
        return False

    # --- Polling Döngüsü ---
    logger.info("[Onay] Admin kararı bekleniyor... (timeout: %ds)", timeout_sn)
    deadline = time.time() + timeout_sn

    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{ADMIN_APPROVAL_API}/{proje_id}",
                timeout=5,
            )
            data = resp.json()

            if data.get("approved") is True or data.get("status") == "approved":
                logger.info("[Onay] ✅ Admin onayladı: %s", proje_id)
                return True

            if data.get("status") == "rejected":
                logger.warning("[Onay] ❌ Admin reddetti: %s", proje_id)
                return False

            # status == "pending" → beklemeye devam
        except Exception as exc:
            logger.warning("[Onay] Polling hatası: %s", exc)

        time.sleep(POLL_INTERVAL)

    logger.error("[Onay] ⏰ Zaman aşımı (%ds): %s → güvenli ret.", timeout_sn, proje_id)
    return False
