"""
backend/i18n.py
----------------
Çoklu dil desteği.
Türkçe (tr) ve İngilizce (en) desteklenir.
API yanıtları Accept-Language header'ına göre dil seçer.
"""

from fastapi import Request

TERCUMELER = {
    "tr": {
        "talep_alindi":        "Talebiniz alındı",
        "giris_basarili":      "Giriş başarılı",
        "giris_basarisiz":     "Kullanıcı adı veya şifre hatalı",
        "token_gecersiz":      "Geçersiz veya süresi dolmuş token",
        "yetki_yok":           "Bu işlem için yetkiniz yok",
        "bulunamadi":          "Kayıt bulunamadı",
        "sifre_guncellendi":   "Şifre başarıyla güncellendi",
        "dosya_buyuk":         "Dosya boyutu limiti aşıldı",
        "dosya_tipi_gecersiz": "İzin verilmeyen dosya türü",
        "odeme_basarili":      "Ödeme başarıyla tamamlandı",
        "odeme_basarisiz":     "Ödeme işlemi başarısız",
        "rapor_hazir":         "Raporunuz hazırlandı",
        "2fa_aktif":           "2FA başarıyla aktif edildi",
        "2fa_kapandi":         "2FA devre dışı bırakıldı",
        "anket_tamamlandi":    "Değerlendirmeniz için teşekkürler",
    },
    "en": {
        "talep_alindi":        "Your request has been received",
        "giris_basarili":      "Login successful",
        "giris_basarisiz":     "Invalid username or password",
        "token_gecersiz":      "Invalid or expired token",
        "yetki_yok":           "You don't have permission for this action",
        "bulunamadi":          "Record not found",
        "sifre_guncellendi":   "Password updated successfully",
        "dosya_buyuk":         "File size limit exceeded",
        "dosya_tipi_gecersiz": "File type not allowed",
        "odeme_basarili":      "Payment completed successfully",
        "odeme_basarisiz":     "Payment failed",
        "rapor_hazir":         "Your report is ready",
        "2fa_aktif":           "2FA successfully enabled",
        "2fa_kapandi":         "2FA has been disabled",
        "anket_tamamlandi":    "Thank you for your feedback",
    },
}


def dil_al(request: Request) -> str:
    """Request'ten dili belirler. Varsayılan: tr"""
    accept = request.headers.get("Accept-Language", "tr")
    if "en" in accept.lower():
        return "en"
    return "tr"


def t(anahtar: str, dil: str = "tr") -> str:
    """Çeviri döner. Anahtar bulunamazsa Türkçe fallback."""
    return TERCUMELER.get(dil, TERCUMELER["tr"]).get(
        anahtar, TERCUMELER["tr"].get(anahtar, anahtar)
    )
