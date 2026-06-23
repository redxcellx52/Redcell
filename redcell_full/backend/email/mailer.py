"""
backend/email/mailer.py
-----------------------
SMTP e-posta sistemi.
- Yeni talep bildirimi → Admin'e
- Talep alındı onayı → Müşteriye
- Rapor tamamlandı → Müşteriye PDF link
- Şifre sıfırlama → Kullanıcıya
- Hoş geldin → Yeni ekip üyesine
- Pentest başladı / bitti → Müşteriye
Tüm mailler HTML şablonlu, Türkçe.
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("REDCELL.email")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "REDCELL AR-GE <noreply@redxcell.com>")
SITE_URL      = os.getenv("SITE_URL", "https://redxcell.com")


# ---------------------------------------------------------------------------
# Temel Gönderici
# ---------------------------------------------------------------------------

def mail_gonder(
    alici: str,
    konu: str,
    html_icerik: str,
    ek_dosyalar: list[tuple[str, bytes]] | None = None,
) -> bool:
    """
    HTML e-posta gönderir.
    ek_dosyalar: [(dosya_adi, bytes), ...]
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("[Mail] SMTP yapılandırılmamış, mail atlandı: %s", alici)
        return False

    try:
        msg = MIMEMultipart("mixed")
        msg["From"]    = SMTP_FROM
        msg["To"]      = alici
        msg["Subject"] = konu

        # HTML gövde
        alternatif = MIMEMultipart("alternative")
        alternatif.attach(MIMEText(html_icerik, "html", "utf-8"))
        msg.attach(alternatif)

        # Ek dosyalar
        if ek_dosyalar:
            for ad, icerik in ek_dosyalar:
                ek = MIMEBase("application", "octet-stream")
                ek.set_payload(icerik)
                encoders.encode_base64(ek)
                ek.add_header("Content-Disposition", f'attachment; filename="{ad}"')
                msg.attach(ek)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as sunucu:
            sunucu.ehlo()
            sunucu.starttls()
            sunucu.login(SMTP_USER, SMTP_PASSWORD)
            sunucu.sendmail(SMTP_FROM, alici, msg.as_string())

        logger.info("[Mail] Gönderildi: %s → %s", konu[:40], alici)
        return True

    except Exception as exc:
        logger.error("[Mail] Gönderilemedi: %s → %s | Hata: %s", konu[:40], alici, exc)
        return False


# ---------------------------------------------------------------------------
# HTML Şablon Motoru
# ---------------------------------------------------------------------------

def _sablon(icerik_html: str, baslik: str) -> str:
    """Tüm maillerin ortak REDCELL HTML şablonu."""
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
  body{{margin:0;padding:0;background:#0a0a0a;font-family:'Helvetica Neue',Arial,sans-serif;color:#e8e8e0}}
  .wrap{{max-width:580px;margin:40px auto;background:#0f0f0f;border:0.5px solid #2a2a2a}}
  .header{{background:#0a0a0a;padding:28px 36px;border-bottom:0.5px solid #1a1a1a}}
  .logo{{font-family:'Courier New',monospace;font-size:15px;font-weight:700;letter-spacing:0.15em;color:#e8e8e0}}
  .logo span{{color:#c0392b}}
  .body{{padding:36px}}
  .title{{font-size:18px;font-weight:600;margin-bottom:16px;color:#e8e8e0}}
  .text{{font-size:14px;line-height:1.7;color:#aaa;margin-bottom:16px}}
  .btn{{display:inline-block;padding:13px 28px;background:#c0392b;color:#fff;text-decoration:none;
        font-family:'Courier New',monospace;font-size:12px;letter-spacing:0.1em;text-transform:uppercase;margin:16px 0}}
  .divider{{border:none;border-top:0.5px solid #1a1a1a;margin:24px 0}}
  .badge{{display:inline-block;padding:4px 10px;border:0.5px solid #2a2a2a;
          font-family:'Courier New',monospace;font-size:11px;color:#888;margin-bottom:8px}}
  .footer{{padding:20px 36px;border-top:0.5px solid #1a1a1a;font-size:11px;color:#555;line-height:1.6}}
  .kirmizi{{color:#c0392b;font-weight:600}}
  .yesil{{color:#27ae60;font-weight:600}}
  .tablo{{width:100%;border-collapse:collapse;margin:16px 0}}
  .tablo td{{padding:10px 12px;border:0.5px solid #1a1a1a;font-size:13px;color:#aaa}}
  .tablo td:first-child{{color:#666;font-family:'Courier New',monospace;font-size:11px;width:35%}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">RED<span>CELL</span> AR-GE</div>
  </div>
  <div class="body">
    <div class="title">{baslik}</div>
    {icerik_html}
  </div>
  <div class="footer">
    Bu e-posta REDCELL AR-GE tarafından otomatik olarak gönderilmiştir.<br/>
    Ofansif Güvenlik &amp; Araştırma — <a href="{SITE_URL}" style="color:#c0392b">{SITE_URL}</a><br/>
    Bu iletiyi yanlışlıkla aldıysanız lütfen dikkate almayınız.
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# 1. YENİ TALEP — Admin'e bildirim
# ---------------------------------------------------------------------------

def mail_yeni_talep_admin(talep: dict, admin_email: str) -> bool:
    icerik = f"""
    <div class="badge">YENİ TALEP</div>
    <p class="text">Sistemde yeni bir pentest talebi oluşturuldu.</p>
    <table class="tablo">
      <tr><td>Müşteri</td><td>{talep.get('ad','')}</td></tr>
      <tr><td>E-posta</td><td>{talep.get('email','')}</td></tr>
      <tr><td>Hizmet</td><td>{talep.get('hizmet','')}</td></tr>
      <tr><td>Öncelik</td><td class="{'kirmizi' if talep.get('oncelik')=='Yüksek' else ''}">{talep.get('oncelik','Normal')}</td></tr>
      <tr><td>Hedef</td><td>{talep.get('hedef','')}</td></tr>
      <tr><td>Tarih</td><td>{datetime.now().strftime('%d.%m.%Y %H:%M')}</td></tr>
    </table>
    <a href="{SITE_URL}/admin" class="btn">Admin Paneline Git</a>
    """
    return mail_gonder(
        admin_email,
        f"[REDCELL] Yeni Talep: {talep.get('ad','')} — {talep.get('hizmet','')}",
        _sablon(icerik, "Yeni Pentest Talebi")
    )


# ---------------------------------------------------------------------------
# 2. TALEP ALINDI — Müşteriye onay
# ---------------------------------------------------------------------------

def mail_talep_alindi_musteri(talep: dict) -> bool:
    icerik = f"""
    <p class="text">Merhaba <strong>{talep.get('ad','')}</strong>,</p>
    <p class="text">
      Siber güvenlik hizmet talebiniz başarıyla alınmıştır. 
      Ekibimiz en kısa sürede sizinle iletişime geçecektir.
    </p>
    <table class="tablo">
      <tr><td>Talep No</td><td><strong>{talep.get('id','')}</strong></td></tr>
      <tr><td>Hizmet</td><td>{talep.get('hizmet','')}</td></tr>
      <tr><td>Hedef</td><td>{talep.get('hedef','')}</td></tr>
      <tr><td>Durum</td><td class="yesil">Alındı — İnceleniyor</td></tr>
    </table>
    <hr class="divider"/>
    <p class="text">
      Sürecinizi müşteri portalımızdan takip edebilirsiniz.
    </p>
    <a href="{SITE_URL}/portal" class="btn">Portalı Aç</a>
    """
    return mail_gonder(
        talep.get("email", ""),
        f"[REDCELL] Talebiniz Alındı — #{talep.get('id','')}",
        _sablon(icerik, "Talebiniz Alındı")
    )


# ---------------------------------------------------------------------------
# 3. RAPOR TAMAMLANDI — Müşteriye
# ---------------------------------------------------------------------------

def mail_rapor_tamamlandi(talep: dict, rapor_id: str, pdf_bytes: bytes | None = None) -> bool:
    ekler = []
    if pdf_bytes:
        ekler.append((f"REDCELL_Rapor_{rapor_id}.pdf", pdf_bytes))

    icerik = f"""
    <p class="text">Merhaba <strong>{talep.get('ad','')}</strong>,</p>
    <p class="text">
      <span class="kirmizi">{talep.get('hizmet','')}</span> kapsamında gerçekleştirilen 
      güvenlik testi tamamlanmış ve raporunuz hazırlanmıştır.
    </p>
    <table class="tablo">
      <tr><td>Talep No</td><td>{talep.get('id','')}</td></tr>
      <tr><td>Rapor No</td><td><strong>{rapor_id}</strong></td></tr>
      <tr><td>Tamamlanma</td><td>{datetime.now().strftime('%d.%m.%Y')}</td></tr>
      <tr><td>Durum</td><td class="yesil">Tamamlandı</td></tr>
    </table>
    <p class="text">
      Raporunuzu {"ekli PDF dosyasında ve " if pdf_bytes else ""}müşteri portalından indirebilirsiniz.
    </p>
    <a href="{SITE_URL}/portal" class="btn">Raporu İndir</a>
    <hr class="divider"/>
    <p class="text" style="font-size:12px;color:#555;">
      Rapor içeriği gizlidir. Lütfen yetkisiz kişilerle paylaşmayınız.
    </p>
    """
    return mail_gonder(
        talep.get("email", ""),
        f"[REDCELL] Güvenlik Raporunuz Hazır — #{rapor_id}",
        _sablon(icerik, "Güvenlik Raporunuz Hazırlandı"),
        ek_dosyalar=ekler if ekler else None
    )


# ---------------------------------------------------------------------------
# 4. ŞİFRE SIFIRLAMA
# ---------------------------------------------------------------------------

def mail_sifre_sifirlama(alici: str, ad: str, token: str) -> bool:
    link = f"{SITE_URL}/sifre-sifirla?token={token}"
    icerik = f"""
    <p class="text">Merhaba <strong>{ad}</strong>,</p>
    <p class="text">
      REDCELL hesabınız için şifre sıfırlama talebinde bulunuldu.
    </p>
    <a href="{link}" class="btn">Şifremi Sıfırla</a>
    <hr class="divider"/>
    <p class="text" style="font-size:12px;color:#555;">
      Bu bağlantı <strong>30 dakika</strong> geçerlidir.<br/>
      Bu talebi siz yapmadıysanız bu e-postayı dikkate almayınız.<br/>
      Link: {link}
    </p>
    """
    return mail_gonder(
        alici,
        "[REDCELL] Şifre Sıfırlama",
        _sablon(icerik, "Şifre Sıfırlama Talebi")
    )


# ---------------------------------------------------------------------------
# 5. HOŞ GELDİN — Yeni ekip üyesi
# ---------------------------------------------------------------------------

def mail_hos_geldin_ekip(uye: dict, gecici_sifre: str) -> bool:
    icerik = f"""
    <p class="text">Merhaba <strong>{uye.get('ad','')}</strong>,</p>
    <p class="text">
      REDCELL AR-GE ekibine hoş geldiniz. Hesabınız oluşturulmuştur.
    </p>
    <table class="tablo">
      <tr><td>Kullanıcı Adı</td><td><strong>{uye.get('kullanici','')}</strong></td></tr>
      <tr><td>Geçici Şifre</td><td><strong>{gecici_sifre}</strong></td></tr>
      <tr><td>Rol</td><td>{uye.get('rol','Ekip Üyesi')}</td></tr>
    </table>
    <a href="{SITE_URL}/ekip" class="btn">Panele Giriş Yap</a>
    <hr class="divider"/>
    <p class="text" style="font-size:12px;color:#555;">
      İlk girişinizde şifrenizi değiştirmeniz gerekmektedir.<br/>
      Güvenliğiniz için 2FA aktif etmenizi öneririz.
    </p>
    """
    return mail_gonder(
        uye.get("eposta", ""),
        "[REDCELL] Hesabınız Oluşturuldu",
        _sablon(icerik, "Ekibe Hoş Geldiniz")
    )


# ---------------------------------------------------------------------------
# 6. PENTEST BAŞLADI — Müşteriye
# ---------------------------------------------------------------------------

def mail_pentest_basladi(talep: dict, ekip_adi: str) -> bool:
    icerik = f"""
    <p class="text">Merhaba <strong>{talep.get('ad','')}</strong>,</p>
    <p class="text">
      <span class="kirmizi">{talep.get('hizmet','')}</span> kapsamındaki güvenlik testiniz başlamıştır.
    </p>
    <table class="tablo">
      <tr><td>Talep No</td><td>{talep.get('id','')}</td></tr>
      <tr><td>Atanan Uzman</td><td>{ekip_adi}</td></tr>
      <tr><td>Başlangıç</td><td>{datetime.now().strftime('%d.%m.%Y %H:%M')}</td></tr>
      <tr><td>Hedef</td><td>{talep.get('hedef','')}</td></tr>
    </table>
    <p class="text">
      Test süresince hedef sisteminizde anlık aktivite gözlemlenebilir.
      Bu durum normaldir ve sözleşme kapsamındadır.
    </p>
    <a href="{SITE_URL}/portal" class="btn">İlerlemeyi Takip Et</a>
    """
    return mail_gonder(
        talep.get("email", ""),
        f"[REDCELL] Güvenlik Testiniz Başladı — #{talep.get('id','')}",
        _sablon(icerik, "Pentest Başladı")
    )
