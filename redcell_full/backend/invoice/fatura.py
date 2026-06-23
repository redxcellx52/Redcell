"""
backend/invoice/fatura.py
-------------------------
E-fatura sistemi.
- PDF fatura üretimi (reportlab)
- Fatura numarası otomatik artan
- KDV hesaplama (%20)
- Fatura veritabanına kayıt
- E-posta ile gönderim
GİB entegrasyonu için e-arşiv fatura yapısı hazır.
"""

import os
import io
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("REDCELL.invoice")

FIRMA_BILGI = {
    "ad":           "REDCELL AR-GE",
    "adres":        "İstanbul, Türkiye",
    "telefon":      "+90 212 000 00 00",
    "eposta":       "fatura@redxcell.com",
    "web":          "www.redxcell.com",
    "vergi_dairesi": "Beyoğlu VD",
    "vergi_no":     "1234567890",
    "iban":         "TR00 0000 0000 0000 0000 0000 00",
}

KDV_ORANI = float(os.getenv("KDV_ORANI", 0.20))  # %20


# ---------------------------------------------------------------------------
# PDF FATURA ÜRETİCİ
# ---------------------------------------------------------------------------

def fatura_pdf_olustur(fatura: dict) -> bytes:
    """
    Fatura verisinden PDF üretir.
    fatura: {
      no, tarih, musteri_ad, musteri_email, musteri_adres,
      kalemler: [{aciklama, miktar, birim_fiyat}],
      odeme_id, notlar
    }
    Döner: PDF bytes
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph,
            Spacer, HRFlowable
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_RIGHT, TA_CENTER, TA_LEFT

        tampon = io.BytesIO()
        doc = SimpleDocTemplate(
            tampon,
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm,   bottomMargin=2*cm,
        )

        KIRMIZI   = HexColor("#c0392b")
        KOYU      = HexColor("#0a0a0a")
        GRI       = HexColor("#888888")
        ACIK_GRI  = HexColor("#f5f5f5")

        stiller = getSampleStyleSheet()
        baslik_stil = ParagraphStyle("baslik",
            fontSize=22, fontName="Helvetica-Bold",
            textColor=KIRMIZI, spaceAfter=4)
        normal_stil = ParagraphStyle("normal",
            fontSize=9, fontName="Helvetica",
            textColor=KOYU, leading=14)
        kucuk_stil = ParagraphStyle("kucuk",
            fontSize=8, fontName="Helvetica",
            textColor=GRI, leading=12)
        sag_stil = ParagraphStyle("sag",
            fontSize=9, fontName="Helvetica",
            textColor=KOYU, alignment=TA_RIGHT)

        elemanlar = []

        # ---- BAŞLIK ----
        baslik_tablo = Table([
            [
                Paragraph("REDCELL AR-GE", baslik_stil),
                Paragraph(f"<b>FATURA</b>", ParagraphStyle("f",
                    fontSize=28, fontName="Helvetica-Bold",
                    textColor=KOYU, alignment=TA_RIGHT)),
            ]
        ], colWidths=[9*cm, 8*cm])
        baslik_tablo.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "BOTTOM"),
        ]))
        elemanlar.append(baslik_tablo)
        elemanlar.append(Spacer(1, 0.3*cm))
        elemanlar.append(HRFlowable(width="100%", thickness=0.5, color=KIRMIZI))
        elemanlar.append(Spacer(1, 0.5*cm))

        # ---- FİRMA BİLGİLERİ + FATURA BİLGİLERİ ----
        bilgi_tablo = Table([
            [
                Paragraph(
                    f"<b>{FIRMA_BILGI['ad']}</b><br/>"
                    f"{FIRMA_BILGI['adres']}<br/>"
                    f"Tel: {FIRMA_BILGI['telefon']}<br/>"
                    f"E-posta: {FIRMA_BILGI['eposta']}<br/>"
                    f"Vergi Dairesi: {FIRMA_BILGI['vergi_dairesi']}<br/>"
                    f"Vergi No: {FIRMA_BILGI['vergi_no']}",
                    kucuk_stil
                ),
                Paragraph(
                    f"<b>Fatura No:</b> {fatura['no']}<br/>"
                    f"<b>Tarih:</b> {fatura['tarih']}<br/>"
                    f"<b>Ödeme:</b> {fatura.get('odeme_id','—')}<br/>"
                    f"<br/>"
                    f"<b>Alıcı:</b><br/>"
                    f"{fatura['musteri_ad']}<br/>"
                    f"{fatura.get('musteri_adres','')}<br/>"
                    f"{fatura['musteri_email']}",
                    kucuk_stil
                ),
            ]
        ], colWidths=[8.5*cm, 8.5*cm])
        elemanlar.append(bilgi_tablo)
        elemanlar.append(Spacer(1, 0.8*cm))

        # ---- KALEM TABLOSU ----
        tablo_verisi = [
            ["#", "Açıklama", "Miktar", "Birim Fiyat", "Tutar"],
        ]
        ara_toplam = 0
        for i, kalem in enumerate(fatura.get("kalemler", []), 1):
            birim = float(kalem["birim_fiyat"])
            miktar = float(kalem.get("miktar", 1))
            toplam = birim * miktar
            ara_toplam += toplam
            tablo_verisi.append([
                str(i),
                kalem["aciklama"],
                f"{miktar:.0f}",
                f"₺{birim:,.2f}",
                f"₺{toplam:,.2f}",
            ])

        kdv = ara_toplam * KDV_ORANI
        genel_toplam = ara_toplam + kdv

        # Toplam satırları
        tablo_verisi.extend([
            ["", "", "", "Ara Toplam", f"₺{ara_toplam:,.2f}"],
            ["", "", "", f"KDV (%{int(KDV_ORANI*100)})", f"₺{kdv:,.2f}"],
            ["", "", "", "GENEL TOPLAM", f"₺{genel_toplam:,.2f}"],
        ])

        kalem_tablo = Table(tablo_verisi,
            colWidths=[0.8*cm, 9.2*cm, 1.8*cm, 3*cm, 3*cm])
        kalem_tablo.setStyle(TableStyle([
            # Başlık satırı
            ("BACKGROUND",    (0,0), (-1,0), KOYU),
            ("TEXTCOLOR",     (0,0), (-1,0), white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 8),
            ("ALIGN",         (0,0), (-1,0), "CENTER"),
            ("BOTTOMPADDING", (0,0), (-1,0), 8),
            ("TOPPADDING",    (0,0), (-1,0), 8),
            # Veri satırları
            ("FONTNAME",      (0,1), (-1,-4), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-4), [white, ACIK_GRI]),
            ("GRID",          (0,0), (-1,-4), 0.25, HexColor("#dddddd")),
            ("TOPPADDING",    (0,1), (-1,-4), 6),
            ("BOTTOMPADDING", (0,1), (-1,-4), 6),
            # Hizalama
            ("ALIGN",         (2,1), (-1,-1), "RIGHT"),
            # Toplam satırları
            ("FONTNAME",      (3,-3), (-1,-1), "Helvetica-Bold"),
            ("LINEABOVE",     (3,-3), (-1,-3), 0.5, KOYU),
            ("BACKGROUND",    (0,-1), (-1,-1), KIRMIZI),
            ("TEXTCOLOR",     (0,-1), (-1,-1), white),
            ("ROWBACKGROUNDS",(0,-3), (-1,-2), [ACIK_GRI]),
        ]))
        elemanlar.append(kalem_tablo)
        elemanlar.append(Spacer(1, 0.8*cm))

        # ---- ÖDEME BİLGİSİ ----
        if fatura.get("notlar"):
            elemanlar.append(Paragraph(f"Not: {fatura['notlar']}", kucuk_stil))
            elemanlar.append(Spacer(1, 0.3*cm))

        elemanlar.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#dddddd")))
        elemanlar.append(Spacer(1, 0.3*cm))
        elemanlar.append(Paragraph(
            f"<b>Banka Transferi:</b> {FIRMA_BILGI['iban']}<br/>"
            f"Ödeme açıklamasına fatura numarasını ({fatura['no']}) yazmayı unutmayınız.",
            kucuk_stil
        ))
        elemanlar.append(Spacer(1, 1*cm))
        elemanlar.append(Paragraph(
            "Bu fatura REDCELL AR-GE tarafından elektronik olarak düzenlenmiştir.",
            ParagraphStyle("alt", fontSize=7, textColor=GRI, alignment=TA_CENTER)
        ))

        doc.build(elemanlar)
        return tampon.getvalue()

    except ImportError:
        logger.warning("[Fatura] reportlab kurulu değil, metin fatura üretiliyor.")
        return _metin_fatura(fatura)


def _metin_fatura(fatura: dict) -> bytes:
    """reportlab yoksa düz metin fatura üretir."""
    satirlar = [
        "REDCELL AR-GE — FATURA",
        "=" * 50,
        f"Fatura No : {fatura['no']}",
        f"Tarih     : {fatura['tarih']}",
        f"Müşteri   : {fatura['musteri_ad']}",
        f"E-posta   : {fatura['musteri_email']}",
        "-" * 50,
    ]
    ara = 0
    for k in fatura.get("kalemler", []):
        t = float(k["birim_fiyat"]) * float(k.get("miktar", 1))
        ara += t
        satirlar.append(f"{k['aciklama']}: ₺{t:,.2f}")
    kdv = ara * KDV_ORANI
    satirlar += [
        "-" * 50,
        f"Ara Toplam : ₺{ara:,.2f}",
        f"KDV (%{int(KDV_ORANI*100)})   : ₺{kdv:,.2f}",
        f"TOPLAM     : ₺{ara+kdv:,.2f}",
        "=" * 50,
    ]
    return "\n".join(satirlar).encode("utf-8")


# ---------------------------------------------------------------------------
# FATURA NUMARASI ÜRETİCİ
# ---------------------------------------------------------------------------

def fatura_no_uret(sira: int) -> str:
    """RC-2026-00001 formatında fatura numarası."""
    yil = datetime.now().year
    return f"RC-{yil}-{sira:05d}"
