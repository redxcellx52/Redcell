"""
backend/routes/eksik_rotalar.py
--------------------------------
Tüm eksik endpoint'ler:
- Şifre sıfırlama (admin + ekip + müşteri)
- Müşteri kayıt / giriş
- Dosya yükleme / indirme
- Takvim
- Aktivite geçmişi
- Arama ve filtreleme
- Memnuniyet anketi
- Ödeme ve fatura endpoint'leri
- PDF rapor indirme
- API v1 prefix
"""

import os
import io
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import asyncpg

from backend.security.auth import (
    sifre_hashle, sifre_dogrula, token_olustur, token_coz,
    giris_denemesi_kontrol, giris_basarisiz, giris_basarili,
)
from backend.email.mailer import (
    mail_sifre_sifirlama, mail_talep_alindi_musteri,
    mail_rapor_tamamlandi, mail_hos_geldin_ekip,
)
from backend.payment.iyzico import odeme_formu_olustur, odeme_dogrula, iade_yap
from backend.invoice.fatura import fatura_pdf_olustur, fatura_no_uret

logger = logging.getLogger("REDCELL.routes")

router = APIRouter(prefix="/api/v1")
security = HTTPBearer(auto_error=False)

YUKLEMELER_DIZIN = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
YUKLEMELER_DIZIN.mkdir(parents=True, exist_ok=True)

IZINLI_UZANTILAR = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".log", ".zip", ".docx"}
MAKS_DOSYA_MB    = int(os.getenv("MAX_UPLOAD_MB", 20))
SITE_URL         = os.getenv("SITE_URL", "https://redxcell.com")


# ---------------------------------------------------------------------------
# YARDIMCILAR
# ---------------------------------------------------------------------------

async def get_db():
    """Her istek için DB bağlantısı. main.py pool'undan beslenir."""
    from backend.main import db_pool
    async with db_pool.acquire() as conn:
        yield conn


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token gerekli")
    try:
        return token_coz(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Geçersiz token")


async def aktivite_kaydet(db, kullanici_id: str, eylem: str, detay: dict,
                           talep_id: str = None, ip: str = None,
                           kullanici_tip: str = "ekip"):
    """Her önemli işlemi aktivite geçmişine kaydeder."""
    import json
    try:
        await db.execute("""
            INSERT INTO aktivite_gecmisi
              (kullanici_id, kullanici_tip, eylem, detay, talep_id, ip_adresi)
            VALUES ($1,$2,$3,$4,$5,$6)
        """, kullanici_id, kullanici_tip, eylem,
            json.dumps(detay, ensure_ascii=False), talep_id, ip)
    except Exception as e:
        logger.warning("[Aktivite] Kayıt hatası: %s", e)


# ===========================================================================
# 1. ŞİFRE SIFIRLAMA
# ===========================================================================

@router.post("/auth/sifre-sifirlama-talep")
async def sifre_sifirlama_talep(body: dict, db=Depends(get_db)):
    """
    E-posta ile şifre sıfırlama talebi.
    Hem ekip hem admin hem müşteri için çalışır.
    """
    email  = body.get("email", "").strip().lower()
    tip    = body.get("tip", "ekip")  # ekip | admin | musteri

    if tip in ("ekip", "admin"):
        row = await db.fetchrow(
            "SELECT id, ad FROM kullanicilar WHERE eposta=$1 AND rol=$2",
            email, tip
        )
        tablo = "kullanicilar"
    else:
        row = await db.fetchrow(
            "SELECT id, ad FROM musteri_hesaplari WHERE email=$1",
            email
        )
        tablo = "musteri_hesaplari"

    # Güvenlik: kullanıcı yoksa da başarılı dön (enumeration koruması)
    if not row:
        return {"mesaj": "Eğer bu e-posta kayıtlıysa sıfırlama bağlantısı gönderildi."}

    token   = secrets.token_urlsafe(48)
    gecerli = datetime.utcnow() + timedelta(minutes=30)

    await db.execute("""
        INSERT INTO sifre_sifirlama (kullanici_id, kullanici_tip, token, gecerlilik)
        VALUES ($1,$2,$3,$4)
    """, row["id"], tip, token, gecerli)

    mail_sifre_sifirlama(email, row["ad"], token)

    return {"mesaj": "Eğer bu e-posta kayıtlıysa sıfırlama bağlantısı gönderildi."}


@router.post("/auth/sifre-sifirla")
async def sifre_sifirla(body: dict, db=Depends(get_db)):
    """Token ile yeni şifre belirleme."""
    token      = body.get("token", "")
    yeni_sifre = body.get("yeni_sifre", "")

    if len(yeni_sifre) < 8:
        raise HTTPException(status_code=400, detail="Şifre en az 8 karakter olmalı")

    row = await db.fetchrow("""
        SELECT * FROM sifre_sifirlama
        WHERE token=$1 AND kullanildi=false AND gecerlilik > NOW()
    """, token)

    if not row:
        raise HTTPException(status_code=400, detail="Geçersiz veya süresi dolmuş bağlantı")

    hash_deger = sifre_hashle(yeni_sifre)
    tip = row["kullanici_tip"]

    if tip in ("ekip", "admin"):
        await db.execute(
            "UPDATE kullanicilar SET sifre_hash=$1 WHERE id=$2",
            hash_deger, row["kullanici_id"]
        )
    else:
        await db.execute(
            "UPDATE musteri_hesaplari SET sifre_hash=$1 WHERE id=$2",
            hash_deger, row["kullanici_id"]
        )

    await db.execute(
        "UPDATE sifre_sifirlama SET kullanildi=true WHERE token=$1", token
    )
    return {"mesaj": "Şifre başarıyla güncellendi"}


# ===========================================================================
# 2. MÜŞTERİ KAYIT / GİRİŞ
# ===========================================================================

@router.post("/musteri/kayit")
async def musteri_kayit(body: dict, db=Depends(get_db)):
    """Müşteri portalına yeni kayıt."""
    email    = body.get("email", "").strip().lower()
    ad       = body.get("ad", "").strip()
    sifre    = body.get("sifre", "")

    if not email or not ad or len(sifre) < 8:
        raise HTTPException(status_code=400, detail="Ad, e-posta ve şifre (min 8 karakter) gerekli")

    mevcut = await db.fetchrow("SELECT id FROM musteri_hesaplari WHERE email=$1", email)
    if mevcut:
        raise HTTPException(status_code=409, detail="Bu e-posta zaten kayıtlı")

    musteri_id     = "M" + str(int(datetime.utcnow().timestamp()))[-8:]
    dogrulama_tok  = secrets.token_urlsafe(32)
    hash_deger     = sifre_hashle(sifre)

    await db.execute("""
        INSERT INTO musteri_hesaplari
          (id, ad, soyad, firma, email, sifre_hash, dogrulama_token, kayit_tarih)
        VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
    """, musteri_id, ad,
        body.get("soyad", ""),
        body.get("firma", ""),
        email, hash_deger, dogrulama_tok)

    # Doğrulama maili gönder (basit bilgi maili)
    from backend.email.mailer import mail_gonder, _sablon
    mail_gonder(email, "[REDCELL] Hoş Geldiniz",
        _sablon(f"<p>Merhaba {ad}, hesabınız oluşturuldu.</p>"
                f"<a href='{SITE_URL}/portal' class='btn'>Portala Git</a>",
                "Hoş Geldiniz"))

    return {"mesaj": "Kayıt başarılı", "id": musteri_id}


@router.post("/musteri/giris")
async def musteri_giris(body: dict, request: Request, db=Depends(get_db)):
    """Müşteri portal girişi."""
    email = body.get("email", "").strip().lower()
    sifre = body.get("sifre", "")
    ip    = request.client.host

    izin, kalan = giris_denemesi_kontrol(f"m_{ip}")
    if not izin:
        raise HTTPException(status_code=429,
            detail=f"Çok fazla deneme. {kalan} saniye bekleyin.")

    row = await db.fetchrow(
        "SELECT * FROM musteri_hesaplari WHERE email=$1 AND aktif=true", email
    )

    if not row or not sifre_dogrula(sifre, row["sifre_hash"]):
        giris_basarisiz(f"m_{ip}")
        raise HTTPException(status_code=401, detail="E-posta veya şifre hatalı")

    giris_basarili(f"m_{ip}")
    await db.execute(
        "UPDATE musteri_hesaplari SET son_giris=NOW() WHERE id=$1", row["id"]
    )

    token = token_olustur({"id": row["id"], "ad": row["ad"],
                           "email": email, "rol": "musteri"})
    return {"token": token, "ad": row["ad"]}


@router.get("/musteri/talepler")
async def musteri_talepler(user=Depends(get_current_user), db=Depends(get_db)):
    """Müşteri kendi taleplerini görür."""
    if user["rol"] != "musteri":
        raise HTTPException(status_code=403)
    email = user["email"]
    rows = await db.fetch(
        "SELECT * FROM talepler WHERE email=$1 ORDER BY tarih DESC", email
    )
    return [dict(r) for r in rows]


@router.get("/musteri/raporlar")
async def musteri_raporlar(user=Depends(get_current_user), db=Depends(get_db)):
    """Müşteri kendi raporlarını görür."""
    if user["rol"] != "musteri":
        raise HTTPException(status_code=403)
    rows = await db.fetch("""
        SELECT r.* FROM raporlar r
        JOIN talepler t ON r.talep_id = t.id
        WHERE t.email=$1
        ORDER BY r.tarih DESC
    """, user["email"])
    return [dict(r) for r in rows]


# ===========================================================================
# 3. PDF RAPOR İNDİRME
# ===========================================================================

@router.get("/raporlar/{rapor_id}/pdf")
async def rapor_pdf_indir(rapor_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    """Raporu PDF olarak indirir. Admin, ekip ve ilgili müşteri erişebilir."""
    row = await db.fetchrow("""
        SELECT r.*, t.email as musteri_email, t.ad as musteri_ad, t.hizmet
        FROM raporlar r
        JOIN talepler t ON r.talep_id = t.id
        WHERE r.id=$1
    """, rapor_id)

    if not row:
        raise HTTPException(status_code=404, detail="Rapor bulunamadı")

    # Müşteri sadece kendi raporuna erişir
    if user["rol"] == "musteri" and user["email"] != row["musteri_email"]:
        raise HTTPException(status_code=403)

    # PDF oluştur
    from backend.invoice.fatura import fatura_pdf_olustur
    icerik = row["icerik"] or ""

    # Basit rapor PDF'i (fatura modülü üzerinden)
    fatura_verisi = {
        "no":           rapor_id,
        "tarih":        str(row["tarih"]),
        "musteri_ad":   row["musteri_ad"],
        "musteri_email": row["musteri_email"],
        "musteri_adres": "",
        "kalemler":     [{"aciklama": row["hizmet"], "miktar": 1, "birim_fiyat": 0}],
        "notlar":       icerik[:200],
    }

    try:
        pdf_bytes = fatura_pdf_olustur(fatura_verisi)
    except Exception:
        pdf_bytes = icerik.encode("utf-8")
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="rapor_{rapor_id}.txt"'}
        )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="REDCELL_Rapor_{rapor_id}.pdf"'}
    )


# ===========================================================================
# 4. DOSYA YÜKLEME / İNDİRME
# ===========================================================================

@router.post("/dosyalar/yukle")
async def dosya_yukle(
    talep_id: str,
    tip: str = "bulgu",
    dosya: UploadFile = File(...),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Bulgu kanıtı, hedef belgesi vb. dosya yükleme."""
    uzanti = Path(dosya.filename).suffix.lower()
    if uzanti not in IZINLI_UZANTILAR:
        raise HTTPException(status_code=400,
            detail=f"İzin verilmeyen dosya türü. İzinliler: {', '.join(IZINLI_UZANTILAR)}")

    icerik = await dosya.read()
    if len(icerik) > MAKS_DOSYA_MB * 1024 * 1024:
        raise HTTPException(status_code=413,
            detail=f"Dosya {MAKS_DOSYA_MB} MB'dan büyük olamaz")

    # Güvenli dosya adı
    guvenli_ad  = f"{talep_id}_{user['id']}_{secrets.token_hex(8)}{uzanti}"
    yol         = YUKLEMELER_DIZIN / guvenli_ad
    yol.write_bytes(icerik)

    row = await db.fetchrow("""
        INSERT INTO dosyalar
          (talep_id, yukleyen_id, dosya_adi, dosya_yolu, mime_turu, boyut_byte, tip)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING id
    """, talep_id, user["id"], dosya.filename,
        str(yol), dosya.content_type, len(icerik), tip)

    await aktivite_kaydet(db, user["id"], "dosya_yuklendi",
        {"dosya": dosya.filename, "boyut": len(icerik)}, talep_id)

    return {"id": row["id"], "dosya_adi": dosya.filename, "boyut": len(icerik)}


@router.get("/dosyalar/{dosya_id}/indir")
async def dosya_indir(dosya_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """Yüklenen dosyayı indirir."""
    row = await db.fetchrow("SELECT * FROM dosyalar WHERE id=$1", dosya_id)
    if not row:
        raise HTTPException(status_code=404)

    yol = Path(row["dosya_yolu"])
    if not yol.exists():
        raise HTTPException(status_code=404, detail="Dosya bulunamadı")

    return StreamingResponse(
        io.BytesIO(yol.read_bytes()),
        media_type=row["mime_turu"] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{row["dosya_adi"]}"'}
    )


@router.get("/dosyalar")
async def dosyalar_listele(talep_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch(
        "SELECT id,dosya_adi,mime_turu,boyut_byte,tip,tarih FROM dosyalar WHERE talep_id=$1",
        talep_id
    )
    return [dict(r) for r in rows]


# ===========================================================================
# 5. TAKVİM
# ===========================================================================

@router.get("/takvim")
async def takvim_listele(
    baslangic: str = Query(None),
    bitis: str = Query(None),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Takvim etkinliklerini listeler. Tarih filtresi opsiyonel."""
    sql  = "SELECT * FROM takvim_etkinlikleri WHERE 1=1"
    vals = []
    if baslangic:
        vals.append(baslangic)
        sql += f" AND baslangic >= ${len(vals)}"
    if bitis:
        vals.append(bitis)
        sql += f" AND baslangic <= ${len(vals)}"
    sql += " ORDER BY baslangic ASC"
    rows = await db.fetch(sql, *vals)
    return [dict(r) for r in rows]


@router.post("/takvim")
async def takvim_ekle(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    row = await db.fetchrow("""
        INSERT INTO takvim_etkinlikleri
          (talep_id, gorev_id, baslik, aciklama, baslangic, bitis, tip, renk, olusturan)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        RETURNING id
    """, body.get("talep_id"), body.get("gorev_id"),
        body["baslik"], body.get("aciklama"),
        body["baslangic"], body.get("bitis"),
        body.get("tip","pentest"), body.get("renk","#c0392b"),
        user["id"])
    return {"id": row["id"]}


@router.delete("/takvim/{etkinlik_id}")
async def takvim_sil(etkinlik_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    await db.execute("DELETE FROM takvim_etkinlikleri WHERE id=$1", etkinlik_id)
    return {"ok": True}


# ===========================================================================
# 6. AKTİVİTE GEÇMİŞİ
# ===========================================================================

@router.get("/aktivite")
async def aktivite_listele(
    talep_id: str = Query(None),
    limit: int = Query(50, le=200),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    if talep_id:
        rows = await db.fetch("""
            SELECT * FROM aktivite_gecmisi
            WHERE talep_id=$1 ORDER BY tarih DESC LIMIT $2
        """, talep_id, limit)
    else:
        rows = await db.fetch("""
            SELECT * FROM aktivite_gecmisi
            ORDER BY tarih DESC LIMIT $1
        """, limit)
    return [dict(r) for r in rows]


# ===========================================================================
# 7. ARAMA VE FİLTRELEME
# ===========================================================================

@router.get("/arama")
async def arama(
    q: str = Query("", min_length=1),
    tip: str = Query("tümü"),   # tümü | talepler | raporlar | ekip
    durum: str = Query(None),
    tarih_baslangic: str = Query(None),
    tarih_bitis: str = Query(None),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Genel arama. Talepler, raporlar ve ekip üyelerinde arar."""
    q_like = f"%{q}%"
    sonuclar = {"talepler": [], "raporlar": [], "ekip": []}

    if tip in ("tümü", "talepler"):
        sql = """
            SELECT id, ad, hizmet, durum, tarih, email
            FROM talepler
            WHERE (ad ILIKE $1 OR hizmet ILIKE $1 OR email ILIKE $1 OR ozet ILIKE $1)
        """
        vals = [q_like]
        if durum:
            vals.append(durum)
            sql += f" AND durum=${len(vals)}"
        if tarih_baslangic:
            vals.append(tarih_baslangic)
            sql += f" AND tarih >= ${len(vals)}"
        if tarih_bitis:
            vals.append(tarih_bitis)
            sql += f" AND tarih <= ${len(vals)}"
        sql += " ORDER BY tarih DESC LIMIT 20"
        rows = await db.fetch(sql, *vals)
        sonuclar["talepler"] = [dict(r) for r in rows]

    if tip in ("tümü", "raporlar"):
        rows = await db.fetch("""
            SELECT id, ad, hizmet, tarih FROM raporlar
            WHERE ad ILIKE $1 OR hizmet ILIKE $1 OR icerik ILIKE $1
            ORDER BY tarih DESC LIMIT 20
        """, q_like)
        sonuclar["raporlar"] = [dict(r) for r in rows]

    if tip in ("tümü", "ekip"):
        rows = await db.fetch("""
            SELECT id, ad, rol, durum FROM kullanicilar
            WHERE rol='ekip' AND (ad ILIKE $1 OR eposta ILIKE $1)
            LIMIT 10
        """, q_like)
        sonuclar["ekip"] = [dict(r) for r in rows]

    return sonuclar


# ===========================================================================
# 8. MEMNUNİYET ANKETİ
# ===========================================================================

@router.post("/anket/gonder")
async def anket_gonder(talep_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    """Proje tamamlanınca müşteriye anket bağlantısı gönderir."""
    talep = await db.fetchrow("SELECT * FROM talepler WHERE id=$1", talep_id)
    if not talep:
        raise HTTPException(status_code=404)

    token = secrets.token_urlsafe(32)
    await db.execute("""
        INSERT INTO anketler (talep_id, musteri_email, token)
        VALUES ($1,$2,$3)
        ON CONFLICT DO NOTHING
    """, talep_id, talep["email"], token)

    link = f"{SITE_URL}/anket?token={token}"
    from backend.email.mailer import mail_gonder, _sablon
    mail_gonder(
        talep["email"],
        "[REDCELL] Hizmet Değerlendirmesi",
        _sablon(
            f"<p>Merhaba {talep['ad']},</p>"
            f"<p>Hizmetimizi değerlendirmenizi rica ederiz.</p>"
            f"<a href='{link}' class='btn'>Anketi Doldur</a>",
            "Hizmet Değerlendirmesi"
        )
    )
    return {"mesaj": "Anket gönderildi"}


@router.post("/anket/yanit")
async def anket_yanit(body: dict, db=Depends(get_db)):
    """Müşteri anket yanıtını kaydeder. Token ile erişim, auth gerekmez."""
    token = body.get("token", "")
    row   = await db.fetchrow(
        "SELECT * FROM anketler WHERE token=$1 AND tamamlandi=false", token
    )
    if not row:
        raise HTTPException(status_code=400, detail="Geçersiz veya tamamlanmış anket")

    await db.execute("""
        UPDATE anketler SET
            puan=$1, yorum=$2, hiz_puani=$3,
            kalite_puani=$4, iletisim_puani=$5, tamamlandi=true
        WHERE token=$6
    """, body.get("puan"), body.get("yorum"),
        body.get("hiz_puani"), body.get("kalite_puani"),
        body.get("iletisim_puani"), token)
    return {"mesaj": "Değerlendirmeniz için teşekkürler"}


@router.get("/anket/istatistik")
async def anket_istatistik(user=Depends(get_current_user), db=Depends(get_db)):
    row = await db.fetchrow("""
        SELECT
            COUNT(*) FILTER (WHERE tamamlandi) AS tamamlanan,
            ROUND(AVG(puan)::numeric, 1) AS ort_puan,
            ROUND(AVG(hiz_puani)::numeric, 1) AS ort_hiz,
            ROUND(AVG(kalite_puani)::numeric, 1) AS ort_kalite,
            ROUND(AVG(iletisim_puani)::numeric, 1) AS ort_iletisim
        FROM anketler WHERE tamamlandi=true
    """)
    return dict(row) if row else {}


# ===========================================================================
# 9. ÖDEME ENDPOINTLERİ
# ===========================================================================

@router.post("/odeme/baslat")
async def odeme_baslat(body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    """İyzico ödeme formu oluşturur."""
    talep_id = body["talep_id"]
    tutar    = float(body["tutar"])

    talep = await db.fetchrow("SELECT * FROM talepler WHERE id=$1", talep_id)
    if not talep:
        raise HTTPException(status_code=404)

    odeme_id = "OD" + str(int(datetime.utcnow().timestamp()))[-8:]

    # DB'ye ödeme kaydı
    kdv = tutar * 0.20
    await db.execute("""
        INSERT INTO odemeler
          (id, talep_id, musteri_email, tutar, kdv_tutari, genel_toplam, durum)
        VALUES ($1,$2,$3,$4,$5,$6,'bekleyen')
    """, odeme_id, talep_id, talep["email"], tutar, kdv, tutar + kdv)

    musteri = {
        "id":    odeme_id,
        "ad":    talep["ad"].split()[0] if talep["ad"] else "Müşteri",
        "soyad": " ".join(talep["ad"].split()[1:]) if " " in (talep["ad"] or "") else ".",
        "email": talep["email"] or "",
    }

    sonuc = await odeme_formu_olustur(
        odeme_id, musteri, tutar + kdv,
        f"REDCELL Pentest — {talep['hizmet']}"
    )
    return {**sonuc, "odeme_id": odeme_id}


@router.post("/odeme/callback")
async def odeme_callback(request: Request, db=Depends(get_db)):
    """İyzico ödeme callback'i."""
    form = await request.form()
    token = form.get("token", "")

    dogrulama = await odeme_dogrula(token)

    if dogrulama["basarili"]:
        await db.execute("""
            UPDATE odemeler
            SET durum='tamamlandi', iyzico_odeme_id=$1
            WHERE iyzico_token=$2
        """, dogrulama.get("odeme_id"), token)

        # Otomatik fatura oluştur
        odeme = await db.fetchrow("SELECT * FROM odemeler WHERE iyzico_token=$1", token)
        if odeme:
            await _fatura_olustur_ve_gonder(db, odeme)

    return HTMLResponse(f"""
        <script>window.location='{os.getenv("SITE_URL","/")}/portal?odeme={"basarili" if dogrulama["basarili"] else "basarisiz"}'</script>
    """)


async def _fatura_olustur_ve_gonder(db, odeme):
    """Ödeme tamamlanınca fatura oluşturur ve mailler."""
    try:
        sira = await db.fetchval("SELECT COUNT(*) + 1 FROM faturalar")
        fatura_no = fatura_no_uret(sira)

        talep = await db.fetchrow("SELECT * FROM talepler WHERE id=$1", odeme["talep_id"])
        if not talep:
            return

        fatura_verisi = {
            "no":           fatura_no,
            "tarih":        datetime.now().strftime("%d.%m.%Y"),
            "musteri_ad":   talep["ad"],
            "musteri_email": talep["email"],
            "musteri_adres": "",
            "odeme_id":     odeme["id"],
            "kalemler":     [{"aciklama": talep["hizmet"],
                              "miktar": 1, "birim_fiyat": float(odeme["tutar"])}],
        }

        pdf = fatura_pdf_olustur(fatura_verisi)

        await db.execute("""
            INSERT INTO faturalar
              (fatura_no, odeme_id, talep_id, musteri_ad, musteri_email,
               kalemler, ara_toplam, kdv_tutari, genel_toplam)
            VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
        """, fatura_no, odeme["id"], odeme["talep_id"],
            talep["ad"], talep["email"],
            f'[{{"aciklama":"{talep["hizmet"]}","miktar":1,"birim_fiyat":{float(odeme["tutar"])}}}]',
            odeme["tutar"], odeme["kdv_tutari"], odeme["genel_toplam"])

        mail_rapor_tamamlandi(dict(talep), fatura_no, pdf)
        logger.info("[Fatura] Oluşturuldu ve gönderildi: %s", fatura_no)

    except Exception as e:
        logger.error("[Fatura] Oluşturma hatası: %s", e)


@router.get("/faturalar")
async def faturalar_listele(user=Depends(get_current_user), db=Depends(get_db)):
    rows = await db.fetch("SELECT * FROM faturalar ORDER BY tarih DESC")
    return [dict(r) for r in rows]


@router.get("/faturalar/{fatura_id}/pdf")
async def fatura_indir(fatura_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """Fatura PDF'ini indirir."""
    row = await db.fetchrow("SELECT * FROM faturalar WHERE id=$1", fatura_id)
    if not row:
        raise HTTPException(status_code=404)

    import json
    fatura_verisi = {
        "no":           row["fatura_no"],
        "tarih":        str(row["tarih"]),
        "musteri_ad":   row["musteri_ad"],
        "musteri_email": row["musteri_email"],
        "musteri_adres": row.get("musteri_adres",""),
        "kalemler":     json.loads(row["kalemler"]) if isinstance(row["kalemler"], str) else row["kalemler"],
    }
    pdf = fatura_pdf_olustur(fatura_verisi)

    return StreamingResponse(
        io.BytesIO(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="Fatura_{row["fatura_no"]}.pdf"'}
    )


# ===========================================================================
# 10. API VERSİYONLAMA UYUMLULUĞU
# ===========================================================================

# /api/ → /api/v1/ yönlendirme için eski rotalar buraya alias olarak eklenir
# main.py'de hem /api hem /api/v1 prefix'i router'a bağlanır
