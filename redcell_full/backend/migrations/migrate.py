"""
backend/migrations/migrate.py
------------------------------
Veritabanı migration sistemi.
Alembic yerine hafif, bağımsız migration yöneticisi.
Şema değişikliklerini sıralı olarak uygular,
hangi migration'ların uygulandığını takip eder.
"""

import os
import asyncio
import logging
from datetime import datetime

import asyncpg

logger = logging.getLogger("REDCELL.migrate")

DB_DSN = os.getenv("DATABASE_URL",
    "postgresql://postgres:changeme@localhost:5432/redcell")

# ---------------------------------------------------------------------------
# MİGRATİON'LAR — Sıralı, geri alınamaz
# ---------------------------------------------------------------------------
MIGRASYONLAR = [

    {
        "versiyon": "001",
        "aciklama": "Temel şema oluştur",
        "sql": open(
            os.path.join(os.path.dirname(__file__), "../../docker/schema.sql"),
            encoding="utf-8"
        ).read() if os.path.exists(
            os.path.join(os.path.dirname(__file__), "../../docker/schema.sql")
        ) else "SELECT 1;",
    },

    {
        "versiyon": "002",
        "aciklama": "Müşteri portalı için kayıt tablosu",
        "sql": """
            CREATE TABLE IF NOT EXISTS musteri_hesaplari (
                id              VARCHAR(20) PRIMARY KEY,
                ad              VARCHAR(100) NOT NULL,
                soyad           VARCHAR(100),
                firma           VARCHAR(255),
                email           VARCHAR(150) UNIQUE NOT NULL,
                sifre_hash      VARCHAR(64) NOT NULL,
                tfa_aktif       BOOLEAN DEFAULT FALSE,
                tfa_secret      VARCHAR(64),
                dogrulama_token VARCHAR(64),
                email_dogrulandi BOOLEAN DEFAULT FALSE,
                kayit_tarih     TIMESTAMP DEFAULT NOW(),
                son_giris       TIMESTAMP,
                aktif           BOOLEAN DEFAULT TRUE
            );
            CREATE INDEX IF NOT EXISTS idx_musteri_email
                ON musteri_hesaplari(email);
        """,
    },

    {
        "versiyon": "003",
        "aciklama": "Şifre sıfırlama tokenları",
        "sql": """
            CREATE TABLE IF NOT EXISTS sifre_sifirlama (
                id          SERIAL PRIMARY KEY,
                kullanici_id VARCHAR(20) NOT NULL,
                kullanici_tip VARCHAR(10) NOT NULL DEFAULT 'ekip',
                token        VARCHAR(64) UNIQUE NOT NULL,
                gecerlilik   TIMESTAMP NOT NULL,
                kullanildi   BOOLEAN DEFAULT FALSE,
                olusturma    TIMESTAMP DEFAULT NOW()
            );
        """,
    },

    {
        "versiyon": "004",
        "aciklama": "Ödeme ve fatura tabloları",
        "sql": """
            CREATE TABLE IF NOT EXISTS odemeler (
                id              VARCHAR(30) PRIMARY KEY,
                talep_id        VARCHAR(20) REFERENCES talepler(id) ON DELETE SET NULL,
                musteri_email   VARCHAR(150),
                tutar           NUMERIC(10,2) NOT NULL,
                kdv_tutari      NUMERIC(10,2),
                genel_toplam    NUMERIC(10,2),
                para_birimi     VARCHAR(5) DEFAULT 'TRY',
                iyzico_token    VARCHAR(100),
                iyzico_odeme_id VARCHAR(50),
                durum           VARCHAR(20) DEFAULT 'bekleyen',
                taksit          INT DEFAULT 1,
                tarih           TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS faturalar (
                id              SERIAL PRIMARY KEY,
                fatura_no       VARCHAR(20) UNIQUE NOT NULL,
                odeme_id        VARCHAR(30) REFERENCES odemeler(id),
                talep_id        VARCHAR(20),
                musteri_ad      VARCHAR(255),
                musteri_email   VARCHAR(150),
                musteri_adres   TEXT,
                kalemler        JSONB NOT NULL,
                ara_toplam      NUMERIC(10,2),
                kdv_orani       NUMERIC(4,2) DEFAULT 0.20,
                kdv_tutari      NUMERIC(10,2),
                genel_toplam    NUMERIC(10,2),
                pdf_yolu        VARCHAR(512),
                tarih           DATE DEFAULT CURRENT_DATE,
                iptal           BOOLEAN DEFAULT FALSE
            );
        """,
    },

    {
        "versiyon": "005",
        "aciklama": "Takvim ve randevu sistemi",
        "sql": """
            CREATE TABLE IF NOT EXISTS takvim_etkinlikleri (
                id          SERIAL PRIMARY KEY,
                talep_id    VARCHAR(20) REFERENCES talepler(id) ON DELETE CASCADE,
                gorev_id    VARCHAR(20),
                baslik      VARCHAR(255) NOT NULL,
                aciklama    TEXT,
                baslangic   TIMESTAMP NOT NULL,
                bitis       TIMESTAMP,
                tip         VARCHAR(30) DEFAULT 'pentest',
                renk        VARCHAR(7)  DEFAULT '#c0392b',
                olusturan   VARCHAR(20),
                tarih       TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_takvim_baslangic
                ON takvim_etkinlikleri(baslangic);
        """,
    },

    {
        "versiyon": "006",
        "aciklama": "Dosya yükleme tablosu",
        "sql": """
            CREATE TABLE IF NOT EXISTS dosyalar (
                id          SERIAL PRIMARY KEY,
                talep_id    VARCHAR(20) REFERENCES talepler(id) ON DELETE CASCADE,
                gorev_id    VARCHAR(20),
                yukleyen_id VARCHAR(20),
                dosya_adi   VARCHAR(255) NOT NULL,
                dosya_yolu  VARCHAR(512) NOT NULL,
                mime_turu   VARCHAR(100),
                boyut_byte  BIGINT,
                tip         VARCHAR(30) DEFAULT 'bulgu',
                tarih       TIMESTAMP DEFAULT NOW()
            );
        """,
    },

    {
        "versiyon": "007",
        "aciklama": "Aktivite geçmişi tablosu",
        "sql": """
            CREATE TABLE IF NOT EXISTS aktivite_gecmisi (
                id          SERIAL PRIMARY KEY,
                kullanici_id VARCHAR(20),
                kullanici_tip VARCHAR(10) DEFAULT 'ekip',
                eylem        VARCHAR(100) NOT NULL,
                detay        JSONB DEFAULT '{}',
                talep_id     VARCHAR(20),
                ip_adresi    VARCHAR(45),
                tarih        TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_aktivite_kullanici
                ON aktivite_gecmisi(kullanici_id);
            CREATE INDEX IF NOT EXISTS idx_aktivite_talep
                ON aktivite_gecmisi(talep_id);
        """,
    },

    {
        "versiyon": "008",
        "aciklama": "Memnuniyet anketi tablosu",
        "sql": """
            CREATE TABLE IF NOT EXISTS anketler (
                id              SERIAL PRIMARY KEY,
                talep_id        VARCHAR(20) REFERENCES talepler(id) ON DELETE CASCADE,
                musteri_email   VARCHAR(150),
                puan            INT CHECK (puan BETWEEN 1 AND 5),
                yorum           TEXT,
                hiz_puani       INT CHECK (hiz_puani BETWEEN 1 AND 5),
                kalite_puani    INT CHECK (kalite_puani BETWEEN 1 AND 5),
                iletisim_puani  INT CHECK (iletisim_puani BETWEEN 1 AND 5),
                token           VARCHAR(64) UNIQUE,
                tamamlandi      BOOLEAN DEFAULT FALSE,
                tarih           TIMESTAMP DEFAULT NOW()
            );
        """,
    },
]


# ---------------------------------------------------------------------------
# MİGRASYON YÖNETİCİSİ
# ---------------------------------------------------------------------------

async def migration_tablosu_olustur(conn):
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS migration_gecmisi (
            versiyon    VARCHAR(10) PRIMARY KEY,
            aciklama    TEXT,
            uygulandi   TIMESTAMP DEFAULT NOW()
        );
    """)


async def uygulanan_versiyonlar(conn) -> set:
    rows = await conn.fetch("SELECT versiyon FROM migration_gecmisi")
    return {r["versiyon"] for r in rows}


async def migrate():
    """Tüm bekleyen migration'ları sırayla uygular."""
    logger.info("Migration başlatılıyor...")
    conn = await asyncpg.connect(DB_DSN)

    try:
        await migration_tablosu_olustur(conn)
        uygulananlar = await uygulanan_versiyonlar(conn)

        bekleyenler = [
            m for m in MIGRASYONLAR
            if m["versiyon"] not in uygulananlar
        ]

        if not bekleyenler:
            logger.info("Tüm migration'lar güncel.")
            return

        for m in bekleyenler:
            logger.info("Migration uygulanıyor: %s — %s",
                        m["versiyon"], m["aciklama"])
            try:
                await conn.execute(m["sql"])
                await conn.execute(
                    "INSERT INTO migration_gecmisi (versiyon, aciklama) VALUES ($1, $2)",
                    m["versiyon"], m["aciklama"]
                )
                logger.info("✅ Migration %s tamamlandı.", m["versiyon"])
            except Exception as exc:
                logger.error("❌ Migration %s BAŞARISIZ: %s", m["versiyon"], exc)
                raise

        logger.info("Tüm migration'lar uygulandı.")

    finally:
        await conn.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(migrate())
