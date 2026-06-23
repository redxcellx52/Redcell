-- ============================================================
-- REDCELL AR-GE — PostgreSQL Şeması
-- docker-compose başlarken otomatik uygulanır
-- ============================================================

-- Timestamp auto-update fonksiyonu
CREATE OR REPLACE FUNCTION guncelle_timestamp()
RETURNS TRIGGER AS $$
BEGIN NEW.guncelleme = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- KULLANICILAR (Admin + Ekip)
-- ============================================================
CREATE TABLE IF NOT EXISTS kullanicilar (
    id           VARCHAR(20)  PRIMARY KEY,
    ad           VARCHAR(100) NOT NULL,
    kullanici    VARCHAR(50)  UNIQUE NOT NULL,
    sifre_hash   VARCHAR(64)  NOT NULL,
    rol          VARCHAR(20)  NOT NULL DEFAULT 'ekip', -- admin | ekip
    eposta       VARCHAR(150),
    cert         JSONB        DEFAULT '[]',
    uzmanlik     JSONB        DEFAULT '[]',
    durum        VARCHAR(20)  DEFAULT 'available',     -- available | busy
    kayit_tarih  DATE         DEFAULT CURRENT_DATE,
    guncelleme   TIMESTAMP    DEFAULT NOW()
);

CREATE TRIGGER trg_kullanicilar
BEFORE UPDATE ON kullanicilar
FOR EACH ROW EXECUTE FUNCTION guncelle_timestamp();

-- Varsayılan admin (sifre: redcell2025 → sha256)
INSERT INTO kullanicilar (id, ad, kullanici, sifre_hash, rol)
VALUES (
    'ADM001', 'Admin', 'admin',
    'a1b3c4d7e8f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8',
    'admin'
) ON CONFLICT (id) DO NOTHING;

-- Demo ekip üyeleri (sifre: test123 → sha256)
INSERT INTO kullanicilar (id, ad, kullanici, sifre_hash, rol, eposta, cert, uzmanlik)
VALUES
('U001','Mehmet Arslan','mehmet','ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae','ekip','mehmet@redcell.com.tr','["OSCP","CEH"]','["web","network","pentest"]'),
('U002','Ayse Kaya','ayse','ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae','ekip','ayse@redcell.com.tr','["eWPTX","GWAPT"]','["web","owasp","appsec","burp"]'),
('U003','Can Demir','can','ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae','ekip','can@redcell.com.tr','["CRTO","OSCP"]','["redteam","apt","lateral","c2"]')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- TALEPLER
-- ============================================================
CREATE TABLE IF NOT EXISTS talepler (
    id         VARCHAR(20)  PRIMARY KEY,
    ad         VARCHAR(255) NOT NULL,
    email      VARCHAR(150),
    hizmet     VARCHAR(100),
    ozet       TEXT,
    hedef      TEXT,
    oncelik    VARCHAR(20)  DEFAULT 'Normal',
    kapsam     JSONB        DEFAULT '[]',
    durum      VARCHAR(30)  DEFAULT 'bekleyen', -- bekleyen | devam | tamamlandi
    tarih      DATE         DEFAULT CURRENT_DATE,
    guncelleme TIMESTAMP    DEFAULT NOW()
);

CREATE TRIGGER trg_talepler
BEFORE UPDATE ON talepler
FOR EACH ROW EXECUTE FUNCTION guncelle_timestamp();

CREATE INDEX IF NOT EXISTS idx_talepler_durum ON talepler(durum);

-- ============================================================
-- RAPORLAR
-- ============================================================
CREATE TABLE IF NOT EXISTS raporlar (
    id        VARCHAR(20)  PRIMARY KEY,
    talep_id  VARCHAR(20)  REFERENCES talepler(id) ON DELETE CASCADE,
    ad        VARCHAR(255),
    hizmet    VARCHAR(100),
    icerik    TEXT,
    tip       VARCHAR(20)  DEFAULT 'text',
    tarih     DATE         DEFAULT CURRENT_DATE
);

-- ============================================================
-- GÖREVLER (Ekip Atamaları)
-- ============================================================
CREATE TABLE IF NOT EXISTS gorevler (
    id              VARCHAR(20) PRIMARY KEY,
    talep_id        VARCHAR(20) REFERENCES talepler(id) ON DELETE CASCADE,
    atanan_id       VARCHAR(20) REFERENCES kullanicilar(id) ON DELETE SET NULL,
    atanan_ad       VARCHAR(100),
    hizmet          VARCHAR(100),
    musteri         VARCHAR(255),
    durum           VARCHAR(30) DEFAULT 'bekleyen',
    notlar          TEXT,
    bulgular        TEXT,
    ilerleme        INT         DEFAULT 0,
    baslangic_tarih DATE        DEFAULT CURRENT_DATE,
    bitis_tarih     DATE
);

CREATE INDEX IF NOT EXISTS idx_gorevler_atanan ON gorevler(atanan_id);
CREATE INDEX IF NOT EXISTS idx_gorevler_durum  ON gorevler(durum);

-- ============================================================
-- BİLDİRİMLER
-- ============================================================
CREATE TABLE IF NOT EXISTS bildirimler (
    id      VARCHAR(20)  PRIMARY KEY,
    tip     VARCHAR(30),  -- talep | durum | rapor | onay | sistem
    baslik  VARCHAR(255),
    mesaj   TEXT,
    meta    JSONB        DEFAULT '{}',
    tarih   TIMESTAMP    DEFAULT NOW(),
    okundu  BOOLEAN      DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_bildirimler_okundu ON bildirimler(okundu);

-- ============================================================
-- WEB PUSH ABONELERİ
-- ============================================================
CREATE TABLE IF NOT EXISTS push_aboneler (
    endpoint      TEXT PRIMARY KEY,
    p256dh        TEXT NOT NULL,
    auth          TEXT NOT NULL,
    kullanici_id  VARCHAR(20) REFERENCES kullanicilar(id) ON DELETE CASCADE,
    kayit_tarih   TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- SİBER AJAN ENTEGRASYONU — ZAFİYET BULGULARI
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id                  SERIAL PRIMARY KEY,
    project_id          VARCHAR(50),
    target_ip_domain    VARCHAR(255),
    vulnerability_title VARCHAR(255),
    severity            VARCHAR(20),
    cve_id              VARCHAR(30),
    description         TEXT,
    proof_of_concept    TEXT,
    is_false_positive   BOOLEAN DEFAULT FALSE,
    discovered_at       TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOG (SOC2)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id                 SERIAL PRIMARY KEY,
    triggered_by       VARCHAR(100),
    action_type        VARCHAR(20),
    target_table       VARCHAR(50),
    target_id          VARCHAR(50),
    degisiklik         JSONB,
    tarih              TIMESTAMP DEFAULT NOW()
);

-- ============================================================
-- 2FA (İki Faktörlü Doğrulama) — Kullanıcı tablosuna ekle
-- ============================================================
ALTER TABLE kullanicilar
    ADD COLUMN IF NOT EXISTS tfa_aktif  BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS tfa_secret VARCHAR(64);

-- Cron job için backup tablosu
CREATE TABLE IF NOT EXISTS yedek_gecmisi (
    id          SERIAL PRIMARY KEY,
    tarih       TIMESTAMP DEFAULT NOW(),
    pg_basari   BOOLEAN,
    chroma_basari BOOLEAN,
    detay       TEXT
);
