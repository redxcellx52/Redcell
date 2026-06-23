# REDCELL AR-GE — Tam Platform

## Proje Yapısı

```
redcell_full/
├── docker-compose.yml          ← Her şey tek komutla ayağa kalkar
├── .env.example                ← Ortam değişkenleri şablonu
│
├── frontend/                   ← Web arayüzü (mevcut tasarım korundu)
│   ├── index.html              → redcell.com/
│   ├── admin.html              → redcell.com/admin
│   ├── portal.html             → redcell.com/portal
│   ├── ekip.html               → redcell.com/ekip
│   ├── rapor-motoru.html       → redcell.com/rapor-motoru
│   ├── rc-api.js               ← localStorage yerine gerçek API (YENİ)
│   └── sw.js                   ← Service Worker — Web Push (YENİ)
│
├── backend/                    ← FastAPI Web + API
│   └── main.py                 ← Sayfa servisi + REST API + Web Push
│
├── agents/                     ← LangGraph Ajan Sistemi
│   ├── main.py                 ← 17 ajan iş akışı
│   ├── db/
│   │   ├── db_writer.py        ← PostgreSQL yazma katmanı
│   │   └── vector_storage.py   ← ChromaDB vektör depo
│   ├── config/
│   │   └── prompts.py          ← Tüm ajan sistem promptları
│   └── utils/
│       └── notification.py     ← Admin onay (Telegram YOK → kendi panelimiz)
│
└── docker/
    ├── schema.sql              ← PostgreSQL şeması
    ├── Dockerfile.web          ← Web servisi
    ├── Dockerfile.agents       ← Ajan servisi
    ├── requirements.web.txt
    └── requirements.agents.txt
```

---

## Hızlı Başlangıç

```bash
# 1. Ortam değişkenleri
cp .env.example .env
# .env'yi düzenle (en az DB_PASSWORD ve SECRET_KEY)

# 2. Web Push VAPID anahtarları üret (bir kere)
npx web-push generate-vapid-keys
# Çıkan PRIVATE ve PUBLIC key'leri .env'ye yaz

# 3. Çalıştır
docker compose up --build

# 4. Tarayıcıdan aç
# Ana site:    http://localhost
# Admin:       http://localhost/admin    → admin / redcell2025
# Müşteri:     http://localhost/portal
# Ekip:        http://localhost/ekip     → mehmet / test123
```

---

## URL Yapısı (.html YOK)

| Eski | Yeni | Açıklama |
|---|---|---|
| admin.html | /admin | Admin paneli |
| portal.html | /portal | Müşteri portalı |
| ekip-panel.html | /ekip | Ekip paneli |
| rapor-motoru.html | /rapor-motoru | Rapor motoru |

---

## Web Push Bildirimi Nasıl Çalışır

1. Admin `/admin` sayfasını açar
2. Tarayıcı "Bildirim iznine izin ver?" sorar → İzin ver
3. Abonelik backend'e kaydedilir
4. Yeni talep geldiğinde veya ajan onay istediğinde telefonuna bildirim düşer
5. Bildirime tıklandığında `/admin` sayfası açılır
6. Admin panelde **ONAYLA** veya **REDDET** butonuna basar
7. Ajan sistemi kararı polling ile alır ve devam eder

**Telegram gerekmez. Dışarıya bağımlılık yok.**

---

## Admin Onay Akışı (Ajan ↔ Panel)

```
Ajan Sistemi
    │
    ├── POST /api/admin-onay/talep   ← "Onay lazım"
    │       │
    │       └── Web Push → Admin'in telefonu 📱
    │
    └── GET /api/ajan/onay/{proje_id}  ← 10 saniyede bir polling
            │
            └── Admin panelde ONAYLA butonuna basınca
                → {"approved": true} döner
                → Ajan devam eder
```

---

## Servisler

| Servis | Port | Açıklama |
|---|---|---|
| Web + API | 80 | FastAPI — site ve API |
| PostgreSQL | 5432 | Kalıcı veri |
| ChromaDB | 8001 | Vektör semantik hafıza |
| Redis | 6379 | Mesaj kuyruğu |
| Agents | — | LangGraph ajan sistemi |

---

## Güvenlik

- URL'de `.html` yok → saldırı yüzeyi azaldı
- JWT token tabanlı kimlik doğrulama
- Admin onayı olmadan siber test başlamıyor
- Phishing sadece whitelist domainlere
- Tüm değişiklikler `audit_logs` tablosuna yazılıyor (SOC2)
- Exploit scriptleri ayrı izole volume'da
