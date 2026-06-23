#!/bin/bash
# ============================================================
# REDCELL AR-GE — İlk Kurulum Script'i
# Sunucuda bir kez çalıştır: bash ilk_kurulum.sh
# ============================================================

set -e
echo "🔴 REDCELL AR-GE Kurulum Başladı"

# Docker kur
apt-get update -q
apt-get install -y docker.io docker-compose-plugin nodejs npm certbot nginx

# Dizinleri oluştur
mkdir -p /opt/redcell/{backups,logs,contracts}

# VAPID key üret
echo ""
echo "📡 VAPID Key üretiliyor..."
npx web-push generate-vapid-keys > /tmp/vapid_keys.txt
cat /tmp/vapid_keys.txt
echo ""
echo "⚠️  Bu keyleri .env dosyasına yaz!"

# Cron job ekle (her gece 02:00'da yedek)
(crontab -l 2>/dev/null; echo "0 2 * * * cd /opt/redcell && python3 scripts/backup.py >> logs/backup.log 2>&1") | crontab -

# SSL sertifikası (domain varsa)
read -p "Domain adın var mı? (redxcell.com gibi, yoksa Enter'a bas): " DOMAIN
if [ ! -z "$DOMAIN" ]; then
    certbot certonly --standalone -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN
    cp docker/nginx.conf /etc/nginx/sites-available/redcell
    # nginx.conf'ta domain'i güncelle
    sed -i "s/redxcell.com/$DOMAIN/g" /etc/nginx/sites-available/redcell
    ln -sf /etc/nginx/sites-available/redcell /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
    echo "✅ SSL ve Nginx kuruldu"
fi

echo ""
echo "✅ Kurulum tamamlandı!"
echo ""
echo "Sonraki adım:"
echo "  1. .env dosyasını doldur"
echo "  2. docker compose up -d --build"
echo "  3. https://$DOMAIN/admin adresine git"
