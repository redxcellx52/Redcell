/**
 * rc-api.js — REDCELL AR-GE
 * localStorage yerine gerçek FastAPI backend'e konuşur.
 * Web Push bildirim aboneliğini yönetir.
 * Tüm HTML sayfaları bu dosyayı kullanır.
 */

const RC = {

  firma: {
    ad:       'REDCELL AR-GE',
    slogan:   'Ofansif Güvenlik & Araştırma',
    adres:    'İstanbul, Türkiye',
    telefon:  '+90 212 000 00 00',
    eposta:   'info@redcell.com.tr',
    web:      'www.redcell.com.tr',
    gizlilik: 'Bu rapor yalnızca alıcıya özeldir. İzinsiz kopyalanamaz.',
    yasal:    'REDCELL AR-GE yalnızca yetkili sistemler üzerinde test gerçekleştirir.',
    logo:     'RC'
  },

  // ---------------------------------------------------------------
  // TOKEN YÖNETİMİ
  // ---------------------------------------------------------------
  _token: null,
  _kullanici: null,

  tokenAl()   { return this._token || sessionStorage.getItem('rc_token'); },
  kullaniciAl() {
    if (this._kullanici) return this._kullanici;
    const raw = sessionStorage.getItem('rc_kullanici');
    return raw ? JSON.parse(raw) : null;
  },
  tokenKaydet(token, kullanici) {
    this._token     = token;
    this._kullanici = kullanici;
    sessionStorage.setItem('rc_token', token);
    sessionStorage.setItem('rc_kullanici', JSON.stringify(kullanici));
  },
  tokenTemizle() {
    this._token = null; this._kullanici = null;
    sessionStorage.removeItem('rc_token');
    sessionStorage.removeItem('rc_kullanici');
  },

  // ---------------------------------------------------------------
  // HTTP YARDIMCISI
  // ---------------------------------------------------------------
  async _fetch(yol, secenekler = {}) {
    const token = this.tokenAl();
    const res = await fetch('/api' + yol, {
      ...secenekler,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: 'Bearer ' + token } : {}),
        ...(secenekler.headers || {}),
      },
    });
    if (res.status === 401) {
      this.tokenTemizle();
      window.location.href = res.url.includes('admin') ? '/admin' : '/portal';
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Sunucu hatası' }));
      throw new Error(err.detail || 'İstek başarısız');
    }
    return res.json();
  },

  // ---------------------------------------------------------------
  // AUTH
  // ---------------------------------------------------------------
  async girisYap(kullanici, sifre, rol = 'admin') {
    try {
      const data = await this._fetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ kullanici, sifre, rol }),
      });
      this.tokenKaydet(data.token, { ad: data.ad, rol: data.rol });
      return { ok: true, uye: data };
    } catch (e) {
      return { ok: false, hata: e.message };
    }
  },

  cikisYap() { this.tokenTemizle(); },

  // ---------------------------------------------------------------
  // TALEPLER
  // ---------------------------------------------------------------
  async talepler()           { return this._fetch('/talepler'); },
  async talepEkle(veri)      { return this._fetch('/talepler', { method:'POST', body:JSON.stringify(veri) }); },
  async talepDurumGuncelle(id, durum) {
    return this._fetch(`/talepler/${id}/durum`, { method:'PATCH', body:JSON.stringify({ durum }) });
  },
  async talepSil(id)         { return this._fetch(`/talepler/${id}`, { method:'DELETE' }); },

  // ---------------------------------------------------------------
  // RAPORLAR
  // ---------------------------------------------------------------
  async raporlar()           { return this._fetch('/raporlar'); },
  async raporKaydet(veri)    { return this._fetch('/raporlar', { method:'POST', body:JSON.stringify(veri) }); },
  async raporSil(id)         { return this._fetch(`/raporlar/${id}`, { method:'DELETE' }); },

  // ---------------------------------------------------------------
  // EKİP
  // ---------------------------------------------------------------
  async ekip()               { return this._fetch('/ekip'); },
  async uyeEkle(veri)        { return this._fetch('/ekip', { method:'POST', body:JSON.stringify(veri) }); },
  async uyeSil(id)           { return this._fetch(`/ekip/${id}`, { method:'DELETE' }); },

  // ---------------------------------------------------------------
  // GÖREVLER
  // ---------------------------------------------------------------
  async gorevler()           { return this._fetch('/gorevler'); },
  async gorevGuncelle(id, veri) {
    return this._fetch(`/gorevler/${id}`, { method:'PATCH', body:JSON.stringify(veri) });
  },

  // ---------------------------------------------------------------
  // BİLDİRİMLER
  // ---------------------------------------------------------------
  async bildirimler()        { return this._fetch('/bildirimler'); },
  async bildirimOku(id)      { return this._fetch(`/bildirimler/oku/${id}`, { method:'POST' }); },
  async tumunuOku()          { return this._fetch('/bildirimler/tumunu-oku', { method:'POST' }); },
  async okunmamisSayi() {
    try {
      const list = await this.bildirimler();
      return list.filter(b => !b.okundu).length;
    } catch { return 0; }
  },

  // ---------------------------------------------------------------
  // ADMİN ONAY (Ajan Sistemi Entegrasyonu)
  // ---------------------------------------------------------------
  async onayKarar(projeId, karar) {
    return this._fetch('/admin-onay/karar', {
      method: 'POST',
      body: JSON.stringify({ proje_id: projeId, karar }),
    });
  },

  // ---------------------------------------------------------------
  // WEB PUSH BİLDİRİMLERİ
  // ---------------------------------------------------------------
  async pushAbonelikBaslat() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      console.warn('Web Push bu tarayıcıda desteklenmiyor.');
      return false;
    }
    try {
      // Service Worker kayıt
      const reg = await navigator.serviceWorker.register('/static/sw.js');

      // İzin iste
      const izin = await Notification.requestPermission();
      if (izin !== 'granted') {
        console.warn('Bildirim izni reddedildi.');
        return false;
      }

      // VAPID public key al
      const { publicKey } = await this._fetch('/push/vapid-key');

      // Push aboneliği oluştur
      const abone = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: this._urlBase64ToUint8Array(publicKey),
      });

      // Backend'e kaydet
      const aboneJson = abone.toJSON();
      await this._fetch('/push/abone', {
        method: 'POST',
        body: JSON.stringify(aboneJson),
      });

      console.log('✅ Web Push aboneliği aktif.');
      return true;
    } catch (e) {
      console.error('Push abonelik hatası:', e);
      return false;
    }
  },

  _urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw     = atob(base64);
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
  },

  // ---------------------------------------------------------------
  // OTOMATİK ATAMA (Artık backend'e bırakıldı, uyumluluk için kaldı)
  // ---------------------------------------------------------------
  async otomatikAta(talepId) {
    return this._fetch(`/talepler/${talepId}/otomatik-ata`, { method:'POST' });
  },

  // ---------------------------------------------------------------
  // DEMO VERİ YÜKLEYİCİ (İlk açılışta backend yoksa graceful fallback)
  // ---------------------------------------------------------------
  async demoyukle() {
    console.log('Demo veri backend\'den geliyor.');
  },

  // ---------------------------------------------------------------
  // BİLDİRİM PANELI RENDER YARDIMCISI (Admin panel için)
  // ---------------------------------------------------------------
  async bildirimPaneliGuncelle(containerSelector) {
    const container = document.querySelector(containerSelector);
    if (!container) return;
    try {
      const liste = await this.bildirimler();
      const sayi  = liste.filter(b => !b.okundu).length;

      // Badge güncelle
      document.querySelectorAll('.notif-badge').forEach(el => {
        el.textContent = sayi;
        el.style.display = sayi > 0 ? 'inline' : 'none';
      });

      container.innerHTML = liste.slice(0, 20).map(b => `
        <div class="notif-item ${b.okundu ? 'read' : 'unread'}" data-id="${b.id}" onclick="RC.bildirimOku('${b.id}').then(()=>this.classList.add('read'))">
          <div class="notif-icon tip-${b.tip}"><i class="ti ti-${this._bildirimIkon(b.tip)}"></i></div>
          <div class="notif-body">
            <div class="notif-baslik">${b.baslik}</div>
            <div class="notif-mesaj">${b.mesaj}</div>
            <div class="notif-tarih">${new Date(b.tarih).toLocaleString('tr-TR')}</div>
            ${b.meta?.proje_id && b.tip==='onay' ? `
              <div class="notif-actions">
                <button class="btn-onay" onclick="event.stopPropagation();RC.onayKarar('${b.meta.proje_id}','approved').then(()=>alert('✅ Onaylandı'))">✅ Onayla</button>
                <button class="btn-red" onclick="event.stopPropagation();RC.onayKarar('${b.meta.proje_id}','rejected').then(()=>alert('❌ Reddedildi'))">❌ Reddet</button>
              </div>` : ''}
          </div>
        </div>
      `).join('') || '<div class="notif-bos">Bildirim yok</div>';
    } catch (e) {
      container.innerHTML = '<div class="notif-bos">Yüklenemedi</div>';
    }
  },

  _bildirimIkon(tip) {
    return { talep:'file-plus', durum:'refresh', rapor:'file-check',
             onay:'shield-check', sistem:'settings' }[tip] || 'bell';
  },

};
