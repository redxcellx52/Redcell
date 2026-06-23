const RC = {

  firma: {
    ad: 'REDCELL AR-GE',
    slogan: 'Ofansif Guvenlik & Arastirma',
    adres: 'Istanbul, Turkiye',
    telefon: '+90 212 000 00 00',
    eposta: 'info@redcell.com.tr',
    web: 'www.redcell.com.tr',
    gizlilik: 'Bu rapor yalnizca aliciya ozeldir. Izinsiz kopyalanamaz veya dagitulamaz.',
    yasal: 'REDCELL AR-GE yalnizca yetkili sistemler uzerinde test gerceklestirir.',
    logo: 'RC'
  },

  uzmanlikHarita: {
    'Web Uygulama Guvenligi': ['web','owasp','burp','appsec'],
    'Ag Sizma Testi': ['network','nmap','pentest','firewall'],
    'Mobil Uygulama Analizi': ['mobile','android','ios','apk'],
    'Red Team Operasyonu': ['redteam','apt','c2','lateral'],
    'IoT Donanim Guvenligi': ['iot','hardware','firmware','embedded'],
    'Sosyal Muhendislik': ['social','phishing','osint'],
  },

  get talepler()    { return JSON.parse(localStorage.getItem('rc_talepler')    ||'[]'); },
  get raporlar()    { return JSON.parse(localStorage.getItem('rc_raporlar')    ||'[]'); },
  get ekip()        { return JSON.parse(localStorage.getItem('rc_ekip')        ||'[]'); },
  get bildirimler() { return JSON.parse(localStorage.getItem('rc_bildirimler') ||'[]'); },
  get gorevler()    { return JSON.parse(localStorage.getItem('rc_gorevler')    ||'[]'); },

  save(key, val) { localStorage.setItem('rc_'+key, JSON.stringify(val)); },

  bildirimEkle(tip, baslik, mesaj, meta) {
    const b = this.bildirimler;
    const yeni = { id:'B'+Date.now(), tip, baslik, mesaj, meta:meta||{}, tarih:new Date().toISOString(), okundu:false };
    b.unshift(yeni);
    if(b.length>100) b.splice(100);
    this.save('bildirimler', b);
    localStorage.setItem('rc_son_bildirim', JSON.stringify({...yeni, _ts:Date.now()}));
    return yeni;
  },

  bildirimOku(id) {
    const b = this.bildirimler;
    const i = b.findIndex(x=>x.id===id);
    if(i>=0){b[i].okundu=true; this.save('bildirimler',b);}
  },

  tumunuOku() { this.save('bildirimler', this.bildirimler.map(x=>({...x,okundu:true}))); },
  okunmamisSayi() { return this.bildirimler.filter(x=>!x.okundu).length; },

  talepEkle(veri) {
    const t = this.talepler;
    const id = 'T'+String(t.length+1).padStart(3,'0');
    const talep = { id, ...veri, tarih:new Date().toISOString().slice(0,10), durum:'bekleyen' };
    t.push(talep);
    this.save('talepler', t);
    const atanan = this.otomatikAta(talep);
    this.bildirimEkle('talep','Yeni Talep', talep.ad+' - '+talep.hizmet, { talepId:id });
    return talep;
  },

  talepDurumGuncelle(id, yeniDurum) {
    const t = this.talepler;
    const i = t.findIndex(x=>x.id===id);
    if(i<0) return null;
    t[i].durum = yeniDurum;
    this.save('talepler', t);
    this.bildirimEkle('durum','Durum Guncellendi', t[i].ad+' - '+yeniDurum, { talepId:id });
    return t[i];
  },

  talepSil(id) {
    this.save('talepler', this.talepler.filter(x=>x.id!==id));
    this.save('gorevler', this.gorevler.filter(x=>x.talepId!==id));
  },

  raporKaydet(talepId, icerik, tip) {
    const r = this.raporlar;
    const talep = this.talepler.find(t=>t.id===talepId)||{};
    const id = 'R'+String(r.length+1).padStart(3,'0');
    const rapor = { id, talepId, ad:talep.ad||'', hizmet:talep.hizmet||'', tarih:new Date().toISOString().slice(0,10), icerik, tip:tip||'text' };
    r.push(rapor);
    this.save('raporlar', r);
    this.talepDurumGuncelle(talepId,'tamamlandi');
    const g = this.gorevler;
    const gi = g.findIndex(x=>x.talepId===talepId);
    if(gi>=0){ g[gi].durum='tamamlandi'; g[gi].bitisTarih=new Date().toISOString().slice(0,10); this.save('gorevler',g); }
    this.bildirimEkle('rapor','Rapor Hazirlandi', rapor.ad+' - '+rapor.hizmet, { raporId:id, talepId });
    return rapor;
  },

  raporSil(id) { this.save('raporlar', this.raporlar.filter(x=>x.id!==id)); },

  otomatikAta(talep) {
    const ekip = this.ekip.filter(u => u.durum === 'available');
    if(!ekip.length) return null;
    const hizmetAnahtarlar = this.uzmanlikHarita[talep.hizmet] || [];
    const skorlar = ekip.map(u => {
      const certStr = ((u.cert||[]).join(' ') + ' ' + (u.uzmanlik||[]).join(' ')).toLowerCase();
      const uzmanlikSkoru = hizmetAnahtarlar.reduce((s,k) => s + (certStr.includes(k)?2:0), 0);
      const yukSkoru = -(this.gorevler.filter(g=>g.atananId===u.id&&g.durum==='devam').length);
      return { uye:u, skor: uzmanlikSkoru + yukSkoru };
    });
    skorlar.sort((a,b) => b.skor - a.skor);
    const secilen = skorlar[0]?.uye;
    if(!secilen) return null;
    this.gorevEkle({ talepId:talep.id, atananId:secilen.id, atananAd:secilen.ad, hizmet:talep.hizmet, musteri:talep.ad, durum:'bekleyen', notlar:'', bulgular:'', ilerleme:0 });
    const e = this.ekip;
    const ei = e.findIndex(x=>x.id===secilen.id);
    if(ei>=0){ e[ei].durum='busy'; this.save('ekip',e); }
    this.bildirimEkle('sistem','Is Atandi', talep.hizmet+' -> '+secilen.ad, { talepId:talep.id, atananId:secilen.id });
    return secilen;
  },

  manuelAta(talepId, uyeId) {
    const talep = this.talepler.find(t=>t.id===talepId);
    const uye = this.ekip.find(u=>u.id===uyeId);
    if(!talep||!uye) return false;
    const g = this.gorevler.filter(x=>x.talepId!==talepId);
    this.save('gorevler', g);
    this.gorevEkle({ talepId, atananId:uyeId, atananAd:uye.ad, hizmet:talep.hizmet, musteri:talep.ad, durum:'devam', notlar:'', bulgular:'', ilerleme:0 });
    const e = this.ekip;
    const ei = e.findIndex(x=>x.id===uyeId);
    if(ei>=0){ e[ei].durum='busy'; this.save('ekip',e); }
    this.bildirimEkle('sistem','Manuel Atama', talep.hizmet+' -> '+uye.ad, {talepId, atananId:uyeId});
    return true;
  },

  gorevEkle(veri) {
    const g = this.gorevler;
    const id = 'G'+String(g.length+1).padStart(3,'0');
    g.push({ id, ...veri, baslangicTarih:new Date().toISOString().slice(0,10) });
    this.save('gorevler', g);
    return id;
  },

  gorevGuncelle(id, degisiklikler) {
    const g = this.gorevler;
    const i = g.findIndex(x=>x.id===id);
    if(i<0) return;
    Object.assign(g[i], degisiklikler);
    this.save('gorevler', g);
    if(degisiklikler.durum==='tamamlandi') {
      const e = this.ekip;
      const ei = e.findIndex(u=>u.id===g[i].atananId);
      if(ei>=0){
        const aktif = g.filter(x=>x.atananId===e[ei].id&&x.durum==='devam'&&x.id!==id).length;
        if(!aktif){ e[ei].durum='available'; this.save('ekip',e); }
      }
    }
  },

  uyeEkle(veri) {
    const e = this.ekip;
    const id = 'U'+String(e.length+1).padStart(3,'0');
    e.push({ id, ...veri, kayitTarih:new Date().toISOString().slice(0,10) });
    this.save('ekip', e);
    return id;
  },

  uyeGuncelle(id, degisiklikler) {
    const e = this.ekip;
    const i = e.findIndex(x=>x.id===id);
    if(i>=0){ Object.assign(e[i], degisiklikler); this.save('ekip',e); }
  },

  uyeSil(id) {
    this.save('ekip', this.ekip.filter(u=>u.id!==id));
    this.save('gorevler', this.gorevler.filter(g=>g.atananId!==id));
  },

  girisYap(user, pass, rol) {
    if(rol==='ekip') {
      const uye = this.ekip.find(u=>u.kullanici===user && u.sifre===pass);
      return uye ? {ok:true, uye} : {ok:false, uye:null};
    }
    const kayitliPass = localStorage.getItem('rc_pass')||'redcell2025';
    return {ok: user==='admin' && pass===kayitliPass, uye:null};
  },

  sifreDegistir(yeni) { localStorage.setItem('rc_pass', yeni); },

  demoyukle() {
    if(this.talepler.length) return;
    this.save('ekip',[
      {id:'U001',ad:'Mehmet Arslan',rol:'Lead Penetration Tester',cert:['OSCP','CEH'],uzmanlik:['web','network','pentest'],durum:'available',kullanici:'mehmet',sifre:'test123',eposta:'mehmet@redcell.com.tr',kayitTarih:'2024-01-10'},
      {id:'U002',ad:'Ayse Kaya',rol:'Web Security Specialist',cert:['eWPTX','GWAPT'],uzmanlik:['web','owasp','appsec','burp'],durum:'available',kullanici:'ayse',sifre:'test123',eposta:'ayse@redcell.com.tr',kayitTarih:'2024-02-15'},
      {id:'U003',ad:'Can Demir',rol:'Red Team Operator',cert:['CRTO','OSCP'],uzmanlik:['redteam','apt','lateral','c2'],durum:'available',kullanici:'can',sifre:'test123',eposta:'can@redcell.com.tr',kayitTarih:'2024-03-20'},
    ]);
    this.save('talepler',[
      {id:'T001',ad:'Teknoloji A.S.',email:'it@teknoloji.com',hizmet:'Web Uygulama Guvenligi',ozet:'E-ticaret platformumuzda kapsamli pentest istiyoruz.',hedef:'https://app.teknoloji.com',oncelik:'Normal',kapsam:['Web Uygulamasi','API'],tarih:'2025-06-18',durum:'devam'},
      {id:'T002',ad:'Finans Ltd.',email:'ciso@finans.com',hizmet:'Ag Sizma Testi',ozet:'Kurumsal ag altyapisinda sizma testi.',hedef:'10.0.0.0/24',oncelik:'Yuksek',kapsam:['Ic Ag','Dis Ag'],tarih:'2025-06-15',durum:'bekleyen'},
      {id:'T003',ad:'Lojistik Grup',email:'it@lojistik.com',hizmet:'Sosyal Muhendislik',ozet:'Calisán farkindalik testi.',hedef:'-',oncelik:'Normal',kapsam:['Sosyal Muhendislik'],tarih:'2025-06-10',durum:'tamamlandi'},
    ]);
    this.save('gorevler',[
      {id:'G001',talepId:'T001',atananId:'U002',atananAd:'Ayse Kaya',hizmet:'Web Uygulama Guvenligi',musteri:'Teknoloji A.S.',durum:'devam',notlar:'Login sayfasinda SQL injection suphe mevcut.',bulgular:'[YUKSEK] SQL Injection - /login\n[ORTA] XSS - /search',ilerleme:65,baslangicTarih:'2025-06-19'},
      {id:'G002',talepId:'T003',atananId:'U001',atananAd:'Mehmet Arslan',hizmet:'Sosyal Muhendislik',musteri:'Lojistik Grup',durum:'tamamlandi',notlar:'Tum testler tamamlandi.',bulgular:'23/50 calisan phishing linkine tikladı.',ilerleme:100,baslangicTarih:'2025-06-10',bitisTarih:'2025-06-14'},
    ]);
    this.bildirimEkle('talep','Yeni Talep','Teknoloji A.S. - Web Uygulama Guvenligi',{talepId:'T001'});
    this.bildirimEkle('sistem','Is Atandi','Web Uygulama Guvenligi -> Ayse Kaya',{talepId:'T001',atananId:'U002'});
    this.bildirimEkle('rapor','Rapor Hazir','Lojistik Grup - Sosyal Muhendislik',{talepId:'T003'});
  }
};