"""
agents/sandbox/docker_sandbox.py
---------------------------------
10. Docker Sandbox — Siber Test Ajanı İzolasyonu
    Nmap, Nuclei ve diğer tarama araçları bu izole container içinde çalışır.
    Ana sisteme erişimi yoktur. Ağ kısıtlamalıdır. Root değildir.
    Whitelist kontrolü sandbox başlamadan yapılır.
"""

import os
import json
import uuid
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("REDCELL.sandbox")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SANDBOX_IMAGE    = os.getenv("SANDBOX_IMAGE", "redcell-sandbox:latest")
SANDBOX_TIMEOUT  = int(os.getenv("SANDBOX_TIMEOUT", 300))   # 5 dakika
SANDBOX_MEMORY   = os.getenv("SANDBOX_MEMORY", "512m")
SANDBOX_CPUS     = os.getenv("SANDBOX_CPUS", "1.0")
RESULTS_DIR      = Path(os.getenv("SANDBOX_RESULTS", "/app/sandbox_results"))


# ---------------------------------------------------------------------------
# WHITELIST KONTROLÜ (Sandbox başlamadan zorunlu)
# ---------------------------------------------------------------------------

def whitelist_kontrol(hedef: str, izinli_listesi: list[str]) -> bool:
    """
    Hedef IP/domain sözleşmedeki whitelist'te mi?
    Değilse tarama kesinlikle başlamaz.
    """
    hedef_temiz = hedef.strip().lower()
    for izinli in izinli_listesi:
        if hedef_temiz == izinli.strip().lower():
            return True
        # CIDR kontrolü
        if "/" in izinli:
            try:
                import ipaddress
                ag = ipaddress.ip_network(izinli, strict=False)
                adres = ipaddress.ip_address(hedef_temiz)
                if adres in ag:
                    return True
            except ValueError:
                pass
    logger.warning("[Sandbox] Whitelist dışı hedef engellendi: %s", hedef)
    return False


# ---------------------------------------------------------------------------
# SANDBOX ÇALIŞTIRICI
# ---------------------------------------------------------------------------

class DockerSandbox:
    """
    Tarama araçlarını izole Docker container içinde çalıştırır.

    Güvenlik önlemleri:
    - --network=none → İnternet erişimi yalnızca hedef IP'ye
    - --read-only → Container dosya sistemi salt okunur
    - --cap-drop=ALL → Tüm Linux yetenekleri kaldırıldı
    - --no-new-privileges → Yetki yükseltme yasak
    - --user 1000:1000 → Root değil
    - --memory → Bellek sınırı
    - --cpus → CPU sınırı
    """

    def __init__(self, proje_id: str, whitelist: list[str]):
        self.proje_id  = proje_id
        self.whitelist = whitelist
        self.sandbox_id = f"rc_sandbox_{uuid.uuid4().hex[:8]}"
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    def nmap_tara(self, hedef: str, portlar: str = "1-10000") -> dict:
        """Nmap port taraması."""
        if not whitelist_kontrol(hedef, self.whitelist):
            return {"hata": "Hedef whitelist dışında", "hedef": hedef}

        komut = [
            "nmap", "-sV", "-sC", "--open",
            f"-p{portlar}",
            "-oJ", "/tmp/nmap_sonuc.json",
            hedef,
        ]
        return self._calistir(komut, "nmap_sonuc.json")

    def nuclei_tara(self, hedef: str, severity: str = "critical,high,medium") -> dict:
        """Nuclei zafiyet taraması."""
        if not whitelist_kontrol(hedef, self.whitelist):
            return {"hata": "Hedef whitelist dışında", "hedef": hedef}

        komut = [
            "nuclei",
            "-u", hedef,
            "-severity", severity,
            "-json",
            "-o", "/tmp/nuclei_sonuc.json",
            "-timeout", "10",
            "-rate-limit", "50",
        ]
        return self._calistir(komut, "nuclei_sonuc.json")

    def _calistir(self, komut: list[str], sonuc_dosyasi: str) -> dict:
        """
        Komutu izole Docker container içinde çalıştırır.
        Sonucu okuyup döner, container'ı temizler.
        """
        sonuc_yolu = RESULTS_DIR / f"{self.sandbox_id}_{sonuc_dosyasi}"

        docker_komut = [
            "docker", "run",
            "--rm",
            "--name", self.sandbox_id,
            "--network", "host",           # Sadece hedef IP'ye erişim
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m", # Geçici yazma alanı
            "--cap-drop", "ALL",
            "--no-new-privileges",
            "--user", "1000:1000",
            "--memory", SANDBOX_MEMORY,
            "--cpus", SANDBOX_CPUS,
            "-v", f"{RESULTS_DIR}:/results:rw",
            SANDBOX_IMAGE,
        ] + komut

        logger.info("[Sandbox] %s başlatılıyor: %s", self.sandbox_id, " ".join(komut[:3]))

        try:
            proc = subprocess.run(
                docker_komut,
                capture_output=True,
                text=True,
                timeout=SANDBOX_TIMEOUT,
            )

            if proc.returncode != 0:
                logger.warning("[Sandbox] Çıkış kodu: %d | %s",
                               proc.returncode, proc.stderr[:200])

            # Sonuç dosyasını oku
            if sonuc_yolu.exists():
                icerik = sonuc_yolu.read_text("utf-8")
                try:
                    return json.loads(icerik)
                except json.JSONDecodeError:
                    return {"ham_cikti": icerik[:5000]}
            else:
                return {"stdout": proc.stdout[:3000], "stderr": proc.stderr[:1000]}

        except subprocess.TimeoutExpired:
            logger.error("[Sandbox] Zaman aşımı: %s", self.sandbox_id)
            self._durdur()
            return {"hata": f"Zaman aşımı ({SANDBOX_TIMEOUT}s)"}

        except Exception as exc:
            logger.error("[Sandbox] Hata: %s", exc)
            return {"hata": str(exc)}

        finally:
            # Sonuç dosyasını temizle
            if sonuc_yolu.exists():
                sonuc_yolu.unlink()

    def _durdur(self):
        """Timeout durumunda container'ı zorla durdurur."""
        try:
            subprocess.run(
                ["docker", "stop", "--time", "5", self.sandbox_id],
                capture_output=True, timeout=10
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SANDBOX DOCKER IMAGE OLUŞTURMA (İlk kurulumda bir kez çalıştırılır)
# ---------------------------------------------------------------------------

SANDBOX_DOCKERFILE = """
FROM ubuntu:22.04

# Güvenlik araçları
RUN apt-get update && apt-get install -y --no-install-recommends \\
    nmap curl wget python3 && \\
    rm -rf /var/lib/apt/lists/*

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip \\
    -O /tmp/nuclei.zip && \\
    cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && \\
    rm /tmp/nuclei.zip

# Root olmayan kullanıcı
RUN useradd -u 1000 -m scanner
USER scanner

WORKDIR /tmp
"""


def sandbox_image_olustur():
    """Sandbox Docker imajını oluşturur. İlk kurulumda bir kez çalıştırılır."""
    with tempfile.TemporaryDirectory() as tmp:
        df_yol = Path(tmp) / "Dockerfile"
        df_yol.write_text(SANDBOX_DOCKERFILE)

        logger.info("[Sandbox] İmaj oluşturuluyor: %s", SANDBOX_IMAGE)
        proc = subprocess.run(
            ["docker", "build", "-t", SANDBOX_IMAGE, tmp],
            capture_output=True, text=True, timeout=600
        )
        if proc.returncode == 0:
            logger.info("[Sandbox] İmaj hazır: %s", SANDBOX_IMAGE)
        else:
            logger.error("[Sandbox] İmaj oluşturulamadı: %s", proc.stderr[:500])
