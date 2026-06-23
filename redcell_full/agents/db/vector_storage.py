"""
db/vector_storage.py
--------------------
Vektör veritabanı yöneticisi (ChromaDB).
Ar-Ge Ajanı ve Siber İstihbarat Ajanı bu modülü kullanarak
semantik bilgi ekler ve sorgular.
Exploit scriptleri ASLA burada saklanmaz; yalnızca izole depo yolu metadata'ya yazılır.
"""

import os
import logging
from typing import Optional

import chromadb
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)


class VectorStorageManager:
    """
    Singleton pattern ile çalışır; uygulama boyunca tek bir ChromaDB bağlantısı kullanılır.
    """

    _instance: Optional["VectorStorageManager"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        db_path = os.getenv("CHROMA_DB_PATH", "./chroma_db")
        api_key = os.getenv("OPENAI_API_KEY")

        self.chroma_client = chromadb.PersistentClient(path=db_path)
        self.embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
            api_key=api_key,
            model_name="text-embedding-3-small",
        )

        self._init_collections()
        self._initialized = True
        logger.info("VectorStorageManager başlatıldı. ChromaDB yolu: %s", db_path)

    # -----------------------------------------------------------------------
    # Koleksiyon Başlatma
    # -----------------------------------------------------------------------

    def _init_collections(self):
        """İki ana koleksiyonu güvenli şekilde oluşturur (varsa açar)."""
        self.knowledge_base = self.chroma_client.get_or_create_collection(
            name="global_knowledge_base",
            embedding_function=self.embedding_fn,
            metadata={"description": "CVE ve zafiyet analizleri - Ar-Ge Ajanı yönetir"},
        )
        self.threat_intel = self.chroma_client.get_or_create_collection(
            name="threat_intelligence",
            embedding_function=self.embedding_fn,
            metadata={"description": "Dark web sızıntı verileri - Siber İstihbarat Ajanı yönetir"},
        )
        logger.info(
            "Koleksiyonlar hazır. KB: %d kayıt | Threat: %d kayıt",
            self.knowledge_base.count(),
            self.threat_intel.count(),
        )

    # -----------------------------------------------------------------------
    # KNOWLEDGE BASE (Ar-Ge Ajanı)
    # -----------------------------------------------------------------------

    def add_knowledge(
        self,
        cve_id: str,
        vuln_type: str,
        analysis_text: str,
        secure_script_path: str,
        affected_systems: str = "",
    ) -> bool:
        """
        Zafiyet analizini Knowledge Base'e ekler.
        GÜVENLİK: Exploit scripti gövdesi embedding'e yazılmaz.
        Sadece izole depo yolu (S3/güvenli disk) metadata'ya kaydedilir.
        """
        try:
            # Aynı CVE zaten varsa güncelle
            existing = self.knowledge_base.get(ids=[cve_id])
            if existing["ids"]:
                self.knowledge_base.update(
                    ids=[cve_id],
                    documents=[analysis_text],
                    metadatas=[{
                        "cve_id":               cve_id,
                        "vulnerability_type":   vuln_type,
                        "affected_systems":     affected_systems,
                        "secure_script_path":   secure_script_path,  # İzole depodaki yol
                    }],
                )
                logger.info("[KB] Güncellendi: %s", cve_id)
            else:
                self.knowledge_base.add(
                    ids=[cve_id],
                    documents=[analysis_text],
                    metadatas=[{
                        "cve_id":               cve_id,
                        "vulnerability_type":   vuln_type,
                        "affected_systems":     affected_systems,
                        "secure_script_path":   secure_script_path,
                    }],
                )
                logger.info("[KB] Eklendi: %s", cve_id)
            return True
        except Exception as exc:
            logger.error("[KB] add_knowledge hatası: %s", exc)
            return False

    def query_knowledge(self, query_text: str, n_results: int = 3) -> list[dict]:
        """
        Siber Test Ajanı ve Olay Müdahale Ajanı için semantik zafiyet araması.
        Dönen liste: [{"cve_id": ..., "analysis": ..., "script_path": ...}]
        """
        try:
            result = self.knowledge_base.query(
                query_texts=[query_text],
                n_results=min(n_results, self.knowledge_base.count() or 1),
            )
            hits = []
            for i, doc in enumerate(result["documents"][0]):
                meta = result["metadatas"][0][i]
                hits.append({
                    "cve_id":       meta.get("cve_id"),
                    "vuln_type":    meta.get("vulnerability_type"),
                    "analysis":     doc,
                    "script_path":  meta.get("secure_script_path"),
                    "distance":     result["distances"][0][i],
                })
            return hits
        except Exception as exc:
            logger.error("[KB] query_knowledge hatası: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # THREAT INTELLIGENCE (Siber İstihbarat Ajanı)
    # -----------------------------------------------------------------------

    def add_threat_intel(
        self,
        company_domain: str,
        summary_text: str,
        leak_source: str,
        leak_year: int,
        risk_score: int = 0,
    ) -> bool:
        """
        Şirkete ait dark web sızıntı verisini Threat Intelligence koleksiyonuna ekler.
        GÜVENLİK: Ham parola veya kimlik bilgisi embedding içeriğine yazılmaz;
        sadece özet metin ve metadata saklanır.
        """
        record_id = f"ti_{company_domain}_{leak_year}"
        try:
            existing = self.threat_intel.get(ids=[record_id])
            if existing["ids"]:
                self.threat_intel.update(
                    ids=[record_id],
                    documents=[summary_text],
                    metadatas=[{
                        "company_domain": company_domain,
                        "leak_source":    leak_source,
                        "leak_year":      str(leak_year),
                        "risk_score":     str(risk_score),
                    }],
                )
            else:
                self.threat_intel.add(
                    ids=[record_id],
                    documents=[summary_text],
                    metadatas=[{
                        "company_domain": company_domain,
                        "leak_source":    leak_source,
                        "leak_year":      str(leak_year),
                        "risk_score":     str(risk_score),
                    }],
                )
            logger.info("[TI] %s için tehdit verisi eklendi/güncellendi.", company_domain)
            return True
        except Exception as exc:
            logger.error("[TI] add_threat_intel hatası: %s", exc)
            return False

    def query_threat_intel(self, company_domain: str, n_results: int = 3) -> list[dict]:
        """
        Belirli bir şirkete ait geçmiş sızıntı verilerini semantik olarak sorgular.
        """
        try:
            result = self.threat_intel.query(
                query_texts=[company_domain],
                n_results=min(n_results, self.threat_intel.count() or 1),
            )
            hits = []
            for i, doc in enumerate(result["documents"][0]):
                meta = result["metadatas"][0][i]
                hits.append({
                    "domain":       meta.get("company_domain"),
                    "source":       meta.get("leak_source"),
                    "year":         meta.get("leak_year"),
                    "risk_score":   int(meta.get("risk_score", 0)),
                    "summary":      doc,
                })
            return hits
        except Exception as exc:
            logger.error("[TI] query_threat_intel hatası: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # HATA ÇÖZÜM ÖĞRENME (Ar-Ge Ajanı tarafından beslenir)
    # -----------------------------------------------------------------------

    def add_error_resolution(self, error_key: str, resolution_text: str) -> bool:
        """
        Bir ajan hatası çözüldüğünde çözümü KB'ye ekler.
        Olay Müdahale Ajanı benzer hatalarla karşılaşınca buradan öğrenir.
        """
        return self.add_knowledge(
            cve_id=f"ERR_{error_key}",
            vuln_type="ERROR_RESOLUTION",
            analysis_text=resolution_text,
            secure_script_path="",
            affected_systems="internal_agent_system",
        )

    def query_error_resolution(self, error_description: str) -> list[dict]:
        """Benzer hatalara ait çözümleri semantik olarak sorgular."""
        results = self.query_knowledge(error_description, n_results=2)
        return [r for r in results if r.get("vuln_type") == "ERROR_RESOLUTION"]

    # -----------------------------------------------------------------------
    # İSTATİSTİK
    # -----------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "knowledge_base_count":  self.knowledge_base.count(),
            "threat_intel_count":    self.threat_intel.count(),
        }
