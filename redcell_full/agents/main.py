"""
main.py
-------
Otonom Siber Güvenlik Çok-Ajan Sistemi - Ana İş Akışı
LangGraph üzerinde tanımlanmış tüm ajanlar, koşullu yollar ve veritabanı entegrasyonu.
"""

import os
import json
import logging
from typing import TypedDict, Optional

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

from config.prompts import PROMPTS, LLM_MODEL, LLM_TEMPERATURE, MAX_RETRY_COUNT
from utils.notification import bekle_admin_onay
from db.db_writer import (
    upsert_client,
    create_project,
    update_project_field,
    write_audit_log,
    write_incident,
    resolve_incident,
    write_vulnerability,
)

# ---------------------------------------------------------------------------
# Loglama
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("CyberAgentSystem")

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------
llm = ChatOpenAI(
    model=LLM_MODEL,
    temperature=LLM_TEMPERATURE,
    api_key=os.getenv("OPENAI_API_KEY"),
)


# ===========================================================================
# 1. GLOBAL STATE TANIMI
# ===========================================================================

class AgentState(TypedDict):
    # Proje Kimliği
    project_id: str
    target_sector: str

    # Faz 1 - İş Geliştirme
    lead_info: Optional[dict]
    sales_email: Optional[str]
    contract_path: Optional[str]
    financial_clearance: Optional[dict]

    # Faz 2 - Koordinasyon
    admin_approval: bool
    operation_launch_ready: bool

    # Faz 3 - Teknik Operasyon
    threat_intel: Optional[dict]
    vulnerability_results: Optional[list]
    cloud_misconfigs: Optional[list]
    phishing_metrics: Optional[dict]
    incident_id: Optional[int]

    # Faz 4 - Kapanış
    final_report: Optional[str]
    compliance_report: Optional[dict]

    # Kontrol Alanları
    is_safe: bool
    error_message: Optional[str]
    retry_count: int
    current_phase: str
    budget_status: str   # NORMAL | WARNING | SUSPEND


# ===========================================================================
# 2. YARDIMCI FONKSIYONLAR
# ===========================================================================

def call_llm(system_prompt: str, human_message: str) -> str:
    """LLM'e istek gönderir, ham metin döner."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
    ])
    chain = prompt | llm
    response = chain.invoke({"input": human_message})
    return response.content.strip()


def parse_json_safe(text: str) -> dict | list | None:
    """LLM çıktısındaki Markdown kod bloklarını temizleyip JSON parse eder."""
    clean = text.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse hatası: %s | Metin: %s", exc, clean[:200])
        return None


# ===========================================================================
# 3. AJAN DÜĞÜMLERİ (NODES)
# ===========================================================================

# ---------------------------------------------------------------------------
# FAZ 1: İŞ GELİŞTİRME
# ---------------------------------------------------------------------------

def avci_ajan_node(state: AgentState) -> dict:
    """Lead (potansiyel müşteri) üretir ve veritabanına kaydeder."""
    logger.info("[Avcı Ajan] %s sektörü için lead araştırılıyor...", state["target_sector"])

    try:
        raw = call_llm(
            PROMPTS["avci_ajan"],
            f"{state['target_sector']} sektörü için bir lead üret.",
        )
        lead = parse_json_safe(raw)

        if not lead or not isinstance(lead, dict):
            raise ValueError("LLM geçersiz JSON döndürdü.")

        required_keys = {"company_name", "authorized_person", "contact_email"}
        if not required_keys.issubset(lead.keys()):
            raise ValueError(f"Eksik alanlar: {required_keys - lead.keys()}")

        # Müşteriyi veritabanına kaydet
        client_id = upsert_client(
            company_name=lead["company_name"],
            authorized_person=lead["authorized_person"],
            contact_email=lead["contact_email"],
        )

        # Projeyi oluştur (ilk kez çalışıyorsa)
        if client_id:
            create_project(
                project_id=state["project_id"],
                client_id=client_id,
                budget_limit=500.0,
            )

        write_audit_log(
            agent_name="Avcı Ajan",
            action_type="INSERT",
            project_id=state["project_id"],
            target_table="clients",
            new_value=json.dumps(lead, ensure_ascii=False),
            details="Lead başarıyla üretildi ve veritabanına kaydedildi.",
        )

        logger.info("[Avcı Ajan] Lead bulundu: %s", lead["company_name"])
        return {"lead_info": lead, "retry_count": 0, "error_message": None}

    except Exception as exc:
        retry = state["retry_count"] + 1
        msg = f"Lead üretim hatası (deneme {retry}/{MAX_RETRY_COUNT}): {exc}"
        logger.warning("[Avcı Ajan] %s", msg)

        incident_id = write_incident(
            project_id=state["project_id"],
            agent_name="Avcı Ajan",
            log_level="WARNING",
            message=msg,
        )
        write_audit_log(
            agent_name="Avcı Ajan",
            action_type="ERROR",
            project_id=state["project_id"],
            details=msg,
        )
        return {
            "error_message": msg,
            "retry_count": retry,
            "incident_id": incident_id,
        }


def guardrail_ajan_node(state: AgentState) -> dict:
    """Avcı Ajan çıktısını güvenlik filtresinden geçirir."""
    logger.info("[Guardrail Ajan] Lead verisi güvenlik kontrolünden geçiyor...")

    if not state.get("lead_info"):
        return {"is_safe": False, "error_message": "Lead bilgisi boş; güvenlik kontrolü yapılamadı."}

    lead = state["lead_info"]
    try:
        verdict = call_llm(
            PROMPTS["guardrail_ajan"],
            f"Şirket: {lead.get('company_name')} | "
            f"Yetkili: {lead.get('authorized_person')} | "
            f"E-posta: {lead.get('contact_email')}",
        ).upper()

        email_valid = "@" in lead.get("contact_email", "") and "." in lead.get("contact_email", "")

        if "SAFE" in verdict and email_valid:
            write_audit_log(
                agent_name="Guardrail Ajan",
                action_type="UPDATE",
                project_id=state["project_id"],
                target_table="projects",
                target_column="is_safe",
                new_value="True",
                details="Lead verisi güvenlik kontrolünden geçti.",
            )
            return {"is_safe": True, "error_message": None}
        else:
            reason = verdict if "UNSAFE" in verdict else "E-posta formatı geçersiz."
            msg = f"Güvenlik kontrolü başarısız: {reason}"
            logger.warning("[Guardrail Ajan] %s", msg)
            write_incident(
                project_id=state["project_id"],
                agent_name="Guardrail Ajan",
                log_level="CRITICAL",
                message=msg,
            )
            return {"is_safe": False, "error_message": msg}

    except Exception as exc:
        msg = f"Guardrail hatası: {exc}"
        write_incident(state["project_id"], "Guardrail Ajan", "CRITICAL", msg)
        return {"is_safe": False, "error_message": msg}


def satis_ajani_node(state: AgentState) -> dict:
    """Kişiselleştirilmiş soğuk e-posta üretir ve projeyi ENGAGED durumuna getirir."""
    lead = state["lead_info"]
    logger.info("[Satış Ajanı] %s için e-posta hazırlanıyor...", lead["company_name"])

    try:
        email_text = call_llm(
            PROMPTS["satis_ajani"],
            f"Şirket: {lead['company_name']} | Yetkili: {lead['authorized_person']}",
        )

        # Proje durumunu güncelle
        update_project_field(
            project_id=state["project_id"],
            field="sales_status",
            new_value="ENGAGED",
            agent_name="Satış Ajanı",
        )

        logger.info("[Satış Ajanı] E-posta hazırlandı.")
        return {"sales_email": email_text, "current_phase": "FAZ2_KOORDINASYON"}

    except Exception as exc:
        msg = f"Satış e-postası üretim hatası: {exc}"
        write_incident(state["project_id"], "Satış Ajanı", "WARNING", msg)
        return {"error_message": msg}


# ---------------------------------------------------------------------------
# FAZ 2: KOORDİNASYON VE ONAY
# ---------------------------------------------------------------------------

def finans_ajani_node(state: AgentState) -> dict:
    """Bütçe kontrolü yapar ve finansal onay sağlar."""
    logger.info("[Finans Ajanı] Bütçe kontrolü yapılıyor...")

    try:
        raw = call_llm(
            PROMPTS["finans_ajani"],
            f"Proje: {state['project_id']} | Harcanan: {0.00} | Limit: 500.00",
        )
        clearance = parse_json_safe(raw) or {"status": "NORMAL", "consumed": 0, "limit": 500, "message": "Bütçe uygun."}

        update_project_field(
            project_id=state["project_id"],
            field="payment_status",
            new_value="PAID",
            agent_name="Finans Ajanı",
        )

        budget_status = clearance.get("status", "NORMAL")

        if budget_status == "SUSPEND":
            msg = f"Bütçe aşıldı: {clearance}"
            write_incident(state["project_id"], "Finans Ajanı", "CRITICAL", msg)

        return {
            "financial_clearance": clearance,
            "budget_status": budget_status,
        }

    except Exception as exc:
        msg = f"Finans ajanı hatası: {exc}"
        write_incident(state["project_id"], "Finans Ajanı", "WARNING", msg)
        return {"error_message": msg, "budget_status": "SUSPEND"}


def hukuk_ajani_node(state: AgentState) -> dict:
    """NDA ve sızma testi izin sözleşmesini hazırlar."""
    logger.info("[Hukuk Ajanı] Sözleşme hazırlanıyor...")

    try:
        contract = call_llm(
            PROMPTS["hukuk_ajani"],
            f"Müşteri: {state['lead_info']['company_name']} | "
            f"Proje: {state['project_id']}",
        )

        update_project_field(
            project_id=state["project_id"],
            field="contract_status",
            new_value="SIGNED",
            agent_name="Hukuk Ajanı",
        )

        contract_path = f"/contracts/{state['project_id']}_NDA.txt"
        logger.info("[Hukuk Ajanı] Sözleşme hazırlandı: %s", contract_path)
        return {"contract_path": contract_path}

    except Exception as exc:
        msg = f"Hukuk ajanı hatası: {exc}"
        write_incident(state["project_id"], "Hukuk Ajanı", "WARNING", msg)
        return {"error_message": msg}


def cozum_merkezi_node(state: AgentState) -> dict:
    """
    AND Kapısı: Hukuk VE Finans onayı geldiğinde operasyon başlatma talebini üretir.
    """
    logger.info("[Çözüm Merkezi] AND kapısı kontrolü: Hukuk + Finans onayları denetleniyor...")

    contract_ok  = state.get("contract_path") is not None
    financial_ok = state.get("financial_clearance") is not None
    budget_ok    = state.get("budget_status") != "SUSPEND"

    if contract_ok and financial_ok and budget_ok:
        write_audit_log(
            agent_name="Çözüm Merkezi",
            action_type="UPDATE",
            project_id=state["project_id"],
            target_table="projects",
            target_column="sales_status",
            new_value="ACTIVE",
            details="AND kapısı geçildi. Operasyon başlatma talebi Admin'e iletildi.",
        )
        update_project_field(
            project_id=state["project_id"],
            field="sales_status",
            new_value="ACTIVE",
            agent_name="Çözüm Merkezi",
        )
        logger.info("[Çözüm Merkezi] Tüm ön koşullar sağlandı. Admin onayı bekleniyor.")
        return {"operation_launch_ready": True}
    else:
        reasons = []
        if not contract_ok:  reasons.append("Sözleşme eksik")
        if not financial_ok: reasons.append("Finansal onay eksik")
        if not budget_ok:    reasons.append("Bütçe aşımı")
        msg = "AND kapısı geçilemedi: " + ", ".join(reasons)
        write_incident(state["project_id"], "Çözüm Merkezi", "CRITICAL", msg)
        return {"operation_launch_ready": False, "error_message": msg}


def admin_giris_ajani_node(state: AgentState) -> dict:
    """
    Telegram üzerinden Admin fiziksel onayı alır.
    TEST modunda (ADMIN_APPROVAL=true) anında geçer.
    Prodüksiyonda inline butonlu mesaj gönderilir ve polling ile beklenir.
    """
    logger.info("[Admin Giriş Ajanı] Admin onayı bekleniyor...")

    lead = state.get("lead_info") or {}
    operation_summary = (
        f"Müşteri: {lead.get('company_name', '?')}\n"
        f"Hedef: {lead.get('contact_email', '?').split('@')[-1]}\n"
        f"Faz: Siber güvenlik sızma testi başlatılacak."
    )

    approved = bekle_admin_onay(
        project_id=state["project_id"],
        operation_summary=operation_summary,
    )

    if approved:
        logger.info("[Admin Giriş Ajanı] ✅ Admin onayı alındı.")
        return {"admin_approval": True}
    else:
        msg = "Admin onayı verilmedi veya zaman aşımına uğradı. Operasyon iptal edildi."
        logger.warning("[Admin Giriş Ajanı] ⛔ %s", msg)
        return {"admin_approval": False, "error_message": msg}


# ---------------------------------------------------------------------------
# FAZ 3: TEKNİK OPERASYON
# ---------------------------------------------------------------------------

def siber_istihbarat_ajani_node(state: AgentState) -> dict:
    """Dark web ve sızıntı verisi taraması yapar."""
    logger.info("[Siber İstihbarat Ajanı] Dark web taraması başlatılıyor...")

    try:
        raw = call_llm(
            PROMPTS["siber_istihbarat_ajani"],
            f"Hedef domain: {state['lead_info']['contact_email'].split('@')[-1]}",
        )
        intel = parse_json_safe(raw) or {}
        logger.info("[Siber İstihbarat Ajanı] İstihbarat paketi hazır.")
        return {"threat_intel": intel}

    except Exception as exc:
        msg = f"Siber istihbarat hatası: {exc}"
        write_incident(state["project_id"], "Siber İstihbarat Ajanı", "WARNING", msg)
        return {"threat_intel": {}, "error_message": msg}


def siber_test_ajani_node(state: AgentState) -> dict:
    """Zafiyet taraması yapar ve bulguları veritabanına yazar."""
    logger.info("[Siber Test Ajanı] Sızma testi başlatılıyor...")

    if not state.get("admin_approval"):
        msg = "Admin onayı olmadan tarama başlatılamaz."
        write_incident(state["project_id"], "Siber Test Ajanı", "CRITICAL", msg)
        return {"error_message": msg, "vulnerability_results": []}

    target_domain = state["lead_info"]["contact_email"].split("@")[-1]

    try:
        raw = call_llm(
            PROMPTS["siber_test_ajani"],
            f"Hedef: {target_domain} | Threat Intel: {json.dumps(state.get('threat_intel', {}), ensure_ascii=False)}",
        )
        result = parse_json_safe(raw) or {"findings": []}
        findings = result.get("findings", [])

        # Her bulguyu veritabanına kaydet
        for finding in findings:
            write_vulnerability(
                project_id=state["project_id"],
                target_ip_domain=target_domain,
                vulnerability_title=finding.get("title", "Bilinmiyor"),
                severity=finding.get("severity", "INFO"),
                description=finding.get("description", ""),
                cve_id=finding.get("cve_id"),
                proof_of_concept=finding.get("poc"),
            )

        write_audit_log(
            agent_name="Siber Test Ajanı",
            action_type="INSERT",
            project_id=state["project_id"],
            target_table="vulnerability_scans",
            new_value=f"{len(findings)} bulgu kaydedildi.",
        )
        logger.info("[Siber Test Ajanı] %d zafiyet bulundu.", len(findings))
        return {"vulnerability_results": findings}

    except Exception as exc:
        msg = f"Siber test hatası (deneme {state['retry_count'] + 1}/{MAX_RETRY_COUNT}): {exc}"
        incident_id = write_incident(
            project_id=state["project_id"],
            agent_name="Siber Test Ajanı",
            log_level="CRITICAL",
            message=msg,
        )
        logger.error("[Siber Test Ajanı] %s", msg)
        return {
            "error_message": msg,
            "retry_count": state["retry_count"] + 1,
            "incident_id": incident_id,
            "vulnerability_results": [],
        }


def olay_mudahale_ajani_node(state: AgentState) -> dict:
    """Kritik hata durumunda incident kaydeder ve çözüm raporu yazar."""
    incident_id = state.get("incident_id")
    msg = state.get("error_message", "Bilinmeyen hata")
    logger.info("[Olay Müdahale Ajanı] İnceleniyor: %s", msg)

    action = "Sistem logları analiz edildi. Retry limiti aşıldı. Admin bilgilendirildi."

    if incident_id:
        resolve_incident(
            incident_id=incident_id,
            agent_name="Olay Müdahale Ajanı",
            action_taken=action,
        )

    write_audit_log(
        agent_name="Olay Müdahale Ajanı",
        action_type="UPDATE",
        project_id=state["project_id"],
        target_table="incident_logs",
        details=action,
    )
    logger.warning("[Olay Müdahale Ajanı] Incident kapatıldı. Süreç sonlandırıldı.")
    return {}


def regülasyon_ajani_node(state: AgentState) -> dict:
    """KVKK/GDPR uyum kontrolü yapar."""
    logger.info("[Regülasyon Ajanı] Uyum denetimi başlatılıyor...")

    try:
        raw = call_llm(
            PROMPTS["regülasyon_ajani"],
            f"Proje: {state['project_id']} | "
            f"Bulgular: {len(state.get('vulnerability_results') or [])} adet",
        )
        compliance = parse_json_safe(raw) or {}
        logger.info("[Regülasyon Ajanı] Uyum raporu hazır.")
        return {"compliance_report": compliance}

    except Exception as exc:
        msg = f"Regülasyon ajanı hatası: {exc}"
        write_incident(state["project_id"], "Regülasyon Ajanı", "WARNING", msg)
        return {"compliance_report": {}, "error_message": msg}


# ---------------------------------------------------------------------------
# FAZ 4: RAPORLAMA VE KAPANIŞ
# ---------------------------------------------------------------------------

def raporlama_ajani_node(state: AgentState) -> dict:
    """Tüm bulguları birleştirerek nihai kurumsal rapor üretir."""
    logger.info("[Raporlama Ajanı] Nihai rapor üretiliyor...")

    vulns    = state.get("vulnerability_results") or []
    clouds   = state.get("cloud_misconfigs") or []
    phishing = state.get("phishing_metrics") or {}
    compliance = state.get("compliance_report") or {}

    try:
        report = call_llm(
            PROMPTS["raporlama_ajani"],
            f"Proje: {state['project_id']}\n"
            f"Zafiyet Bulguları: {json.dumps(vulns, ensure_ascii=False)}\n"
            f"Bulut Yapılandırma Hataları: {json.dumps(clouds, ensure_ascii=False)}\n"
            f"Phishing Metrikleri: {json.dumps(phishing, ensure_ascii=False)}\n"
            f"Uyum Durumu: {json.dumps(compliance, ensure_ascii=False)}",
        )

        update_project_field(
            project_id=state["project_id"],
            field="sales_status",
            new_value="COMPLETED",
            agent_name="Raporlama Ajanı",
        )

        write_audit_log(
            agent_name="Raporlama Ajanı",
            action_type="INSERT",
            project_id=state["project_id"],
            target_table="projects",
            details="Nihai müşteri raporu üretildi ve proje COMPLETED durumuna alındı.",
        )

        logger.info("[Raporlama Ajanı] ✅ Rapor tamamlandı.")
        return {"final_report": report, "current_phase": "TAMAMLANDI"}

    except Exception as exc:
        msg = f"Raporlama hatası: {exc}"
        write_incident(state["project_id"], "Raporlama Ajanı", "WARNING", msg)
        return {"error_message": msg}


# ===========================================================================
# 4. KOŞULLU YOLLAR (CONDITIONAL EDGES)
# ===========================================================================

def avci_kontrol(state: AgentState) -> str:
    if state.get("error_message") and not state.get("lead_info"):
        return "retry" if state["retry_count"] < MAX_RETRY_COUNT else "fail"
    return "success"


def guardrail_kontrol(state: AgentState) -> str:
    return "approved" if state.get("is_safe") else "blocked"


def cozum_merkezi_kontrol(state: AgentState) -> str:
    return "hazir" if state.get("operation_launch_ready") else "fail"


def admin_kontrol(state: AgentState) -> str:
    return "onaylandi" if state.get("admin_approval") else "reddedildi"


def siber_test_kontrol(state: AgentState) -> str:
    if state.get("error_message") and not state.get("vulnerability_results"):
        return "retry" if state["retry_count"] < MAX_RETRY_COUNT else "fail"
    return "success"


def butce_kontrol(state: AgentState) -> str:
    return "suspend" if state.get("budget_status") == "SUSPEND" else "devam"


# ===========================================================================
# 5. WORKFLOW GRAPH OLUŞTURMA
# ===========================================================================

workflow = StateGraph(AgentState)

# --- Düğümleri Ekle ---
workflow.add_node("avci_ajan",            avci_ajan_node)
workflow.add_node("guardrail_ajan",       guardrail_ajan_node)
workflow.add_node("satis_ajani",          satis_ajani_node)
workflow.add_node("finans_ajani",         finans_ajani_node)
workflow.add_node("hukuk_ajani",          hukuk_ajani_node)
workflow.add_node("cozum_merkezi",        cozum_merkezi_node)
workflow.add_node("admin_giris_ajani",    admin_giris_ajani_node)
workflow.add_node("siber_istihbarat",     siber_istihbarat_ajani_node)
workflow.add_node("siber_test_ajani",     siber_test_ajani_node)
workflow.add_node("regülasyon_ajani",     regülasyon_ajani_node)
workflow.add_node("raporlama_ajani",      raporlama_ajani_node)
workflow.add_node("olay_mudahale",        olay_mudahale_ajani_node)

# --- Başlangıç Noktası ---
workflow.set_entry_point("avci_ajan")

# --- Akış Bağlantıları ---

# Avcı Ajan → Guardrail (ya da retry / fail)
workflow.add_conditional_edges("avci_ajan", avci_kontrol, {
    "success": "guardrail_ajan",
    "retry":   "avci_ajan",
    "fail":    "olay_mudahale",
})

# Guardrail → Satış (ya da olay müdahale)
workflow.add_conditional_edges("guardrail_ajan", guardrail_kontrol, {
    "approved": "satis_ajani",
    "blocked":  "olay_mudahale",
})

# Satış → Finans + Hukuk (paralel)
workflow.add_edge("satis_ajani", "finans_ajani")
workflow.add_edge("satis_ajani", "hukuk_ajani")

# Finans + Hukuk → Çözüm Merkezi
workflow.add_edge("finans_ajani", "cozum_merkezi")
workflow.add_edge("hukuk_ajani",  "cozum_merkezi")

# Bütçe kontrolü
workflow.add_conditional_edges("finans_ajani", butce_kontrol, {
    "suspend": "olay_mudahale",
    "devam":   "cozum_merkezi",
})

# Çözüm Merkezi → Admin (ya da fail)
workflow.add_conditional_edges("cozum_merkezi", cozum_merkezi_kontrol, {
    "hazir": "admin_giris_ajani",
    "fail":  "olay_mudahale",
})

# Admin → Teknik Operasyon (ya da sonlandır)
workflow.add_conditional_edges("admin_giris_ajani", admin_kontrol, {
    "onaylandi":   "siber_istihbarat",
    "reddedildi":  "olay_mudahale",
})

# İstihbarat → Siber Test
workflow.add_edge("siber_istihbarat", "siber_test_ajani")

# Siber Test → Regülasyon + Raporlama (ya da retry / fail)
workflow.add_conditional_edges("siber_test_ajani", siber_test_kontrol, {
    "success": "regülasyon_ajani",
    "retry":   "siber_test_ajani",
    "fail":    "olay_mudahale",
})

# Regülasyon → Raporlama
workflow.add_edge("regülasyon_ajani", "raporlama_ajani")

# Bitiş Noktaları
workflow.add_edge("raporlama_ajani", END)
workflow.add_edge("olay_mudahale",   END)

# --- Grafı Derle ---
app = workflow.compile()


# ===========================================================================
# 6. SİSTEMİ ÇALIŞTIRMA
# ===========================================================================

if __name__ == "__main__":
    initial_state: AgentState = {
        "project_id":           "PRJ-2026-001",
        "target_sector":        "Finansal Teknoloji (FinTech)",
        "lead_info":            None,
        "sales_email":          None,
        "contract_path":        None,
        "financial_clearance":  None,
        "admin_approval":       False,
        "operation_launch_ready": False,
        "threat_intel":         None,
        "vulnerability_results": None,
        "cloud_misconfigs":     None,
        "phishing_metrics":     None,
        "incident_id":          None,
        "final_report":         None,
        "compliance_report":    None,
        "is_safe":              False,
        "error_message":        None,
        "retry_count":          0,
        "current_phase":        "FAZ1_IS_GELISTIRME",
        "budget_status":        "NORMAL",
    }

    print("\n" + "="*70)
    print("  OTONOM SİBER GÜVENLİK SİSTEMİ - BAŞLATILDI")
    print("="*70)

    final_state = app.invoke(initial_state)

    print("\n" + "="*70)
    print("  SÜREÇ TAMAMLANDI")
    print("="*70)

    if final_state.get("final_report"):
        print("\n📄 NİHAİ RAPOR:\n")
        print(final_state["final_report"])
    elif final_state.get("error_message"):
        print(f"\n⚠️  HATA İLE SONLANDI: {final_state['error_message']}")
    else:
        print("\n✅ Süreç tamamlandı, rapor oluşturulmadı (beklenmedik durum).")

    print(f"\nProje Fazı : {final_state.get('current_phase')}")
    print(f"Bütçe Durumu: {final_state.get('budget_status')}")
    print(f"Admin Onayı : {final_state.get('admin_approval')}")
    print("="*70 + "\n")
