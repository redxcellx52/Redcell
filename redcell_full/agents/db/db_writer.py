"""
db_writer.py
------------
Tüm ajanların ortak kullandığı veritabanı yazma/okuma katmanı.
Her state değişikliği buradaki fonksiyonlar aracılığıyla kalıcı hale gelir.
"""

import os
import json
import logging
from datetime import datetime
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bağlantı Ayarları (Ortam değişkenlerinden okunur)
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME", "cyber_agents"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}


@contextmanager
def get_connection():
    """
    Context manager: bağlantıyı açar, işlem biter veya hata oluşursa kapatır.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("DB transaction rolled back: %s", exc)
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

def write_audit_log(
    agent_name: str,
    action_type: str,
    project_id: str | None = None,
    target_table: str | None = None,
    target_column: str | None = None,
    old_value=None,
    new_value=None,
    details: str | None = None,
) -> int | None:
    """
    Her önemli state değişikliği, hata veya retry işlemi için audit kaydı düşer.
    Dönen değer: audit_id (ileride referans için kullanılabilir)
    """
    sql = """
        INSERT INTO audit_logs
            (project_id, triggered_by_agent, action_type,
             target_table, target_column, old_value, new_value, details)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING audit_id;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    project_id,
                    agent_name,
                    action_type,
                    target_table,
                    target_column,
                    str(old_value) if old_value is not None else None,
                    str(new_value) if new_value is not None else None,
                    details,
                ))
                row = cur.fetchone()
                return row[0] if row else None
    except Exception as exc:
        logger.error("[write_audit_log] Hata: %s", exc)
        return None


# ---------------------------------------------------------------------------
# MÜŞTERİ (CLIENT) KAYDI
# ---------------------------------------------------------------------------

def upsert_client(company_name: str, authorized_person: str, contact_email: str) -> int | None:
    """
    Müşteri zaten varsa mevcut client_id döner, yoksa yeni kaydeder.
    """
    sql_select = "SELECT client_id FROM clients WHERE contact_email = %s;"
    sql_insert = """
        INSERT INTO clients (company_name, authorized_person, contact_email)
        VALUES (%s, %s, %s)
        RETURNING client_id;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql_select, (contact_email,))
                row = cur.fetchone()
                if row:
                    return row[0]
                cur.execute(sql_insert, (company_name, authorized_person, contact_email))
                row = cur.fetchone()
                return row[0] if row else None
    except Exception as exc:
        logger.error("[upsert_client] Hata: %s", exc)
        return None


# ---------------------------------------------------------------------------
# PROJE KAYDI / GÜNCELLEME
# ---------------------------------------------------------------------------

def create_project(project_id: str, client_id: int, budget_limit: float) -> bool:
    """
    Yeni proje kaydı oluşturur. Aynı project_id zaten varsa sessizce geçer.
    """
    sql = """
        INSERT INTO projects (project_id, client_id, budget_limit)
        VALUES (%s, %s, %s)
        ON CONFLICT (project_id) DO NOTHING;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (project_id, client_id, budget_limit))
        return True
    except Exception as exc:
        logger.error("[create_project] Hata: %s", exc)
        return False


def update_project_field(
    project_id: str,
    field: str,
    new_value,
    agent_name: str,
) -> bool:
    """
    Projenin tek bir alanını günceller ve otomatik audit logu düşer.
    Sadece izin verilen alanlar güncellenebilir (injection koruması).
    """
    ALLOWED_FIELDS = {
        "sales_status", "contract_status", "payment_status",
        "admin_approval", "budget_consumed",
    }
    if field not in ALLOWED_FIELDS:
        logger.warning("[update_project_field] İzinsiz alan: %s", field)
        return False

    sql_select = f"SELECT {field} FROM projects WHERE project_id = %s;"
    sql_update = f"UPDATE projects SET {field} = %s WHERE project_id = %s;"

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                # Eski değeri oku
                cur.execute(sql_select, (project_id,))
                row = cur.fetchone()
                old_value = row[0] if row else None

                # Güncelle
                cur.execute(sql_update, (new_value, project_id))

        # Audit logu yaz
        write_audit_log(
            agent_name=agent_name,
            action_type="UPDATE",
            project_id=project_id,
            target_table="projects",
            target_column=field,
            old_value=old_value,
            new_value=new_value,
        )
        return True
    except Exception as exc:
        logger.error("[update_project_field] Hata: %s", exc)
        return False


# ---------------------------------------------------------------------------
# INCIDENT LOG (Hata / Uyarı Kaydı)
# ---------------------------------------------------------------------------

def write_incident(
    project_id: str,
    agent_name: str,
    log_level: str,
    message: str,
    status: str = "OPEN",
) -> int | None:
    """
    Hata, zaman aşımı veya güvenlik uyarısı olduğunda incident_logs'a yazar.
    Dönen değer: incident_id
    """
    sql = """
        INSERT INTO incident_logs (project_id, agent_name, log_level, message, status)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING incident_id;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (project_id, agent_name, log_level, message, status))
                row = cur.fetchone()
                incident_id = row[0] if row else None

        # Audit logu da düş
        write_audit_log(
            agent_name=agent_name,
            action_type="INSERT",
            project_id=project_id,
            target_table="incident_logs",
            details=f"[{log_level}] {message}",
        )
        return incident_id
    except Exception as exc:
        logger.error("[write_incident] Hata: %s", exc)
        return None


def resolve_incident(incident_id: int, agent_name: str, action_taken: str) -> bool:
    """
    Olay Müdahale Ajanı bir incident'ı kapattığında çağrılır.
    """
    sql_update  = "UPDATE incident_logs SET status = 'RESOLVED' WHERE incident_id = %s;"
    sql_resolve = """
        INSERT INTO resolution_reports (incident_id, resolved_by_agent, action_taken)
        VALUES (%s, %s, %s);
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql_update, (incident_id,))
                cur.execute(sql_resolve, (incident_id, agent_name, action_taken))
        return True
    except Exception as exc:
        logger.error("[resolve_incident] Hata: %s", exc)
        return False


# ---------------------------------------------------------------------------
# ZAFİYET BULGULARI
# ---------------------------------------------------------------------------

def write_vulnerability(
    project_id: str,
    target_ip_domain: str,
    vulnerability_title: str,
    severity: str,
    description: str,
    cve_id: str | None = None,
    proof_of_concept: str | None = None,
    is_false_positive: bool = False,
) -> int | None:
    sql = """
        INSERT INTO vulnerability_scans
            (project_id, target_ip_domain, vulnerability_title,
             severity, cve_id, description, proof_of_concept, is_false_positive)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING scan_id;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (
                    project_id, target_ip_domain, vulnerability_title,
                    severity, cve_id, description, proof_of_concept, is_false_positive,
                ))
                row = cur.fetchone()
                return row[0] if row else None
    except Exception as exc:
        logger.error("[write_vulnerability] Hata: %s", exc)
        return None


# ---------------------------------------------------------------------------
# PHISHING KAMPANYA
# ---------------------------------------------------------------------------

def write_phishing_record(
    project_id: str,
    target_email: str,
    scenario_type: str,
) -> int | None:
    sql = """
        INSERT INTO phishing_campaigns (project_id, target_email, scenario_type)
        VALUES (%s, %s, %s)
        RETURNING campaign_id;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (project_id, target_email, scenario_type))
                row = cur.fetchone()
                return row[0] if row else None
    except Exception as exc:
        logger.error("[write_phishing_record] Hata: %s", exc)
        return None


def update_phishing_outcome(
    campaign_id: int,
    is_delivered: bool = False,
    is_clicked: bool = False,
    is_data_entered: bool = False,
) -> bool:
    sql = """
        UPDATE phishing_campaigns
        SET is_delivered = %s, is_clicked = %s, is_data_entered = %s
        WHERE campaign_id = %s;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (is_delivered, is_clicked, is_data_entered, campaign_id))
        return True
    except Exception as exc:
        logger.error("[update_phishing_outcome] Hata: %s", exc)
        return False
