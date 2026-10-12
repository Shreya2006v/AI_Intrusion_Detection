import sqlite3
import json
from typing import List, Dict, Any

DB_NAME = "blackbox_ledger.db"

def init_db():
    """Initializes the SQLite Black Box Ledger schema."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            cve_id TEXT,
            severity_level TEXT NOT NULL,
            vulnerability_description TEXT NOT NULL,
            action_required TEXT NOT NULL,
            firewall_rule TEXT NOT NULL,
            raw_evidence TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_incident(incident_data: Dict[str, Any]):
    """Persists an analyzed threat payload into the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO security_incidents (
            timestamp, source_ip, anomaly_type, confidence_score,
            cve_id, severity_level, vulnerability_description,
            action_required, firewall_rule, raw_evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident_data["timestamp"],
        incident_data["source_ip"],
        incident_data["anomaly_type"],
        incident_data["confidence_score"],
        incident_data["cve_id"],
        incident_data["severity_level"],
        incident_data["vulnerability_description"],
        incident_data["action_required"],
        incident_data["firewall_rule"],
        incident_data["raw_evidence"]
    ))
    conn.commit()
    conn.close()

def get_all_incidents() -> List[Dict[str, Any]]:
    """Retrieves all historical threat logs for the dashboard."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_incidents ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]