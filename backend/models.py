from pydantic import BaseModel, Field
from typing import Optional

# ---------------------------------------------------------
# Agent 1: The Anomaly Detector (IDS Layer)
# ---------------------------------------------------------
class AnomalyReport(BaseModel):
    """
    Schema for the Level 1 Triage Analyst.
    Takes raw server logs and categorizes the specific attack type.
    """
    source_ip: str = Field(..., description="The IP address of the attacker")
    anomaly_type: str = Field(..., description="E.g., 'Brute Force', 'Directory Traversal', 'SQL Injection'")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence of the detection (0.0 to 1.0)")
    raw_evidence: str = Field(..., description="The exact raw log line that triggered the alert")

# ---------------------------------------------------------
# Agent 2: The Vulnerability Mapper (SIEM Layer)
# ---------------------------------------------------------
class VulnerabilityMapping(BaseModel):
    """
    Schema for the Threat Correlation Engine.
    Takes the AnomalyReport and maps it to a known CVE.
    """
    source_ip: str
    cve_id: Optional[str] = Field(default=None, description="The assigned CVE ID if known, e.g., 'CVE-2021-44228'")
    vulnerability_description: str = Field(..., description="A short plain-English explanation of the threat vector")
    severity_level: str = Field(..., description="Must be one of: 'Low', 'Medium', 'High', 'Critical'")

# ---------------------------------------------------------
# Agent 3: The Mitigation Strategist (IPS Layer)
# ---------------------------------------------------------
class MitigationStrategy(BaseModel):
    """
    Schema for the Infrastructure Hardening Agent.
    Generates the exact command needed to block the threat.
    """
    target_ip: str
    action_required: str = Field(..., description="E.g., 'Block IP in Firewall', 'Patch Nginx Config'")
    firewall_rule_syntax: str = Field(..., description="The exact bash/iptables/ufw syntax to block the threat, e.g., 'iptables -A INPUT -s <ip> -j DROP'")

# ---------------------------------------------------------
# Unified Dashboard Output
# ---------------------------------------------------------
class ThreatIntelligenceReport(BaseModel):
    """
    The final unified payload sent to the React Frontend and SQLite Database.
    """
    incident_id: str
    timestamp: str
    anomaly: AnomalyReport
    vulnerability: VulnerabilityMapping
    mitigation: MitigationStrategy