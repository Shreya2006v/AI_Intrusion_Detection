import os
import json
from dotenv import load_dotenv
from groq import Groq
from models import AnomalyReport, VulnerabilityMapping, MitigationStrategy

# Load environment variables from .env
load_dotenv()

# Initialize Groq client
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Model to use (fast inference)
LLM_MODEL = "openai/gpt-oss-20b"
def analyze_anomaly(log_entry: dict) -> AnomalyReport:
    """Agent 1: Anomaly Detector (IDS Layer)"""
    prompt = f"""
    You are an expert Network Intrusion Detection Analyst.
    Analyze the following suspicious server log entry and categorize the attack.
    
    Log Data:
    IP: {log_entry.get('ip')}
    Status: {log_entry.get('status')}
    Request: {log_entry.get('request')}
    Raw Evidence: {log_entry.get('raw_evidence')}

    Return ONLY a valid JSON object matching this schema:
    {{
        "source_ip": "{log_entry.get('ip')}",
        "anomaly_type": "<e.g., Brute Force, Directory Traversal, SQL Injection, Port Scan>",
        "confidence_score": <float between 0.0 and 1.0>,
        "raw_evidence": "{log_entry.get('raw_evidence')}"
    }}
    """
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model=LLM_MODEL,
        response_format={"type": "json_object"}
    )
    
    raw_json = json.loads(chat_completion.choices[0].message.content)
    return AnomalyReport(**raw_json)


def map_vulnerability(anomaly: AnomalyReport) -> VulnerabilityMapping:
    """Agent 2: Vulnerability Mapper (SIEM Layer)"""
    prompt = f"""
    You are a Threat Intelligence Analyst.
    Correlate this detected anomaly with common known vulnerabilities (CVEs) or attack vectors.
    
    Anomaly Detected:
    Source IP: {anomaly.source_ip}
    Anomaly Type: {anomaly.anomaly_type}
    Evidence: {anomaly.raw_evidence}

    Return ONLY a valid JSON object matching this schema:
    {{
        "source_ip": "{anomaly.source_ip}",
        "cve_id": "<e.g., CVE-2021-44228 or null if generic>",
        "vulnerability_description": "<concise explanation of the threat vector>",
        "severity_level": "<Low | Medium | High | Critical>"
    }}
    """
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model=LLM_MODEL,
        response_format={"type": "json_object"}
    )
    
    raw_json = json.loads(chat_completion.choices[0].message.content)
    return VulnerabilityMapping(**raw_json)


def generate_mitigation(vulnerability: VulnerabilityMapping) -> MitigationStrategy:
    """Agent 3: Mitigation Strategist (IPS Layer)"""
    prompt = f"""
    You are an Automated Intrusion Prevention System (IPS).
    Generate actionable firewall rules or server configuration commands to block the attack.
    
    Threat Details:
    Target/Attacker IP: {vulnerability.source_ip}
    Description: {vulnerability.vulnerability_description}
    Severity: {vulnerability.severity_level}

    Return ONLY a valid JSON object matching this schema:
    {{
        "target_ip": "{vulnerability.source_ip}",
        "action_required": "<e.g., Block IP via iptables, Rate-limit endpoint>",
        "firewall_rule_syntax": "<exact bash command, e.g., iptables -A INPUT -s {vulnerability.source_ip} -j DROP>"
    }}
    """
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model=LLM_MODEL,
        response_format={"type": "json_object"}
    )
    
    raw_json = json.loads(chat_completion.choices[0].message.content)
    return MitigationStrategy(**raw_json)


# Quick verification test
if __name__ == "__main__":
    test_entry = {
        "ip": "10.0.0.5",
        "status": "401",
        "request": "POST /admin/login",
        "raw_evidence": '10.0.0.5 - - [12/Oct/2026:10:05:00 +0000] "POST /admin/login HTTP/1.1" 401 512'
    }
    
    print("\n--- Running Multi-Agent Pipeline Test ---")
    anomaly = analyze_anomaly(test_entry)
    print(f"\n[Agent 1: Anomaly Report]\n{anomaly.model_dump_json(indent=2)}")
    
    vuln = map_vulnerability(anomaly)
    print(f"\n[Agent 2: Vulnerability Mapping]\n{vuln.model_dump_json(indent=2)}")
    
    mitigation = generate_mitigation(vuln)
    print(f"\n[Agent 3: Mitigation Strategy]\n{mitigation.model_dump_json(indent=2)}")