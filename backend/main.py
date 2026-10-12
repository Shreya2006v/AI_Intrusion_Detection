import os
import shutil
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, save_incident, get_all_incidents
from log_parser import parse_and_filter_logs
from ai_engine import analyze_anomaly, map_vulnerability, generate_mitigation

app = FastAPI(
    title="AI-Driven Network Intrusion Detection Pipeline",
    version="1.0.0"
)

# Enable CORS for the future React/Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/")
def health_check():
    return {"status": "active", "service": "NIDS AI Pipeline"}

@app.get("/incidents")
def list_incidents():
    """Returns historical security incidents recorded in SQLite."""
    return get_all_incidents()

@app.post("/analyze-file")
async def analyze_log_file(file: UploadFile = File(...)):
    """
    Ingests a raw server log file, applies regex pre-filtering,
    executes the 3-agent AI pipeline, and saves results to the ledger.
    """
    temp_file_path = f"temp_{file.filename}"
    try:
        # Save incoming file to disk temporarily
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Stage 1: Regex Pre-filtering
        flagged_logs = parse_and_filter_logs(temp_file_path)
        if not flagged_logs:
            return {"message": "No suspicious activity detected in uploaded log file.", "processed": 0, "incidents": []}

        processed_incidents = []

        # Stage 2: Autonomous Multi-Agent Pipeline
        for log_entry in flagged_logs:
            # Agent 1: Anomaly Detector (IDS)
            anomaly = analyze_anomaly(log_entry)

            # Agent 2: Vulnerability Mapper (SIEM)
            vuln = map_vulnerability(anomaly)

            # Agent 3: Mitigation Strategist (IPS)
            mitigation = generate_mitigation(vuln)

            # Prepare structured record
            incident_payload = {
                "timestamp": log_entry.get("timestamp") or datetime.utcnow().isoformat(),
                "source_ip": anomaly.source_ip,
                "anomaly_type": anomaly.anomaly_type,
                "confidence_score": anomaly.confidence_score,
                "cve_id": vuln.cve_id,
                "severity_level": vuln.severity_level,
                "vulnerability_description": vuln.vulnerability_description,
                "action_required": mitigation.action_required,
                "firewall_rule": mitigation.firewall_rule_syntax,
                "raw_evidence": anomaly.raw_evidence
            }

            # Stage 3: Persistence in Black Box Ledger
            save_incident(incident_payload)
            processed_incidents.append(incident_payload)

        return {
            "status": "success",
            "processed_count": len(processed_incidents),
            "incidents": processed_incidents
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temporary uploaded file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)