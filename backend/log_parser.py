import re
import os

# Standard Apache/Nginx combined log regex pattern
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>[A-Z]+) (?P<request>.*?) HTTP/.*?" '
    r'(?P<status>\d{3})'
)

def parse_and_filter_logs(log_file_path: str) -> list[dict]:
    """
    Reads a server log file line by line.
    Filters and returns only high-risk entries to save LLM context tokens.
    """
    suspicious_logs = []
    
    # Ensure the file exists before attempting to read it
    if not os.path.exists(log_file_path):
        return suspicious_logs
        
    with open(log_file_path, 'r') as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                log_data = match.groupdict()
                status_code = int(log_data['status'])
                request_path = log_data['request'].lower()
                
                # Filter Rule 1: High-risk HTTP status codes (4xx unauthorized, 5xx server errors)
                is_error_status = status_code >= 400
                
                # Filter Rule 2: Targeting sensitive directories or injection attempts
                is_sensitive_path = any(keyword in request_path for keyword in ['login', 'admin', 'wp-admin', 'config', 'passwd'])
                
                # If the log triggers either rule, we flag it for the AI Anomaly Detector
                if is_error_status or is_sensitive_path:
                    # Append the raw line as 'raw_evidence' for the Pydantic schema later
                    log_data['raw_evidence'] = line.strip()
                    suspicious_logs.append(log_data)
                    
    return suspicious_logs

# Quick local test block
if __name__ == "__main__":
    # Create a dummy log file to test the parser
    test_file = "test_logs.txt"
    sample_logs = (
        '192.168.1.10 - - [12/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024\n'  # Normal traffic (Should be ignored)
        '10.0.0.5 - - [12/Oct/2026:10:05:00 +0000] "POST /admin/login HTTP/1.1" 401 512\n'      # Failed login (Should be flagged)
        '172.16.0.8 - - [12/Oct/2026:10:10:00 +0000] "GET /etc/passwd HTTP/1.1" 403 256\n'      # Directory traversal (Should be flagged)
    )
    with open(test_file, "w") as f:
        f.write(sample_logs)
        
    print("Scanning logs...")
    results = parse_and_filter_logs(test_file)
    
    for r in results:
        print(f"[FLAGGED] IP: {r['ip']} | Status: {r['status']} | Target: {r['request']}")