from fpdf import FPDF
from datetime import datetime

def clean_text(text: str) -> str:
    """Replaces Unicode characters with standard ASCII to prevent PDF font errors."""
    if not text:
        return ""
    
    # Replace common AI-generated smart quotes and dashes with standard keyboard equivalents
    replacements = {
        '\u2011': '-', '\u2012': '-', '\u2013': '-', '\u2014': '-', 
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u200b': '' # Zero-width space
    }
    
    cleaned = str(text)
    for unicode_char, ascii_char in replacements.items():
        cleaned = cleaned.replace(unicode_char, ascii_char)
        
    # Ignore any remaining unsupported characters rather than crashing
    return cleaned.encode('latin-1', 'ignore').decode('latin-1')

class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", 'B', 16)
        self.set_text_color(0, 51, 102)
        self.cell(0, 10, "AI-Driven NIDS - Threat Intelligence Report", ln=True, align='C')
        self.set_font("Arial", 'I', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        self.ln(10)

def create_pdf(incidents: list, filename="nids_report.pdf") -> str:
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    if not incidents:
        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, "No security incidents recorded in the ledger.", ln=True)
        pdf.output(filename)
        return filename

    for idx, inc in enumerate(incidents):
        # Clean text fields
        anomaly = clean_text(inc['anomaly_type'])
        severity = clean_text(inc['severity_level'])
        desc = clean_text(inc['vulnerability_description'])
        action = clean_text(inc['action_required'])
        rule = clean_text(inc['firewall_rule'])
        cve = clean_text(inc['cve_id']) if inc['cve_id'] else None

        # Threat Title & Severity
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(200, 0, 0) if severity.lower() in ['high', 'critical'] else pdf.set_text_color(204, 102, 0)
        pdf.cell(0, 8, f"Incident #{idx+1}: {anomaly} ({severity})", ln=True)
        
        # Metadata
        pdf.set_font("Arial", '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 6, f"Timestamp: {inc['timestamp']}", ln=True)
        pdf.cell(0, 6, f"Target IP: {inc['source_ip']} | Confidence: {inc['confidence_score']}", ln=True)
        if cve:
            pdf.cell(0, 6, f"Known Vulnerability: {cve}", ln=True)
            
        # Description
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 6, "Threat Profile:", ln=True)
        pdf.set_font("Arial", '', 10)
        pdf.multi_cell(0, 6, desc)
        
        # Mitigation
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 10)
        pdf.set_text_color(0, 102, 51)
        pdf.cell(0, 6, f"Mitigation Strategy ({action}):", ln=True)
        pdf.set_font("Courier", '', 9)
        pdf.multi_cell(0, 6, rule)
        
        # Separator
        pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 10, "-"*80, ln=True, align='C')
        pdf.ln(2)

    pdf.output(filename)
    return filename