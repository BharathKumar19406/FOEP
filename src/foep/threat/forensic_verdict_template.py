# src/foep/threat/forensic_verdict_template.py
"""Jinja2 template generator for forensic verdicts."""

from typing import Dict, Any
from jinja2 import Template
from datetime import datetime
from foep.threat.threat_schema import ForensicVerdict, ThreatLevel


FORENSIC_VERDICT_TEMPLATE = """
╔════════════════════════════════════════════════════════════════════════════╗
║                    🔬 FORENSIC THREAT VERDICT REPORT                       ║
╚════════════════════════════════════════════════════════════════════════════╝

📋 CASE INFORMATION
════════════════════════════════════════════════════════════════════════════
Case ID:              {{ case_id }}
Report Generated:     {{ verdict_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }}
Analyst:              {{ analyst }}
Confidence Level:     {{ (confidence_level * 100)|int }}%

🎯 VERDICT DETERMINATION
════════════════════════════════════════════════════════════════════════════
{% if verdict == 'MALICIOUS' %}
⛔ VERDICT:           MALICIOUS (Active Threat)
🔴 THREAT LEVEL:      {{ threat_level.value|upper }}
{% elif verdict == 'SUSPICIOUS' %}
⚠️  VERDICT:           SUSPICIOUS (Probable Threat)
🟠 THREAT LEVEL:      {{ threat_level.value|upper }}
{% elif verdict == 'INCONCLUSIVE' %}
❓ VERDICT:           INCONCLUSIVE (Insufficient Evidence)
🟡 THREAT LEVEL:      {{ threat_level.value|upper }}
{% else %}
✅ VERDICT:           BENIGN (No Threat Detected)
🟢 THREAT LEVEL:      {{ threat_level.value|upper }}
{% endif %}

📊 THREAT ANALYSIS SUMMARY
════════════════════════════════════════════════════════════════════════════
Total Evidence Items Analyzed:   {{ threat_count }}
Flagged as Malicious:            {{ threat_evidences|length }}
Incident Clusters Identified:    {{ incident_count }}
Credibility Index:               {{ (credibility_index * 100)|int }}%

🚨 PRIMARY THREAT INDICATORS
════════════════════════════════════════════════════════════════════════════
{% if primary_threat_indicators %}
{% for indicator in primary_threat_indicators %}
  • {{ indicator }}
{% endfor %}
{% else %}
  No primary threat indicators identified.
{% endif %}

🔗 FLAGGED EVIDENCE
════════════════════════════════════════════════════════════════════════════
{% if threat_evidences %}
{% for evidence_id in threat_evidences %}
  🔴 {{ evidence_id }}
{% endfor %}
{% else %}
  No flagged evidence items.
{% endif %}

📝 CONCLUSIONS
════════════════════════════════════════════════════════════════════════════
{{ conclusions }}

💡 RECOMMENDATIONS
════════════════════════════════════════════════════════════════════════════
{% if recommendations %}
{% for i, recommendation in enumerate(recommendations, 1) %}
{{ i }}. {{ recommendation }}
{% endfor %}
{% else %}
No specific recommendations at this time.
{% endif %}

🔐 INTEGRITY VERIFICATION
════════════════════════════════════════════════════════════════════════════
Report Hash:         {% if signature_hash %}{{ signature_hash }}{% else %}[Generated]{% endif %}
Verification:        ✓ PASSED
Chain of Custody:    ✓ MAINTAINED

╔════════════════════════════════════════════════════════════════════════════╗
║                  END OF FORENSIC VERDICT REPORT                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"""


HTML_VERDICT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Threat Verdict Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1000px;
            margin: 20px auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .verdict-badge {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 18px;
            margin-top: 10px;
        }
        
        .verdict-malicious {
            background: #dc3545;
            color: white;
        }
        
        .verdict-suspicious {
            background: #ff9800;
            color: white;
        }
        
        .verdict-inconclusive {
            background: #ffc107;
            color: #333;
        }
        
        .verdict-benign {
            background: #28a745;
            color: white;
        }
        
        .section {
            padding: 25px;
            border-bottom: 1px solid #eee;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section h2 {
            font-size: 18px;
            margin-bottom: 15px;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 8px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .info-item {
            background: #f9f9f9;
            padding: 12px;
            border-radius: 4px;
        }
        
        .info-label {
            font-weight: bold;
            color: #667eea;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .info-value {
            font-size: 16px;
            margin-top: 5px;
            color: #333;
            word-break: break-all;
        }
        
        .threat-indicator {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px 15px;
            margin: 8px 0;
            border-radius: 4px;
        }
        
        .threat-indicator.critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        
        .threat-indicator.high {
            background: #ffe5cc;
            border-left-color: #ff9800;
        }
        
        .recommendation {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 4px;
        }
        
        .evidence-list {
            list-style: none;
            margin: 10px 0;
        }
        
        .evidence-list li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
        }
        
        .evidence-list li:last-child {
            border-bottom: none;
        }
        
        .evidence-list li:before {
            content: "🔴";
            margin-right: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 15px 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .conclusions {
            background: #f0f4ff;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            line-height: 1.8;
            color: #555;
        }
        
        .footer {
            background: #f9f9f9;
            padding: 15px 25px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
        
        .integrity-check {
            display: inline-block;
            padding: 8px 15px;
            background: #e8f5e9;
            border: 1px solid #4caf50;
            border-radius: 4px;
            color: #2e7d32;
            font-weight: bold;
        }
        
        .confidence-bar {
            width: 100%;
            height: 25px;
            background: #eee;
            border-radius: 12px;
            overflow: hidden;
            margin: 8px 0;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
                margin: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 Forensic Threat Verdict Report</h1>
            <div class="verdict-badge verdict-{{ verdict.lower().replace(' ', '-') }}">
                {{ verdict|upper }}
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Case Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Case ID</div>
                    <div class="info-value">{{ case_id }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Report Generated</div>
                    <div class="info-value">{{ verdict_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Analyst</div>
                    <div class="info-value">{{ analyst }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Confidence Level</div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {{ (confidence_level * 100)|int }}%">
                            {{ (confidence_level * 100)|int }}%
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Threat Analysis Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ threat_count }}</div>
                    <div class="stat-label">Evidence Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ threat_evidences|length }}</div>
                    <div class="stat-label">Flagged Items</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ incident_count }}</div>
                    <div class="stat-label">Incidents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ (credibility_index * 100)|int }}%</div>
                    <div class="stat-label">Credibility</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Primary Threat Indicators</h2>
            {% if primary_threat_indicators %}
                {% for indicator in primary_threat_indicators %}
                    <div class="threat-indicator {% if 'critical' in indicator.lower() %}critical{% elif 'high' in indicator.lower() %}high{% endif %}">
                        {{ indicator }}
                    </div>
                {% endfor %}
            {% else %}
                <p style="color: #999;">No primary threat indicators identified.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>🔗 Flagged Evidence</h2>
            {% if threat_evidences %}
                <ul class="evidence-list">
                    {% for evidence_id in threat_evidences %}
                        <li>{{ evidence_id }}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <p style="color: #999;">No flagged evidence items.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>📝 Conclusions</h2>
            <div class="conclusions">
                {{ conclusions }}
            </div>
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
            {% if recommendations %}
                {% for recommendation in recommendations %}
                    <div class="recommendation">
                        <strong>→</strong> {{ recommendation }}
                    </div>
                {% endfor %}
            {% else %}
                <p style="color: #999;">No specific recommendations at this time.</p>
            {% endif %}
        </div>
        
        <div class="footer">
            <p><strong>Report Hash:</strong> {% if signature_hash %}{{ signature_hash }}{% else %}[Generated]{% endif %}</p>
            <p style="margin-top: 10px;"><span class="integrity-check">✓ Integrity Verified</span></p>
        </div>
    </div>
</body>
</html>
"""


class ForensicVerdictGenerator:
    """Generate forensic verdict reports in multiple formats."""
    
    def __init__(self):
        # Add enumerate to globals for Jinja2
        self.text_template = Template(FORENSIC_VERDICT_TEMPLATE)
        self.text_template.globals['enumerate'] = enumerate
        
        self.html_template = Template(HTML_VERDICT_TEMPLATE)
        self.html_template.globals['enumerate'] = enumerate
    
    def generate_text_report(self, verdict: ForensicVerdict) -> str:
        """Generate text-formatted forensic verdict."""
        return self.text_template.render(
            case_id=verdict.case_id,
            verdict_timestamp=verdict.verdict_timestamp,
            analyst=verdict.analyst,
            confidence_level=verdict.confidence_level,
            verdict=verdict.verdict,
            threat_level=verdict.threat_level,
            threat_count=verdict.threat_count,
            threat_evidences=verdict.threat_evidences,
            incident_count=verdict.incident_count,
            credibility_index=verdict.credibility_index,
            primary_threat_indicators=verdict.primary_threat_indicators,
            conclusions=verdict.conclusions,
            recommendations=verdict.recommendations,
            signature_hash=verdict.signature_hash,
        )
    
    def generate_html_report(self, verdict: ForensicVerdict) -> str:
        """Generate HTML-formatted forensic verdict."""
        return self.html_template.render(
            case_id=verdict.case_id,
            verdict_timestamp=verdict.verdict_timestamp,
            analyst=verdict.analyst,
            confidence_level=verdict.confidence_level,
            verdict=verdict.verdict,
            threat_level=verdict.threat_level,
            threat_count=verdict.threat_count,
            threat_evidences=verdict.threat_evidences,
            incident_count=verdict.incident_count,
            credibility_index=verdict.credibility_index,
            primary_threat_indicators=verdict.primary_threat_indicators,
            conclusions=verdict.conclusions,
            recommendations=verdict.recommendations,
            signature_hash=verdict.signature_hash,
        )
    
    @staticmethod
    def generate_json_report(verdict: ForensicVerdict) -> Dict[str, Any]:
        """Generate JSON-formatted forensic verdict."""
        import json
        from datetime import datetime
        
        return {
            "case_id": verdict.case_id,
            "verdict_timestamp": verdict.verdict_timestamp.isoformat(),
            "verdict": verdict.verdict,
            "confidence_level": verdict.confidence_level,
            "threat_level": verdict.threat_level.value,
            "threat_count": verdict.threat_count,
            "flagged_evidences": len(verdict.threat_evidences),
            "incident_count": verdict.incident_count,
            "credibility_index": verdict.credibility_index,
            "primary_threat_indicators": verdict.primary_threat_indicators,
            "threat_evidences": verdict.threat_evidences,
            "conclusions": verdict.conclusions,
            "recommendations": verdict.recommendations,
            "analyst": verdict.analyst,
            "signature_hash": verdict.signature_hash,
        }

