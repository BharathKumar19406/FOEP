# src/foep/report/generator.py

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML, CSS

from foep.normalize.schema import Evidence
from foep.report.redactor import Redactor
from foep.report.custody import ChainOfCustody

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates court-admissible forensic reports from Evidence objects.

    Produces PDF/HTML with redaction, custody metadata, and credibility context.
    """

    def __init__(
        self,
        template_dir: Optional[Union[str, Path]] = None,
        redactor: Optional[Redactor] = None,
        neo4j_uri: Optional[str] = None,
    ):
        """
        Initialize report generator.

        Args:
            template_dir: Directory containing Jinja2 templates (default: built-in)
            redactor: Redactor instance for PII removal
            neo4j_uri: Neo4j URI for embedded graph links (optional)
        """
        self.neo4j_uri = neo4j_uri
        self.redactor = redactor or Redactor(
            redact_emails=False
        )  # Default: minimal redaction

        # Set up Jinja2 environment
        if template_dir:
            template_path = Path(template_dir).resolve()
            if not template_path.exists():
                raise ValueError(f"Template directory not found: {template_path}")
            loader = FileSystemLoader(str(template_path))
        else:
            # Use built-in templates
            loader = FileSystemLoader(str(Path(__file__).parent / "templates"))

        self.env = Environment(
            loader=loader,
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_report(
        self,
        evidence_list: List[Evidence],
        output_path: Union[str, Path],
        case_info: Dict[str, Any],
        custody: Optional[ChainOfCustody] = None,
        format: str = "pdf",
    ) -> str:
        """
        Generate a forensic report in specified format.

        Args:
            evidence_list: List of Evidence objects
            output_path: Output file path (e.g., "report.pdf")
            case_info: Case metadata {"title", "description", "investigator", etc.}
            custody: ChainOfCustody instance (optional)
            format: "pdf" or "html"

        Returns:
            Absolute path to generated report.
        """
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Apply redaction
        redacted_evidence = [self.redactor.redact_evidence(ev) for ev in evidence_list]

        # Prepare report context
        context = self._build_report_context(redacted_evidence, case_info, custody)

        # Render template
        if format.lower() == "html":
            return self._render_html(context, output_path)
        elif format.lower() == "pdf":
            return self._render_pdf(context, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}. Use 'pdf' or 'html'.")

    # ✅ SANITIZE METHOD: MUST BE AT CLASS LEVEL (NOT NESTED)
    def _sanitize_evidence_metadata(self, evidence_list: List[Evidence]) -> List[Evidence]:
        """
        Remove chain_of_custody and internal scoring fields from evidence for external reports.
        Preserves forensic integrity in database/JSON.
        """
        sanitized = []
        for ev in evidence_list:
            clean_meta = dict(ev.metadata)
            # ✅ Remove sensitive/internal fields
            clean_meta.pop("chain_of_custody", None)
            clean_meta.pop("credibility_adjustments", None)
            clean_meta.pop("original_credibility_score", None)
            # Optional: also remove raw timestamps if desired
            # clean_meta.pop("created_at", None)
            
            sanitized.append(
                Evidence(
                    evidence_id=ev.evidence_id,
                    entity_type=ev.entity_type,
                    entity_value=ev.entity_value,
                    observation_type=ev.observation_type,
                    source=ev.source,
                    metadata=clean_meta,
                    credibility_score=ev.credibility_score,
                    sha256_hash=ev.sha256_hash,
                )
            )
        return sanitized

    def _build_report_context(
        self,
        evidence_list: List[Evidence],
        case_info: Dict[str, Any],
        custody: Optional[ChainOfCustody],
    ) -> Dict[str, Any]:
        """Build context dictionary for Jinja2 template."""
        
        # ✅ SANITIZE BEFORE PROCESSING
        evidence_list = self._sanitize_evidence_metadata(evidence_list)

        # Group evidence by observation type
        evidence_by_type = {}
        for ev in evidence_list:
            obs_type = ev.observation_type.value
            if obs_type not in evidence_by_type:
                evidence_by_type[obs_type] = []
            evidence_by_type[obs_type].append(ev)

        # Extract unique entities for summary
        unique_entities = set()
        for ev in evidence_list:
            unique_entities.add((ev.entity_type.value, ev.entity_value))

        # Build Neo4j exploration URL if available
        neo4j_url = None
        if self.neo4j_uri:
            uri_parts = self.neo4j_uri.replace("bolt://", "").replace("neo4j://", "")
            neo4j_url = f"https://neo4j.com/browser/?db={quote(uri_parts)}#"

        return {
            "case_info": case_info,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "evidence_summary": {
                "total_items": len(evidence_list),
                "unique_entities": len(unique_entities),
                "observation_types": list(evidence_by_type.keys()),
                "high_credibility_count": sum(
                    1 for ev in evidence_list if ev.credibility_score >= 80
                ),
            },
            "evidence_by_type": evidence_by_type,
            "custody_info": custody.__dict__ if custody else None,
            "neo4j_explorer_url": neo4j_url,
            "tool_info": {
                "name": "Forensic OSINT-to-Evidence Pipeline (FOEP)",
                "version": self._get_tool_version(),
            },
        }

    def _render_html(self, context: Dict[str, Any], output_path: Path) -> str:
        """Render HTML report."""
        template = self.env.get_template("report.html")
        html_content = template.render(**context)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report saved to: {output_path}")
        return str(output_path)

    def _render_pdf(self, context: Dict[str, Any], output_path: Path) -> str:
        """Render PDF report using WeasyPrint."""
        template = self.env.get_template("report.html")
        html_content = template.render(**context)

        # Add CSS for print-friendly PDF
        css_path = Path(__file__).parent / "templates" / "report.css"
        css = CSS(filename=str(css_path)) if css_path.exists() else None

        HTML(string=html_content).write_pdf(
            str(output_path), stylesheets=[css] if css else None
        )

        logger.info(f"PDF report saved to: {output_path}")
        return str(output_path)

    def _get_tool_version(self) -> str:
        """Get FOEP version."""
        try:
            from foep import __version__
            return __version__
        except ImportError:
            return "unknown"


# --- BUILT-IN TEMPLATES ---
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_DIR.mkdir(exist_ok=True)

# Default HTML template (updated to avoid raw JSON)
_REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ case_info.title }} - FOEP Forensic Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .case-info { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .evidence-item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .credibility-high { border-left: 4px solid #28a745; }
        .credibility-medium { border-left: 4px solid #ffc107; }
        .credibility-low { border-left: 4px solid #dc3545; }
        .metadata { font-size: 0.9em; color: #555; margin-top: 8px; }
        .custody { background: #e9ecef; padding: 15px; margin-top: 30px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .meta-value { word-break: break-word; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Forensic OSINT-to-Evidence Pipeline (FOEP)</h1>
        <h2>{{ case_info.title }}</h2>
        <p>Generated on: {{ generated_at }}</p>
    </div>

    <div class="case-info">
        <h3>Case Information</h3>
        <p><strong>Description:</strong> {{ case_info.description }}</p>
        <p><strong>Investigator:</strong> {{ case_info.investigator }}</p>
        {% if case_info.case_id %}<p><strong>Case ID:</strong> {{ case_info.case_id }}</p>{% endif %}
    </div>

    <div class="summary">
        <h3>Evidence Summary</h3>
        <p>Total Items: {{ evidence_summary.total_items }}</p>
        <p>Unique Entities: {{ evidence_summary.unique_entities }}</p>
        <p>High-Credibility Items (≥80): {{ evidence_summary.high_credibility_count }}</p>
        {% if neo4j_explorer_url %}
        <p><a href="{{ neo4j_explorer_url }}" target="_blank">Explore Evidence Graph in Neo4j Browser</a></p>
        {% endif %}
    </div>

    {% for obs_type, items in evidence_by_type.items() %}
    <h3>{{ obs_type.replace('_', ' ').title() }} ({{ items|length }})</h3>
    {% for item in items %}
    <div class="evidence-item 
        {% if item.credibility_score >= 80 %}credibility-high
        {% elif item.credibility_score >= 50 %}credibility-medium
        {% else %}credibility-low{% endif %}">
        <p><strong>Entity:</strong> {{ item.entity_value }}</p>
        <p><strong>Type:</strong> {{ item.entity_type.value }}</p>
        <p><strong>Source:</strong> {{ item.source }}</p>
        <p><strong>Credibility:</strong> {{ item.credibility_score }}/100</p>
        {% if item.metadata %}
        <div class="metadata">
            <strong>Meta</strong>
            <table>
                {% for key, value in item.metadata.items() %}
                <tr>
                    <td>{{ key|replace('_', ' ')|title }}</td>
                    <td class="meta-value">
                        {# ✅ Clean rendering: avoid raw JSON #}
                        {% if value is none %}
                            <em>null</em>
                        {% elif value is string and value|length > 100 %}
                            {{ value[:100] }}...
                        {% elif value is mapping or value is iterable and value is not string %}
                            <code>{{ value|tojson|truncate(200) }}</code>
                        {% else %}
                            {{ value }}
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
    </div>
    {% endfor %}
    {% endfor %}

    {% if custody_info %}
    <div class="custody">
        <h3>Chain of Custody</h3>
        <p><strong>Investigator:</strong> {{ custody_info.investigator }}</p>
        <p><strong>Organization:</strong> {{ custody_info.organization }}</p>
        <p><strong>Tool:</strong> {{ tool_info.name }} v{{ tool_info.version }}</p>
        <p><strong>Generated At:</strong> {{ custody_info.custody_timestamp }}</p>
    </div>
    {% endif %}
</body>
</html>
"""

# Write default template
_REPORT_HTML_PATH = _TEMPLATE_DIR / "report.html"
if not _REPORT_HTML_PATH.exists():
    with open(_REPORT_HTML_PATH, "w") as f:
        f.write(_REPORT_HTML)

# Default CSS
_REPORT_CSS = """
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}
.header {
    border-bottom: 3px solid #0056b3;
    padding-bottom: 20px;
    margin-bottom: 30px;
}
.header h1 {
    color: #0056b3;
    margin-bottom: 5px;
}
.evidence-item {
    margin: 15px 0;
    padding: 15px;
    border-radius: 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.credibility-high {
    border-left: 5px solid #28a745;
    background-color: #f8fff9;
}
.credibility-medium {
    border-left: 5px solid #ffc107;
    background-color: #fffaf5;
}
.credibility-low {
    border-left: 5px solid #dc3545;
    background-color: #fff5f5;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}
th, td {
    border: 1px solid #dee2e6;
    padding: 10px;
    text-align: left;
}
th {
    background-color: #e9ecef;
    font-weight: 600;
}
.custody {
    background-color: #f8f9fa;
    border: 1px solid #dee2e6;
    border-radius: 6px;
    padding: 20px;
    margin-top: 30px;
}
.meta-value {
    font-family: monospace;
    font-size: 0.9em;
    white-space: pre-wrap;
}
"""

_REPORT_CSS_PATH = _TEMPLATE_DIR / "report.css"
if not _REPORT_CSS_PATH.exists():
    with open(_REPORT_CSS_PATH, "w") as f:
        f.write(_REPORT_CSS)
