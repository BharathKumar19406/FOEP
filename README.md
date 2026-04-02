# 🕵️‍♂️ Forensic OSINT-to-Evidence Pipeline (FOEP)

**Automated Multi-Source OSINT Collection, Correlation, and Reporting for Digital Forensics**

---

## 📌 Overview

FOEP is a comprehensive forensic framework that automates the collection, correlation, and reporting of open-source intelligence (OSINT) and digital forensics evidence from multiple public sources. It transforms raw data into structured, court-ready evidence with credibility scoring and knowledge graph visualization.

### ✨ Key Features
- **Multi-Source Collection**: GitHub, Twitter, Domain DNS, HIBP Breaches, IP Geolocation, VirusTotal, Shodan, Archive.org
- **Forensic Integration**: Disk image analysis, Memory dumps, System logs
- **Digital Forensics**: File hashing, Artifact extraction, Timeline analysis
- **🚨 Automated Threat Detection**: AbuseIPDB, OTX, and Shodan intelligence parsing with threat scoring
- **Threat Intelligence Correlation**: Neo4j-based incident node creation and threat actor linkage
- **Forensic Verdict Generation**: Automated malicious entity flagging with confidence scoring and recommendations
- **Credibility Scoring**: Evidence weighted by source reliability
- **Knowledge Graph**: Neo4j-based entity correlation and link analysis
- **Court-Ready Reports**: HTML/PDF output with redacted sensitive fields and threat analysis
- **Chain of Custody**: Automated documentation of evidence handling
- **Ethical Compliance**: Uses only public APIs and authorized forensic analysis — no unauthorized access

---

## 🚀 Quick Start

```bash
# Setup development environment
git clone https://github.com/yourusername/FOEP.git
cd FOEP
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python -m pytest tests/unit/test_normalize.py -v
python run_all_tests.py

# Install Neo4j (optional but recommended)
sudo apt install neo4j -y
sudo neo4j-admin dbms set-initial-password neo4j
sudo systemctl start neo4j

# Run full forensic pipeline
foep-ingest \
  --social "github:trailofbits" \
  --social "twitter:jack" \
  --domain "microsoft.com" \
  --breach "account-exists@hibp-integration-tests.com" \
  --output evidence.json \
  --case-id DEMO-2026

foep-correlate --input evidence.json --output correlated.json --case-id DEMO-2026
foep-report --input correlated.json --output reports/ --case-id DEMO-2026 --format html
```

---

## 📦 Installation & Development Setup from Scratch

### System Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS, or Windows (WSL2)
- **Python**: 3.10 or higher
- **Git**: Latest version
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 2GB minimum
- **Neo4j**: 5.x (optional but recommended for graph correlation)

### Step-by-Step Complete Setup

#### **Phase 1: System Prerequisites**

##### Linux/Ubuntu Setup
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3.10 python3.10-venv python3-pip git curl wget

# Verify installations
python3 --version
git --version
```

##### macOS Setup
```bash
# Install using Homebrew (if not installed, visit https://brew.sh)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.10 git

# Verify installations
python3 --version
git --version
```

##### Windows (WSL2) Setup
```bash
# Open PowerShell as Administrator
# Install WSL2: wsl --install
# Then in WSL Ubuntu terminal:
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git
```

#### **Phase 2: Repository Setup**

```bash
# 1. Clone repository
git clone https://github.com/BharathKumar19406/FOEP.git
cd FOEP

# 2. Verify repository structure
ls -la
# Should show: src/, scripts/, tests/, config/, README.md, setup.py, requirements.txt

# 3. Check current branch (should be 'main')
git branch
```

#### **Phase 3: Virtual Environment Setup**

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# On Windows (cmd):
venv\Scripts\activate.bat

# 3. Verify activation (should show (venv) prefix)
which python  # or 'where python' on Windows
```

#### **Phase 4: Install Dependencies**

```bash
# 1. Upgrade pip, setuptools, wheel to latest versions
pip install --upgrade pip setuptools wheel

# 2. Install all project dependencies
pip install -r requirements.txt

# 3. (Optional) Install development/testing tools
pip install -r requirements-dev.txt

# 4. Install package in development mode (editable)
pip install -e .

# 5. Verify installation
pip list | grep -E "pydantic|neo4j|pytest|jinja2"
```

#### **Phase 5: Verify Installation**

```bash
# 1. Check Python packages
python -c "import foep; print('✅ FOEP imported successfully')"

# 2. Run quick test
python -m pytest tests/unit/test_normalize.py::TestEvidenceSchema::test_valid_evidence_creation -v

# 3. Expected output: "PASSED"
```

#### **Phase 6: (Optional) Neo4j Setup**

##### Docker-based Neo4j (Recommended)
```bash
# 1. Install Docker (visit https://docs.docker.com/get-docker/)

# 2. Start Neo4j container
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/foep-password \
  neo4j:5

# 3. Wait for startup (30 seconds)
sleep 30

# 4. Verify connection
curl http://localhost:7474

# 5. Access Neo4j Browser
# Open: http://localhost:7474
# Login: neo4j / foep-password
```

##### System Neo4j Installation (Ubuntu)
```bash
# Add Neo4j repository
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list

# Install
sudo apt update
sudo apt install -y neo4j

# Start service
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Set password
sudo neo4j-admin set-initial-password foep-password

# Restart
sudo systemctl restart neo4j
```

#### **Phase 7: Configure Application**

```bash
# 1. Edit configuration file
cp config/config.yaml.example config/config.yaml  # if example exists
# OR
nano config/config.yaml

# 2. Update config/config.yaml with your settings:
```

```yaml
# Neo4j Connection
neo4j:
  enabled: true
  uri: "bolt://localhost:7687"
  username: "neo4j"
  password: "foep-password"

# Threat Intelligence Sources
threat_intel:
  abuseipdb:
    enabled: true
    api_key: "YOUR_ABUSEIPDB_KEY"  # Optional
  
  otx:
    enabled: true
    api_key: "YOUR_OTX_KEY"  # Optional
  
  shodan:
    enabled: true
    api_key: "YOUR_SHODAN_KEY"  # Optional

# OSINT Sources  
github:
  enabled: true
  api_key: "" # Optional

twitter:
  enabled: true
  api_key: "" # Optional

virustotal:
  enabled: false
  api_key: "YOUR_VIRUSTOTAL_KEY"
```

#### **Phase 8: Run Tests to Verify Complete Setup**

```bash
# 1. Run all unit tests
python -m pytest tests/unit/ -v

# 2. Run threat detection tests
python -m pytest tests/unit/ -k threat -v

# 3. Check test coverage
python -m pytest tests/ --cov=src/foep --cov-report=term-missing

# 4. Expected result: All tests should PASS ✅
```

---

## 🚀 Quick Verification After Setup

```bash
# Verify your installation is complete
bash << 'EOF'
echo "" && echo "=== FOEP Installation Verification ==="
echo ""
echo "✓ Python Version:"
python --version
echo ""
echo "✓ Virtual Environment:"
echo "Location: $(which python)"
echo ""
echo "✓ Key Packages:"
pip list | grep -E "foep|pydantic|neo4j|pytest|jinja2"
echo ""
echo "✓ Project Structure:"
ls -d src/foep/*/
echo ""
echo "✓ Running smoke test..."
python -m pytest tests/unit/test_normalize.py -q
echo ""
echo "=== Setup Complete! ==="
EOF
```

---

## 🧪 Testing

### Run All Tests
```bash
# Using pytest
python -m pytest tests/ -v

# Or use the provided test runner
python run_all_tests.py

# With coverage
python -m pytest tests/ --cov=src/foep --cov-report=html
```

### Run Specific Test Suites
```bash
# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests  
python -m pytest tests/integration/ -v

# Specific test file
python -m pytest tests/unit/test_normalize.py -v
```

---

## 📂 Project Structure

```
FOEP/
├── src/foep/                  # Main package
│   ├── core/                 # Core pipeline
│   │   ├── config.py        # Configuration management
│   │   └── pipeline.py      # Main orchestration
│   ├── ingest/              # Data collection
│   │   ├── forensic/        # Disk, memory, logs
│   │   └── osint/           # GitHub, Twitter, etc.
│   ├── normalize/           # Schema & transformation
│   │   ├── schema.py        # Evidence schema
│   │   └── hash_utils.py    # Hash operations
│   ├── correlate/           # Graph correlation
│   │   ├── graph_db.py      # Neo4j integration
│   │   └── linker.py        # Entity linking
│   ├── threat/              # 🚨 THREAT DETECTION
│   │   ├── threat_schema.py # Threat intelligence models
│   │   ├── threat_parser.py # AbuseIPDB, OTX, Shodan parsers
│   │   ├── threat_correlation.py  # Neo4j incident correlation
│   │   └── forensic_verdict_template.py  # Verdict generation
│   ├── report/              # Report generation
│   │   ├── generator.py     # Report builder
│   │   └── redactor.py      # Sensitive data redaction
│   └── credibility/         # Score calculation
├── scripts/                  # CLI entry points
│   ├── foep_ingest.py       # Data collection CLI
│   ├── foep_correlate.py    # Correlation CLI
│   ├── foep_report.py       # Report generation CLI
│   └── threat_detection_demo.py  # 🚨 Threat detection demo
├── tests/                   # Test suite
│   ├── unit/               # Unit tests (17 passing)
│   └── integration/        # Integration tests
├── threat_detection_results/  # 🚨 Demo output files
├── dashboard/              # Web dashboard (optional)
├── config/                 # Configuration files
└── README.md              # This file
```

---

## 🧪 Usage Examples

### Basic OSINT Collection
```bash
# Single source
foep-ingest --domain "example.com" --output domain.json

# Multi-source
foep-ingest \
  --social "github:user123" \
  --social "twitter:user123" \
  --breach "user@example.com" \
  --output osint.json
```

### Full Forensic Pipeline
```bash
# 1. Collect evidence
foep-ingest \
  --social "github:trailofbits" \
  --social "twitter:jack" \
  --domain "microsoft.com" \
  --breach "account-exists@hibp-integration-tests.com" \
  --output evidence.json \
  --case-id FORENSIC-2026

# 2. Correlate entities
foep-correlate --input evidence.json --output correlated.json --case-id FORENSIC-2026

# 3. Generate report
foep-report --input correlated.json --output reports/ --case-id FORENSIC-2026 --format html
```

### View Knowledge Graph
1. Open [http://localhost:7474](http://localhost:7474)
2. Login: `neo4j` / `neo4j`
3. Run query:
   ```cypher
   MATCH (e:Evidence) RETURN e
   ```


---

## 🏗️ Architecture

```
CLI → Ingestion → Normalization → Correlation → Reporting
          │            │             │            │
          ▼            ▼             ▼            ▼
      GitHub       Evidence      Knowledge     HTML/PDF
      Twitter      Schema         Graph        Report
      Domain                     (Neo4j)
      Breach
```

### Core Components
- **Ingestion**: Collects raw data from OSINT sources
- **Normalization**: Converts to `Evidence` schema with credibility scores
- **Correlation**: Links related entities using Neo4j
- **Reporting**: Generates redacted, court-ready outputs

---

## 🚨 Threat Detection Pipeline (NEW)

### Overview
Automated threat detection and forensic verdict generation from multiple threat intelligence sources.

### Threat Detection Stages

#### **Stage 1: Threat Intelligence Parsing**
Parses threat data from three major threat sources with confidence scoring:

| Source | Entity Type | Threat Level Mapping | Output |
|--------|-------------|----------------------|--------|
| **AbuseIPDB** | IPv4/IPv6 | Confidence 0-100 → CRITICAL/HIGH/MEDIUM | Abuse reports, GeoIP, indicators |
| **OTX (Alienvault) ** | Domains, IPs, Hashes | Verdict → Threat level + Campaigns | Threat campaigns, behavioral analysis |
| **Shodan** | Infrastructure IPs | Service Risk Score | Exposed services, versions, recommendations |

**Example:**
```python
from src.foep.threat.threat_parser import AbuseIPDBParser, OTXParser, ShodanParser
from src.foep.normalize.schema import Evidence

# Create evidence
evidence = Evidence(
    evidence_id="abuseipdb::ip::192.168.1.100",
    entity_type="ip_address",
    entity_value="192.168.1.100",
    observation_type="threat_intel",
    source="abuseipdb"
)

# Parse threats
parser = AbuseIPDBParser()
threat_intel = parser.parse(evidence, abuse_data={
    "abuseConfidenceScore": 92,
    "totalReports": 3,
    "reports": [...]
})

print(f"Threat Level: {threat_intel.threat_level}")  # CRITICAL
print(f"Score: {threat_intel.threat_score}")  # 92.0
```

#### **Stage 2: Incident Correlation**
Creates Neo4j Incident nodes and links malicious entities:

```python
from src.foep.threat.threat_correlation import ThreatCorrelationEngine

engine = ThreatCorrelationEngine()

# Create incident from threat
incident = engine.create_incident_from_threat(threat_intel, case_id="FORENSIC-2024-001")

# Generate Neo4j Cypher queries
cypher_queries = engine.build_incident_graph_query([incident])

# Correlate incidents to find patterns
patterns = engine.correlate_incidents([incident1, incident2, incident3])
```

**Output:** Neo4j Incident nodes with relationships:
- `Incident` → `INVOLVES` → `Evidence`
- `Incident` → `PERPETRATED_BY` → `ThreatActor`
- `Incident` → `RELATED_TO` → `Incident`

#### **Stage 3: Forensic Verdict Generation**
Automated verdict with conclusions and recommendations:

```python
from src.foep.threat.forensic_verdict_template import ForensicVerdictGenerator
from src.foep.threat.threat_schema import ForensicVerdict

verdict = ForensicVerdict(
    verdict="MALICIOUS",
    confidence_level=92,
    threat_evidences=threats,
    conclusions="2 malicious entities identified across 3 evidence items",
    recommendations=["Block IPs immediately", "Monitor for campaigns", ...]
)

generator = ForensicVerdictGenerator()
html_report = generator.render_html_report(verdict)
text_report = generator.render_text_report(verdict)
json_report = generator.render_json_report(verdict)
```

### Run Threat Detection Demo

```bash
# Execute full threat detection pipeline with sample data
cd /workspaces/FOEP
python scripts/threat_detection_demo.py

# Output files will be generated in threat_detection_results/:
# - threat_intelligence.json     (Parsed threats from all 3 sources)
# - incidents_correlation.json   (Neo4j incidents created)
# - neo4j_queries.cypher         (Cypher DDL for Neo4j graph)
# - verdict_report.html          (Interactive HTML verdict)
# - verdict_report.json          (Machine-readable verdict)
# - verdict_textreport.txt       (ASCII formatted verdict)

# View generated files
ls -lh threat_detection_results/

# View text report
cat threat_detection_results/verdict_textreport.txt

# View HTML report (open in browser)
open threat_detection_results/verdict_report.html  # macOS
xdg-open threat_detection_results/verdict_report.html  # Linux
start threat_detection_results/verdict_report.html  # Windows
```

### Integration with Main Pipeline

```bash
# Full forensic pipeline with threat detection
foep-ingest --social "github:user" --output evidence.json
foep-correlate --input evidence.json --output correlated.json
foep-report --input correlated.json --with-threats --output reports/
```

### Threat Schema Models

```python
class ThreatLevel(str, Enum):
    CRITICAL = "critical"     # Immediate action required
    HIGH = "high"            # Urgent investigation
    MEDIUM = "medium"        # Important but not immediate
    LOW = "low"              # Monitor
    INFO = "info"            # Informational
    BENIGN = "benign"        # No threat

class ThreatIntelligence(BaseModel):
    evidence_id: str
    entity_value: str
    threat_level: ThreatLevel
    threat_score: float  # 0-100
    is_malicious: bool
    indicators: List[ThreatIndicator]
    sources: Dict[str, str]

class IncidentNode(BaseModel):
    incident_id: str
    case_id: str
    incident_type: str  # malware_infection, phishing_campaign, etc.
    severity_score: float
    affected_entities: List[str]
    threat_actors: List[str]
    recommended_actions: List[str]

class ForensicVerdict(BaseModel):
    verdict: str  # MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE
    confidence_level: int  # 0-100%
    threat_evidences: List[ThreatIntelligence]
    conclusions: str
    recommendations: List[str]
```

---

## 🎯 Generate Sample Reports

### Create Sample Evidence

```bash
# Create a sample evidence JSON file
cat > sample_evidence.json << 'EOF'
{
  "evidence_id": "sample::osint::001",
  "entity_type": "username",
  "entity_value": "example-user",
  "observation_type": "osint_social",
  "source": "github",
  "metadata": {
    "name": "Example User",
    "public_repos": 42,
    "followers": 250,
    "created_at": "2020-01-15"
  },
  "credibility_score": 85,
  "case_id": "SAMPLE-2026"
}
EOF
```

### Run Forensic Pipeline

```bash
# 1. Normalize evidence
foep-ingest --input sample_evidence.json --output normalized.json

# 2. Correlate entities
foep-correlate --input normalized.json --output correlated.json --case-id SAMPLE-2026

# 3. Generate report
foep-report --input correlated.json --output reports/ --case-id SAMPLE-2026 --format html

# 4. View generated reports
ls -lh reports/
```

### Run Full Threat Detection Pipeline

```bash
# Run with threat detection enabled
foep-report --input correlated.json --output reports/ --with-threats --case-id SAMPLE-2026

# Generated report will include:
# ✅ Threat intelligence analysis
# ✅ Neo4j incident nodes
# ✅ Forensic verdict (MALICIOUS/SUSPICIOUS/BENIGN)
# ✅ Confidence scoring
# ✅ Actionable recommendations
```

---

## ⚙️ Configuration

Edit `config/config.yaml`:

```yaml
# Enable/disable sources
github:
  enabled: true

twitter:
  enabled: true

# API keys (optional)
virustotal:
  enabled: false
  api_key: ""

# Neo4j connection
neo4j:
  uri: "bolt://localhost:7687"
  username: "neo4j"
  password: "neo4j"
```

---

## 🛡️ Ethical Compliance

FOEP adheres to strict ethical guidelines:
- ✅ Only uses **publicly available data**
- ✅ Respects **robots.txt** and **rate limits**
- ✅ No credential harvesting or private data access
- ✅ Compliant with **GDPR** and **CCPA** for public data

---

## 📚 References

- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [Neo4j Graph Data Modeling](https://neo4j.com/developer/guide-data-modeling/)
- [OSINT Framework](https://osintframework.com/)


## 🙏 Acknowledgements

- Troy Hunt for [Have I Been Pwned](https://haveibeenpwned.com/)
- Trail of Bits for public GitHub presence
- Neo4j for open-source graph database

