# 🕵️‍♂️ FOEP - Forensic OSINT-to-Evidence Pipeline

**Automated Multi-Source OSINT Collection, Threat Analysis, Correlation, and Court-Ready Reporting for Digital Forensics**

---

## 📌 About

FOEP is an end-to-end forensic framework that automates:
- **Collection**: Gathers evidence from forensic artifacts (disk, memory, logs) and 10+ OSINT sources
- **Threat Detection**: Identifies malicious activity through integrated threat intelligence
- **Correlation**: Links entities and discovers relationships using Neo4j knowledge graphs
- **Analysis**: Generates forensic verdicts with threat scoring and recommendations
- **Reporting**: Creates court-admissible reports with chain of custody documentation

Perfect for forensic analysts who need to quickly gather data from multiple sources, detect threats, and generate comprehensive investigation reports.

### ✨ Key Features
- ✅ **Forensic Integration**: Disk images, memory dumps, system logs
- ✅ **10+ OSINT Sources**: GitHub, Twitter, Domains, HIBP, IP Geolocation, VirusTotal, Shodan, Archive.org, Code Repos, Breaches
- ✅ **Real-Time Threat Detection**: 6+ threat detector types (malware, phishing, botnet, persistence, LOLBin)
- ✅ **Multi-Source Intelligence**: AbuseIPDB, OTX, Shodan, VirusTotal, Local DB, Emerging Threats
- ✅ **Knowledge Graph**: Neo4j-based entity correlation and incident visualization
- ✅ **Threat Analysis**: Automated malicious entity identification with confidence scoring
- ✅ **Credibility Scoring**: Evidence weighted by source reliability and corroboration
- ✅ **Court-Ready Reports**: HTML/PDF with forensic verdict, threat analysis, and full chain of custody
- ✅ **Redaction**: PII protection (emails, IPs, names, usernames)
- ✅ **Ethical Compliance**: Only public APIs and authorized forensic analysis

---

## 🚀 Installation & Setup Guide

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|------------|
| **OS** | Ubuntu 18.04, macOS 10.14, Windows 10 WSL2 | Ubuntu 20.04+, macOS 11+, Windows 11 WSL2 |
| **Python** | 3.8 | 3.10+ |
| **RAM** | 4GB | 8GB+ |
| **Disk Space** | 2GB | 5GB+ |
| **Neo4j** | 4.4 (optional) | 5.x (docker) |

### Step 1: Clone Repository

```bash
# Clone the project
git clone https://github.com/BharathKumar19406/FOEP.git
cd FOEP

# Verify structure
ls -la
# Expected: src/, scripts/, tests/, config/, setup.py, requirements.txt, requirements-dev.txt
```

### Step 2: Install System Dependencies

#### **On Ubuntu/Debian:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.10 python3.10-venv python3-pip git curl wget
python3.10 --version  # Verify Python 3.10
```

#### **On macOS:**
```bash
# Install Homebrew if needed: https://brew.sh
brew install python@3.10 git
python3 --version  # Should show 3.10+
```

#### **On Windows (PowerShell as Admin):**
```powershell
# Install WSL2 environment
wsl --install

# Then in WSL Ubuntu terminal:
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On Linux/macOS:
source venv/bin/activate

# On Windows (PowerShell):
venv\Scripts\Activate.ps1
# On Windows (cmd.exe):
venv\Scripts\activate.bat

# Verify activation (should show (venv) prefix in terminal)
which python
```

### Step 4: Install Project Dependencies

```bash
# Upgrade pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Install all requirements
pip install -r requirements.txt

# (Optional) Install development dependencies for testing
pip install -r requirements-dev.txt

# Install package in development mode (enables CLI commands globally)
pip install -e .

# Verify installation
foep-ingest --help  # Should show CLI help without error
```

---

## 🎯 Quick Start: Using FOEP via CLI Commands

FOEP provides three main CLI commands for the complete forensic pipeline. **NO Python code changes needed!**

### Command 1: `foep-ingest` - Collect Evidence

Gather evidence from forensics, OSINT, and threat intelligence sources.

```bash
# Basic usage - GitHub evidence
foep-ingest \
  --social "github:username" \
  --output evidence.json \
  --case-id CASE-2024-001

# Full example with multiple sources
foep-ingest \
  --social "github:trailofbits" \
  --social "twitter:jack" \
  --breach "admin@company.com" \
  --domain "example.com" \
  --vt-hash "d41d8cd98f00b204e9800998ecf8427e" \
  --output evidence.json \
  --case-id FORENSIC-2024-001 \
  --investigator "John Doe" \
  --verbose

# With forensic artifacts
foep-ingest \
  --disk /path/to/image.E01 \
  --memory /path/to/memory.dump \
  --log /var/log/auth.log \
  --output forensic_evidence.json \
  --case-id CASE-2024-001 \
  --verbose
```

### Command 2: `foep-correlate` - Correlate & Analyze

Link entities, detect relationships, and identify threats.

```bash
# Basic correlation
foep-correlate \
  --input evidence.json \
  --output correlated.json \
  --case-id FORENSIC-2024-001

# With verbose output
foep-correlate \
  --input evidence.json \
  --output correlated.json \
  --case-id FORENSIC-2024-001 \
  --investigator "Jane Smith" \
  --verbose
```

### Command 3: `foep-report` - Generate Forensic Report

Create court-ready reports with threat analysis and chain of custody.

```bash
# Generate HTML report
foep-report \
  --input correlated.json \
  --output reports/ \
  --case-id FORENSIC-2024-001 \
  --format html \
  --title "Case Investigation Report" \
  --organization "Cyber Forensics Lab"

# Generate PDF report
foep-report \
  --input correlated.json \
  --output reports/ \
  --case-id FORENSIC-2024-001 \
  --format pdf \
  --title "Incident Response Report" \
  --description "Comprehensive threat analysis and evidence correlation" \
  --organization "SOC Team"
```

### Complete Pipeline Example

```bash
# Step 1: Collect evidence from multiple sources
foep-ingest \
  --social "github:attacker" \
  --domain "malicious.com" \
  --breach "suspect@email.com" \
  --output evidence.json \
  --case-id INVESTIGATION-2024 \
  --investigator "Security Team"

# Step 2: Correlate entities and detect threats
foep-correlate \
  --input evidence.json \
  --output correlated.json \
  --case-id INVESTIGATION-2024 \
  --verbose

# Step 3: Generate comprehensive report
foep-report \
  --input correlated.json \
  --output case_reports/ \
  --case-id INVESTIGATION-2024 \
  --format html \
  --title "Security Investigation Report" \
  --organization "Incident Response Team"

# Results:
# ✅ case_reports/report.html - Interactive forensic report
# ✅ case_reports/threat_summary.json - Threat analysis data
# ✅ case_reports/chain_of_custody.txt - Evidence chain of custody
echo "✅ Investigation complete! Check case_reports/ for all generated files"
```

---

## 🔧 Step 5: (Optional) Setup Neo4j for Graph Correlation

#### **Option A: Docker (Recommended)**
```bash
# Install Docker: https://docs.docker.com/get-docker/

# Start Neo4j container
docker run -d \
  --name foep-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/foep-password \
  neo4j:5.0

# Wait for startup
sleep 30

# Verify
curl http://localhost:7474
# Open browser: http://localhost:7474
# Login: neo4j / foep-password
```

#### **Option B: Ubuntu/Debian**
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
sudo neo4j-admin dbms set-initial-password foep-password
sudo systemctl restart neo4j
```

### Step 6: Configure Application

```bash
# Review/edit configuration
cat config/config.yaml

# Update config with your settings:
# - Neo4j connection details
# - Threat intelligence API keys (optional)
# - Redaction preferences
# - Case defaults
```

---

## 📦 Project Dependencies & Modules

### Core Python Packages

| Package | Version | Purpose |
|---------|---------|---------|
| **pydantic** | >=2.0.0 | Data validation and schema modeling |
| **PyYAML** | >=6.0.0 | Configuration file parsing |
| **requests** | >=2.28.0 | HTTP client for API calls |
| **Jinja2** | >=3.0.0 | Report templating engine |
| **beautifulsoup4** | >=4.12.0 | HTML parsing for OSINT |
| **lxml** | >=4.9.0 | XML/HTML processing |
| **neo4j** | >=5.0.0 | Neo4j graph database driver |

### Forensic Analysis Packages

| Package | Version | Purpose |
|---------|---------|---------|
| **dfvfs** | >=20240101 | Digital forensics virtual filesystem |
| **volatility3** | >=2.0.0 | Memory dump analysis |

### Testing & Quality

| Package | Version | Purpose |
|---------|---------|---------|
| **pytest** | >=7.0.0 | Testing framework |
| **pytest-cov** | >=4.0.0 | Code coverage analysis |
| **pytest-mock** | >=3.10.0 | Test mocking utilities |
| **black** | >=23.0.0 | Code formatting |
| **mypy** | >=1.5.0 | Static type checking |
| **flake8** | >=6.0.0 | Code linting |
| **isort** | >=5.12.0 | Import sorting |

### Project Structure

```
FOEP/
├── src/foep/                          # Main package
│   ├── core/                          # Core pipeline orchestration
│   │   ├── config.py                  # Configuration management
│   │   └── pipeline.py                # Main orchestration (with threat detection)
│   ├── ingest/                        # Data ingestion
│   │   ├── forensic/                  # Disk, memory, log analysis
│   │   ├── osint/                     # GitHub, Twitter, Shodan, etc.
│   │   └── threat_utils.py            # Threat detection utilities
│   ├── threat/                        # Threat detection & intelligence
│   │   ├── threat_detector.py         # Local threat detection engine
│   │   ├── threat_intelligence_aggregator.py  # Multi-source threat feeds
│   │   ├── threat_parser.py           # AbuseIPDB, OTX, Shodan parsing
│   │   ├── threat_correlation.py      # Threat incident correlation
│   │   └── threat_schema.py           # Data schemas for threats
│   ├── normalize/                     # Evidence normalization
│   │   ├── schema.py                  # Evidence data models
│   │   ├── transformer.py             # Data transformation
│   │   └── hash_utils.py              # Cryptographic hashing
│   ├── correlate/                     # Entity correlation & linking
│   │   ├── extractor.py               # Entity extraction
│   │   ├── linker.py                  # Entity relationship linking
│   │   └── graph_db.py                # Neo4j graph operations
│   ├── credibility/                   # Evidence credibility scoring
│   │   └── scorer.py                  # Credibility calculation
│   ├── report/                        # Report generation
│   │   ├── generator.py               # Main report generator
│   │   ├── custody.py                 # Chain of custody tracking
│   │   ├── redactor.py                # PII redaction
│   │   └── templates/                 # HTML/CSS templates
│   └── sources.py                     # Credibility sources
├── scripts/                           # CLI scripts
│   ├── foep_ingest.py                 # Evidence ingestion CLI
│   ├── foep_correlate.py              # Correlation CLI
│   ├── foep_report.py                 # Report generation CLI
│   └── threat_detection_demo.py       # Threat detection demo
├── tests/                             # Test suite
│   ├── unit/                          # Unit tests
│   └── integration/                   # Integration tests
├── config/                            # Configuration files
│   └── config.yaml                    # Main configuration
├── setup.py                           # Package installer
├── requirements.txt                   # Core dependencies
├── requirements-dev.txt               # Development dependencies
└── README.md                          # This file
```

---

## 🎯 Usage & Execution Guide

### 1️⃣ Run Threat Detection Demo

Quickly see threat detection capabilities:

```bash
# From project root
python scripts/threat_detection_demo.py

# Expected output:
# ✅ Local threat detection: Detects malware, C2 domains, botnet IPs, etc.
# ✅ Threat aggregation: Queries multiple intelligence sources
# ✅ Evidence enrichment: Adds threat metadata to evidence
# ✅ Threat filtering: Categorizes by severity
# ✅ Summary generation: Statistical analysis
```

### 2️⃣ Run Unit Tests

Verify installation and basic functionality:

```bash
# Run all unit tests
python -m pytest tests/unit/ -v

# Run specific test
python -m pytest tests/unit/test_normalize.py -v

# Run with coverage
python -m pytest tests/unit/ --cov=src/foep --cov-report=html
```

### 3️⃣ Run Integration Tests

Test complete pipeline workflow:

```bash
# Run integration tests
python -m pytest tests/integration/ -v

# Run specific integration test
python -m pytest tests/integration/test_full_pipeline.py::TestFullPipeline::test_full_pipeline_basic -v
```

### 4️⃣ Run Full Pipeline (Python Script)

Process evidence through complete workflow:

```bash
python << 'EOF'
import sys
sys.path.insert(0, 'src')

from foep.core.config import load_config
from foep.core.pipeline import FOEPPipeline

# Load configuration
config = load_config('config/config.yaml')

# Initialize pipeline
pipeline = FOEPPipeline(
    config=config,
    case_id='DEMO-CASE-001',
    investigator='Forensic Analyst'
)

# Example 1: OSINT Collection Only
print("=" * 80)
print("EXAMPLE 1: OSINT Collection and Threat Analysis")
print("=" * 80)

osint_evidence = pipeline.run_osint_collection(
    social_queries=[
        {'platform': 'github', 'identifier': 'torvalds'},
        {'platform': 'twitter', 'identifier': 'elonmusk'}
    ],
    breach_queries=[
        {'query': 'test@example.com', 'type': 'email'}
    ]
)

print(f"Collected {len(osint_evidence)} OSINT items")

# Perform threat analysis
threat_analysis = pipeline.run_threat_analysis()
print(f"Threat analysis: {threat_analysis['summary']['total_threats']} threats detected")

# Generate report
report_path = pipeline.generate_report(
    output_dir='reports/demo_osint',
    format='html'
)
print(f"✅ Report generated: {report_path}")

EOF
```

### 5️⃣ Using CLI Scripts

#### Ingestion
```bash
# Collect OSINT evidence
python scripts/foep_ingest.py \
  --social "github:linus" \
  --social "twitter:vint" \
  --domain "example.com" \
  --breach "user@example.com" \
  --output evidence.json \
  --case-id DEMO-2026
```

#### Correlation
```bash
# Correlate entities
python scripts/foep_correlate.py \
  --input evidence.json \
  --output correlated.json \
  --case-id DEMO-2026
```

#### Reporting
```bash
# Generate report
python scripts/foep_report.py \
  --input correlated.json \
  --output reports/demo/ \
  --case-id DEMO-2026 \
  --format html
```

### 6️⃣ Python API Usage

```python
from foep.core.config import load_config
from foep.core.pipeline import FOEPPipeline
from foep.ingest.threat_utils import create_threat_summary, filter_evidence_by_threat_level

# Initialize
config = load_config('config/config.yaml')
pipeline = FOEPPipeline(config, 'CASE-001', 'Analyst')

# Collect evidence
forensic_evidence = pipeline.run_forensic_ingestion(
    disk_images=['disk.img'],
    log_directories=['/var/log']
)

osint_evidence = pipeline.run_osint_collection(
    social_queries=[{'platform': 'github', 'identifier': 'torvalds'}]
)

# Threat analysis
threat_analysis = pipeline.run_threat_analysis()
print(f"Critical threats: {threat_analysis['summary']['critical_count']}")

# Correlation
scored_evidence = pipeline.run_correlation_and_scoring()

# Generate report
report = pipeline.generate_report(
    output_dir='reports',
    format='html',
    case_info={'description': 'Investigation into suspicious activity'}
)
print(f"Report: {report}")
```

---

## 📊 Threat Detection Capabilities

### 6 Specialized Threat Detectors

1. **MalwareHashDetector**: Known malware hash identification
2. **MaliciousDomainDetector**: C2 servers, phishing infrastructure
3. **MaliciousIPDetector**: Botnet C2, exposed risky ports, geolocation threats
4. **MaliciousURLDetector**: Malicious download URLs, payload distribution
5. **BehavioralThreatDetector**: Persistence mechanisms, suspicious file patterns
6. **ProcessThreatDetector**: Living-off-the-land (LOLBin) attacks

### 7 Threat Intelligence Sources

1. **AbuseIPDB** - IP reputation database
2. **OTX** - Open Threat Exchange
3. **Shodan** - Security exposure data
4. **VirusTotal** - Malware hash detection
5. **Local Malware DB** - Custom threat indicators
6. **Emerging Threats** - Emerging threat feeds
7. **Abuse Feeds** - Aggregated abuse data

### Threat Levels

- 🔴 **CRITICAL** (80-100%): Immediate action required
- 🟠 **HIGH** (60-79%): Significant risk
- 🟡 **MEDIUM** (40-59%): Moderate concern
- 🟢 **LOW** (20-39%): Minor concern
- ⚪ **INFO** (0-19%): Informational

---

## 🧪 Verification & Troubleshooting

### Verify Installation

```bash
# Test imports
python -c "from foep.core.pipeline import FOEPPipeline; print('✅ OK')"

# Run demo
python scripts/threat_detection_demo.py

# Run tests
python -m pytest tests/unit/test_normalize.py -v
```

### Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'foep'` | Run `pip install -e .` from project root |
| `Neo4j connection refused` | Check Neo4j is running: `docker ps` or `sudo systemctl status neo4j` |
| `API key missing` | Add keys to `config/config.yaml` or use default mock responses |
| `Permission denied` on config | Run `chmod 644 config/config.yaml` |

### Check Logs

```bash
# View recent logs
tail -f test.log

# Run with verbose output
python -m pytest tests/ -v -s
```

---

## 📝 Example Investigation Workflow

```bash
#!/bin/bash

# Step 1: Create case directory
mkdir -p investigations/case-001/{evidence,reports}
cd investigations/case-001

# Step 2: Collect OSINT
python ../../scripts/foep_ingest.py \
  --social "github:suspect-user" \
  --domain "suspect.com" \
  --breach "suspect@email.com" \
  --output evidence/raw.json \
  --case-id CASE-001

# Step 3: Correlate entities
python ../../scripts/foep_correlate.py \
  --input evidence/raw.json \
  --output evidence/correlated.json \
  --case-id CASE-001

# Step 4: Generate report
python ../../scripts/foep_report.py \
  --input evidence/correlated.json \
  --output reports/ \
  --case-id CASE-001 \
  --format html

# Step 5: Review outputs
echo "Investigation complete!"
echo "Reports generated in: reports/"
ls -la reports/
```

---

## 📞 Support & Documentation

- **Bug Reports**: Check existing issues or create new ones
- **Questions**: Post in discussions section
- **Configuration**: See `config/config.yaml` for all options
- **API Docs**: Detailed in source code docstrings

---

## 📄 License

This project is provided as-is for forensic analysis and research purposes.

---

## ✅ Getting Started Checklist

- [ ] Clone repository: `git clone ...`
- [ ] Install Python 3.10+: `python3 --version`
- [ ] Create venv: `python3 -m venv venv && source venv/bin/activate`
- [ ] Install deps: `pip install -r requirements.txt`
- [ ] Run demo: `python scripts/threat_detection_demo.py`
- [ ] Run tests: `python -m pytest tests/unit/test_normalize.py -v`
- [ ] (Optional) Setup Neo4j via Docker
- [ ] Read `config/config.yaml`
- [ ] Run full pipeline: See "Python API Usage" section
- [ ] Generate reports: See "Execution Guide" section

🚀 **You're ready to go! Start with the threat detection demo to see FOEP in action.**
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

### Verify CLI Commands Work

```bash
# Test foep-ingest CLI
foep-ingest --help

# Test foep-correlate CLI  
foep-correlate --help

# Test foep-report CLI
foep-report --help

# All commands should display usage and options without error
```

### Run All Unit Tests
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

# Threat detection tests
python -m pytest tests/ -k threat -v
```

### Expected Test Results
```
tests/unit/test_normalize.py ..................... [100%]
✅ 17 passed in 0.18s
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

