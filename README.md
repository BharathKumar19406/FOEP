# 🕵️‍♂️ Forensic OSINT-to-Evidence Pipeline (FOEP)

**Automated Multi-Source OSINT Collection, Correlation, and Reporting for Digital Forensics**

---

## 📌 Overview

FOEP is a command-line forensic tool that automates the collection, correlation, and reporting of open-source intelligence (OSINT) from multiple public sources. It transforms raw OSINT data into structured, court-ready evidence with credibility scoring and knowledge graph visualization.

### ✨ Key Features
- **Multi-Source Collection**: GitHub, Twitter, Domain DNS, HIBP Breaches
- **Auto-Enrichment**: Archive.org history, IP Geolocation, VirusTotal (optional)
- **Credibility Scoring**: Evidence weighted by source reliability
- **Knowledge Graph**: Neo4j-based entity correlation
- **Court-Ready Reports**: HTML/PDF output with redacted internal fields
- **Ethical Compliance**: Uses only public APIs — no scraping

---

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/yourusername/FOEP.git
cd FOEP
python3 -m venv foep-env
source foep-env/bin/activate
pip install -r requirements.txt

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

# View report
xdg-open reports/foep_report_DEMO-2026_*.html
```

---

## 📦 Installation

### Prerequisites
- Python 3.10+
- Neo4j 5.x (optional)
- `jq` (for JSON processing)

### Step-by-Step Setup

#### 1. **Install System Dependencies**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv neo4j jq -y
```

#### 2. **Setup Python Environment**
```bash
git clone https://github.com/yourusername/FOEP.git
cd FOEP
python3 -m venv foep-env
source foep-env/bin/activate
pip install -r requirements.txt
```

#### 3. **Configure Neo4j (Optional)**
```bash
# Set password
sudo neo4j-admin dbms set-initial-password neo4j

# Start service
sudo systemctl enable neo4j
sudo systemctl start neo4j

# Verify
sudo systemctl status neo4j
```

#### 4. **Configure API Keys (Optional)**
Edit `config/config.yaml`:
```yaml
virustotal:
  enabled: true
  api_key: "YOUR_VIRUSTOTAL_KEY"

shodan:
  enabled: true
  api_key: "YOUR_SHODAN_KEY"
```

> 💡 **Free API Keys**:  
> - [VirusTotal](https://www.virustotal.com/gui/join-us) (500 req/day)  
> - [Shodan](https://account.shodan.io/register) (100 req/month)

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

## 📄 Sample Output

### Evidence JSON
```json
{
  "evidence_id": "github_user::trailofbits",
  "entity_type": "username",
  "entity_value": "trailofbits",
  "observation_type": "osint_social",
  "source": "github",
  "metadata": {
    "name": "Trail of Bits",
    "public_repos": 247,
    "followers": 5800
  },
  "credibility_score": 90
}
```

### HTML Report Features
- Clean evidence table
- Credibility indicators
- Redacted internal fields
- Case metadata

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

