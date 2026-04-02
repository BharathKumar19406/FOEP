# 🐛 FOEP Troubleshooting Guide & Solutions

## ISSUE #1: `json.decoder.JSONDecodeError: Extra data`

### Error Message
```
json.decoder.JSONDecodeError: Extra data: line 1 column 3 (char 2)
```

### Root Cause
Your JSON file is corrupted with multiple array markers:
```json
❌ WRONG:    [][][][{...}]     ← Extra brackets at start
✅ CORRECT:  [{...}]           ← Single array
```

### Solution
Create a clean JSON file with proper array syntax:

```python
# Validate your JSON file
python3 -c "import json; json.load(open('evidence.json'))" && echo "✅ Valid JSON"
```

---

## ISSUE #2: Pydantic Validation Error - `observation_type`

### Error Message
```
1 validation error for Evidence
observation_type
  Input should be 'disk_artifact', 'memory_artifact', 'log_artifact', 
  'osint_post', 'osint_dns', ...
  [type=enum, input_value='osint_social', input_type=str]
```

### Problem
Using invalid `observation_type` value like `"osint_social"`

### Valid Values

| Value | Description |
|-------|-------------|
| `disk_artifact` | Local disk files |
| `memory_artifact` | RAM dumps, memory forensics |
| `log_artifact` | System/application logs |
| `osint_post` | Social media posts ✅ (NOT `osint_social`) |
| `osint_dns` | DNS records |
| `osint_reputation` | VirusTotal, URLhaus, etc. |
| `osint_exposure` | Shodan, censys, etc. |
| `osint_geo` | Geolocation data |
| `osint_historical` | Historical records |
| `osint_registration` | Domain/IP registration |
| `osint_breach` | Data breach records |
| `osint_code` | Code repositories |

### Example Fix
```json
❌ WRONG: "observation_type": "osint_social"
✅ RIGHT: "observation_type": "osint_post"
```

---

## ISSUE #3: Pydantic Validation Error - `entity_type`

### Error Message
```
1 validation error for Evidence
entity_type
  Input should be 'ip', 'ip_port', 'domain', ...
  [type=enum, input_value='file_hash', input_type=str]
```

### Problem
Using invalid `entity_type` value like `"file_hash"`

### Valid Values

| Value | Description |
|-------|-------------|
| `ip` | IPv4/IPv6 address |
| `ip_port` | IP:Port combination |
| `domain` | Domain name |
| `ip_address` | IP address variant |
| `email` | Email address |
| `username` | User account |
| `file` | File path |
| `hash` | File hash (MD5, SHA256) ✅ (NOT `file_hash`) |
| `url` | HTTP/HTTPS URL |
| `repo` | Repository |
| `post` | Social media post |
| `code_snippet` | Code snippet |
| `command_line` | CLI command |
| `breach` | Breach record |
| `aws_arn` | AWS ARN |

### Example Fix
```json
❌ WRONG: "entity_type": "file_hash"
✅ RIGHT: "entity_type": "hash"
```

---

## ISSUE #4: Neo4j Connection Refused

### Error Message
```
foep.correlate.graph_db - ERROR - Failed to connect to Neo4j: 
Couldn't connect to localhost:7687
```

### Status
⚠️ **OPTIONAL** - Application works fine WITHOUT Neo4j
- ✅ JSON files are created
- ✅ Reports are generated
- ⚠️ Graph visualization unavailable

### Optional: Start Neo4j

**Using Docker:**
```bash
docker run -d --name foep-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/foep-password \
  neo4j:5.0
```

**Access at:** http://localhost:7474
- **Login:** neo4j / foep-password

**Using Kali Linux / Ubuntu:**
```bash
sudo apt install neo4j
sudo neo4j-admin set-initial-password foep-password
sudo systemctl start neo4j
```

---

## ✅ Complete Working Example

### Step 1: Create `evidence.json`

```json
[
  {
    "evidence_id": "github::user_alice",
    "entity_type": "username",
    "entity_value": "alice",
    "observation_type": "osint_post",
    "source": "github",
    "metadata": {
      "platform": "github",
      "repos": 25,
      "followers": 100
    },
    "credibility_score": 85
  },
  {
    "evidence_id": "virustotal::hash_abc123",
    "entity_type": "hash",
    "entity_value": "abc123def456",
    "observation_type": "osint_reputation",
    "source": "virustotal",
    "metadata": {
      "hash_type": "sha256",
      "verdict": "likely_malicious",
      "detections": 5
    },
    "credibility_score": 90
  },
  {
    "evidence_id": "shodan::ip_1_2_3_4",
    "entity_type": "ip",
    "entity_value": "1.2.3.4",
    "observation_type": "osint_exposure",
    "source": "shodan",
    "metadata": {
      "country": "US",
      "open_ports": [22, 80, 443]
    },
    "credibility_score": 75
  }
]
```

### Step 2: Validate JSON
```bash
python3 -c "import json; json.load(open('evidence.json'))" && echo "✅ Valid"
```

### Step 3: Correlate
```bash
foep-correlate --input evidence.json \
  --output correlated.json \
  --case-id CASE-2024-001
```

**Expected Output:**
```
✅ Loaded 3 evidence items
✅ Created linkage groups for 6 evidence items
✅ Wrote 6 items to correlated.json
```

### Step 4: Generate Report
```bash
foep-report --input correlated.json \
  --output reports/ \
  --case-id CASE-2024-001 \
  --format html
```

**Expected Output:**
```
✅ HTML report saved
✅ Chain-of-custody log saved
```

**Files created:**
- `foep_report_CASE-2024-001.html` (interactive report)
- `custody_CASE-2024-001.json` (chain of custody)

---

## 🎯 Quick Reference Checklist

### ✅ DO:
- ✓ Use valid `entity_type` values from enum list
- ✓ Use valid `observation_type` values from enum list
- ✓ Format `evidence_id` as `"source::unique_key"`
- ✓ Set `credibility_score` between 0-100
- ✓ Wrap JSON array in `[ ]` brackets
- ✓ Include all required fields
- ✓ Use proper JSON syntax (commas, quotes, etc.)

### ❌ DON'T:
- ✗ Mix multiple arrays: `[][][][] {...}`
- ✗ Use invalid enum values
- ✗ Leave required fields empty or null
- ✗ Forget commas between JSON objects
- ✗ Omit the double colon in evidence_id
- ✗ Use `"osint_social"` instead of `"osint_post"`
- ✗ Use `"file_hash"` instead of `"hash"`

---

## 📞 Still Having Issues?

1. **Validate JSON first:**
   ```bash
   python3 -m json.tool evidence.json > /dev/null && echo "✅ Valid JSON"
   ```

2. **Check schema values:**
   - Copy from the "Valid Values" tables above
   - Don't invent custom values

3. **View pipeline logs:**
   ```bash
   foep-correlate --input evidence.json --output out.json --case-id TEST 2>&1
   ```

4. **Start fresh:**
   ```bash
   rm evidence.json correlated.json
   # Create new file using template above
   ```

---

**Version:** 1.0  
**Updated:** 2024-04-02  
**Tested On:** Ubuntu 24.04 LTS / Kali Linux
