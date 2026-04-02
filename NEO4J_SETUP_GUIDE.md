# Neo4j Browser Setup & Usage Guide

**Status:** ✅ **Neo4j Database Running**  
**Date:** April 2, 2026  
**Evidence Ingested:** 50 items (23 collected + 27 extracted entities)

---

## 🚀 Quick Start

### Access Neo4j Browser

**Open in your browser:**
```
http://localhost:7474
```

### Neo4j Login Credentials

| Field | Value |
|-------|-------|
| **URL** | `bolt://localhost:7687` |
| **Username** | `neo4j` |
| **Password** | `foep_security_2026` |

---

## 📊 What's in the Graph

### 50 Items Indexed:
- **23 Evidence Items** (from foep-ingest collection)
- **27 Extracted Entities** (from correlation analysis)

### Graph Statistics:
```
Nodes Created    : 50
Relationships    : [Linked via entity correlations]
Sources          : 8 (GitHub, DNS, VT, OTX, Shodan, URLScan, Archive.org, Geolocation)
Entities         : Domains, IPs, Usernames, Repositories, Hashes, URLs
```

---

## 🔍 Useful Neo4j Queries

### 1. View All Nodes
```cypher
MATCH (n) RETURN n LIMIT 20
```

### 2. Find All GitHub Evidence
```cypher
MATCH (n {source: 'github'}) RETURN n
```

### 3. Find Domain-to-IP Relationships
```cypher
MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress) RETURN d.value, ip.value
```

### 4. Find Linus Torvalds Profile & Repos
```cypher
MATCH (user:User {entity_value: 'torvalds'})-[:CONTRIBUTED_TO]->(repo) 
RETURN user.entity_value, repo.entity_value, repo.metadata
```

### 5. Show All Evidence from Specific Source
```cypher
MATCH (n:Evidence {source: 'shodan'}) RETURN n.entity_value, n.metadata
```

### 6. Find High-Credibility Evidence (>80)
```cypher
MATCH (n:Evidence) WHERE n.credibility_score > 80 RETURN n.entity_value, n.credibility_score ORDER BY n.credibility_score DESC
```

### 7. Correlations Between Domains & IPs
```cypher
MATCH (d:Domain)-[:HAS_RECORD]->(ip:IPAddress) RETURN d.value, ip.value, d.metadata
```

### 8. Find All Threat Intelligence
```cypher
MATCH (n:Evidence {source: 'otx'}) RETURN n.entity_value, n.metadata
```

### 9. Infrastructure Inventory (Shodan)
```cypher
MATCH (ip:IPAddress)-[:HAS_EXPOSURE]->(port) 
WHERE ip.metadata.source = 'shodan' 
RETURN ip.value, port.metadata
```

### 10. Complete Investigation Graph
```cypher
MATCH path = (n)-[r]-(m) RETURN path LIMIT 50
```

---

## 📈 Graph Structure

```
Evidence
├── ID, Type, Source, Metadata, Credibility Score
└── Relationships:
    ├── CORRELATES_WITH (other evidence)
    ├── RELATES_TO (entities)
    └── MENTIONS (external entities)

Entities
├── Username (torvalds, github, etc.)
├── Domain (google.com, github.com)
├── IPAddress (8.8.8.8, 142.250.207.174, etc.)
├── Repository (torvalds/kernel, etc.)
├── URL (https://google.com, etc.)
└── Hash (MD5, SHA256)
```

---

## 💻 Neo4j Desktop Integration

### Connect Desktop to Local Database

1. Open **Neo4j Desktop**
2. Click **Add Database** → **Connect to Remote Database**
3. Use these settings:

```
Name          : foep-local
Connection URI: bolt://localhost:7687
Username      : neo4j
Password      : foep_security_2026
```

4. Click **Connect** ✅

---

## 🔐 Docker Container Info

### View Container Status
```bash
docker ps | grep foep-neo4j
```

### Container Details
```bash
Container Name   : foep-neo4j
Image            : neo4j:5.15
Port Mapping     : 7474 (HTTP), 7687 (Bolt)
Memory           : Default (2GB recommended)
Volume           : None (in-memory for testing)
```

### View Logs
```bash
docker logs foep-neo4j
```

### Stop Neo4j (when done)
```bash
docker stop foep-neo4j
```

### Restart Neo4j
```bash
docker start foep-neo4j
```

### Remove Container (cleanup)
```bash
docker rm -f foep-neo4j
```

---

## 📋 Data Summary in Graph

### GitHub Social (12 nodes)
```
User: Linus Torvalds
  ├── 294,425 followers
  ├── Profile URL: https://github.com/torvalds
  └── Repositories:
      ├── 1590A (OpenSCAD - Guitar Pedal)
      ├── AudioNoise (C - Digital Audio Effects)
      ├── GuitarPedal (Learning Analog Circuits)
      ├── linux (🌟 Main kernel repository)
      └── [7 more repositories]
```

### Domain Intelligence (6 nodes)
```
google.com
  ├── DNS → 142.250.207.174 (US, Google LLC)
  ├── VT Reputation → Clean (0/94 engines)
  ├── OTX Threat → Benign
  ├── Archive.org → 1000+ snapshots
  └── Historical Data

github.com
  ├── DNS → 20.207.73.82 (India, Microsoft)
  ├── VT Reputation → Clean (0/94 engines)
  ├── URLScan → 100+ scans
  └── Infrastructure Mapped
```

### IP Intelligence (5 nodes)
```
8.8.8.8 (Google DNS)
  ├── OTX Reputation → Benign
  ├── Geographic Location → US
  └── ISP → Google LLC

1.1.1.1 (Cloudflare DNS)
  ├── Shodan → 14 open ports
  ├── Infrastructure → Cloudflare ISP
  └── Geographic Location → Unknown
```

---

## 🎯 FOEP Workflow with Neo4j

### Phase 1: Ingest (✅ Complete)
```
Multiple OSINT sources
        ↓
  23 Evidence Items
        ↓
  JSON Output
```

### Phase 2: Correlate (✅ Complete)  
```
23 Evidence Items
        ↓
Extract Entities (27 new)
        ↓
Link Relationships
        ↓
Score Credibility
        ↓
Neo4j Graph (50 nodes)
```

### Phase 3: Report (Ready)
```
Neo4j Graph
        ↓
Generate HTML Report
        ↓
Redact Sensitive Data
        ↓
PDF/HTML Output
```

---

## 📊 Browser Views

### 1. Graph Visualization
Navigate to Neo4j Browser and run:
```cypher
MATCH (n) RETURN n LIMIT 30
```
**View:** Interactive graph with connections between entities

### 2. Table View
```cypher
MATCH (n:Evidence) RETURN n.entity_value, n.source, n.credibility_score
```
**View:** Tabular evidence listing

### 3. Text View
```cypher
MATCH (n) RETURN n.entity_value, n.metadata
```
**View:** Metadata details for all entities

---

## ⚡ Performance Tips

- **Limit results** when querying large graphs: `LIMIT 50`
- **Use indexes** for faster queries on frequently searched fields
- **Check explain plan** for query optimization: `EXPLAIN MATCH ...`

---

## 🚨 Troubleshooting

### Issue: Cannot Connect
```
❌ Connection refused: bolt://localhost:7687
```
**Solution:** Check if Neo4j container is running:
```bash
docker ps | grep foep-neo4j
```

### Issue: Wrong Password
```
❌ Neo4j AuthenticationException
```
**Solution:** Verify password in config.yaml matches container start command

### Issue: No Data in Graph
```
❌ MATCH (n) RETURN n → (empty)
```
**Solution:** Run foep-correlate first:
```bash
foep-correlate --input complete_investigation.json --output correlated.json
```

---

## 📚 Next Steps

1. ✅ **Neo4j is running** - Access browser at http://localhost:7474
2. ✅ **Data is ingested** - 50 items in graph database
3. ✅ **Ready to explore** - Use queries above to analyze

### To Generate Report
```bash
foep-report \
  --input correlated_graph.json \
  --output investigation_report.html \
  --case-id FULL-TEST \
  --redact-emails \
  --redact-internal-ips
```

---

## 🎓 Learning Resources

- [Neo4j Browser Guide](https://neo4j.com/developer/neo4j-browser/)
- [Cypher Query Language](https://neo4j.com/developer/cypher/)
- [Graph Database Concepts](https://neo4j.com/developer/graph-database/)

---

**Setup Complete! Go explore your knowledge graph at http://localhost:7474 🌐**

