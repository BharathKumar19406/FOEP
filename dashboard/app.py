import streamlit as st
import json
import pandas as pd
import plotly.express as px
from pathlib import Path
from datetime import datetime

# Page config
st.set_page_config(
    page_title="FOEP Forensic Dashboard",
    page_icon="🔍",
    layout="wide"
)

# Header
st.title("🔍 Forensic OSINT-to-Evidence Pipeline (FOEP)")
st.markdown("Real-time OSINT evidence analysis and correlation")

# Sidebar
st.sidebar.header("📁 Case Management")
case_id = st.sidebar.text_input("Case ID", "DFIR-2026")
evidence_file = st.sidebar.file_uploader("Upload Evidence JSON", type=["json"])

# Load data
@st.cache_data
def load_evidence(file_path):
    with open(file_path) as f:
        return json.load(f)

if evidence_file:
    evidence_data = json.load(evidence_file)
else:
    # Default test file
    default_path = Path("correlated.json")
    if default_path.exists():
        evidence_data = load_evidence(default_path)
    else:
        evidence_data = []

if not evidence_data:
    st.warning("⚠️ No evidence loaded. Upload a JSON file or run FOEP pipeline.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(evidence_data)

# Main dashboard
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Evidence", len(df))
with col2:
    st.metric("Unique Sources", df["source"].nunique())
with col3:
    avg_cred = df["credibility_score"].mean()
    st.metric("Avg Credibility", f"{avg_cred:.1f}/100")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔍 Evidence", "🌐 Knowledge Graph", "📈 Analytics"])

# Tab 1: Overview
with tab1:
    st.subheader("Evidence by Source")
    source_counts = df["source"].value_counts().reset_index()
    fig1 = px.bar(source_counts, x="source", y="count", color="source")
    st.plotly_chart(fig1, width='stretch')
    
    st.subheader("Credibility Distribution")
    fig2 = px.histogram(df, x="credibility_score", nbins=10, color_discrete_sequence=["#636EFA"])
    st.plotly_chart(fig2, width='stretch')

# Tab 2: Evidence Table
with tab2:
    st.subheader("Evidence Details")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        sources = st.multiselect("Sources", options=df["source"].unique(), default=df["source"].unique())
    with col2:
        min_cred = st.slider("Min Credibility", 0, 100, 50)
    with col3:
        entity_type = st.selectbox("Entity Type", ["All"] + list(df["entity_type"].unique()))
    
    # Filter data
    filtered_df = df[df["source"].isin(sources)]
    filtered_df = filtered_df[filtered_df["credibility_score"] >= min_cred]
    if entity_type != "All":
        filtered_df = filtered_df[filtered_df["entity_type"] == entity_type]
    
    # Display table
    st.dataframe(
        filtered_df[[
            "entity_value", "entity_type", "source", 
            "credibility_score", "observation_type"
        ]].sort_values("credibility_score", ascending=False),
        width='stretch',
        height=400
    )
    
    # Export button
    csv = filtered_df.to_csv(index=False)
    st.download_button("📥 Download CSV", csv, "foep_evidence.csv", "text/csv")

# Tab 3: Knowledge Graph (Fixed)
with tab3:
    st.subheader("Knowledge Graph Visualization")
    
    # Neo4j connection (keep existing)
    with st.expander("Neo4j Connection Settings"):
        col1, col2, col3 = st.columns(3)
        with col1:
            neo4j_uri = st.text_input("URI", "bolt://localhost:7687", key="neo4j_uri")
        with col2:
            username = st.text_input("Username", "neo4j", key="neo4j_user")
        with col3:
            password = st.text_input("Password", type="password", key="neo4j_pass")
        
        if st.button("Connect & Render Graph", key="connect_graph"):
            try:
                from neo4j import GraphDatabase
                driver = GraphDatabase.driver(neo4j_uri, auth=(username, password))
                
                # Query for nodes and relationships
                with driver.session() as session:
                    nodes_result = session.run("MATCH (n:Evidence) RETURN id(n) as id, n.entity_value as value, n.source as source, n.entity_type as type")
                    nodes = [record for record in nodes_result]

                    rels_result = session.run("MATCH (a:Evidence)-[r]->(b:Evidence) RETURN id(a) as src, id(b) as tgt, type(r) as rel")
                    rels = [record for record in rels_result]
                
                # Build PyVis graph
                from pyvis.network import Network
                net = Network(height="600px", width="100%", bgcolor="#1e1e2e", font_color="white")
                
                node_map = {}
                for record in nodes:
                    node_id = str(record["id"])
                    label = f"{record['value'][:20]} ({record['source']})"
                    title = f"Type: {record['type']}\nSource: {record['source']}"
                    net.add_node(node_id, label=label, title=title, color="#636EFA")
                    node_map[node_id] = record["value"]
                
                for record in rels:
                    src = str(record["src"])
                    tgt = str(record["tgt"])
                    rel_type = record["rel"]
                    net.add_edge(src, tgt, label=rel_type, color="#F5B7B1")
                
                # Save and display
                net.save_graph("graph.html")
                st.components.v1.html(open("graph.html").read(), height=600)
                st.success(f"✅ Rendered {len(node_map)} nodes, {len(rels)} relationships")
                
                driver.close()
            except Exception as e:
                st.error(f"❌ Graph render failed: {e}")
    
    st.info("💡 Tip: Upload evidence JSON first, then connect to Neo4j to see live graph.")

# Tab 4: Analytics (Enhanced Threat Intelligence)
with tab4:
    st.subheader("Threat Intelligence Comparison")
    
    # Filter threat IPs
    threat_ips = df[df["entity_type"] == "ip_address"]
    if not threat_ips.empty:
        # Credibility heatmap
        fig1 = px.scatter(
            threat_ips,
            x="entity_value",
            y="credibility_score",
            color="source",
            size="credibility_score",
            hover_data=["metadata"],
            title="Threat IP Credibility Score",
            labels={"credibility_score": "Credibility (0-100)"},
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig1.update_layout(height=400)
        st.plotly_chart(fig1, width='stretch')
        
        # Threat categories
        all_categories = []
        for _, row in threat_ips.iterrows():
            meta = row.get("metadata", {})
            cats = meta.get("categories", []) or meta.get("malware_families", [])
            if isinstance(cats, str):
                cats = [cats]
            for cat in cats:
                all_categories.append({
                    "IP": row["entity_value"],
                    "Category": cat,
                    "Source": row["source"]
                })
        if all_categories:
            cat_df = pd.DataFrame(all_categories)
            fig2 = px.histogram(cat_df, x="Category", color="Source", title="Threat Categories by Source")
            st.plotly_chart(fig2, width='stretch')
    
    else:
        st.info("🔍 No threat IPs found. Upload JSON with malicious IPs (e.g., 185.220.101.132).")

    st.subheader("Evidence Confidence Heatmap")
    
    # Credibility vs Source
    cred_df = df.groupby("source")["credibility_score"].agg(["mean", "count"]).reset_index()
    cred_df.columns = ["source", "avg_credibility", "count"]
    
    fig3 = px.scatter(
        cred_df,
        x="source",
        y="avg_credibility",
        size="count",
        color="source",
        hover_data=["count"],
        title="Source Reliability & Evidence Volume",
        labels={"avg_credibility": "Avg Credibility", "count": "Evidence Count"}
    )
    fig3.update_layout(xaxis_tickangle=-45, height=400)
    st.plotly_chart(fig3, width='stretch')

    st.subheader("IOC Mapping")
    st.markdown("""
    | IOC Type | Value | Confidence | Sources |
    |----------|-------|------------|---------|
    | IP | `185.220.101.132` | 95–98% | OTX, AbuseIPDB, Shodan |
    | Domain | `evil-domain.com` | 85% | Archive.org |
    | Email | `user@company.com` | 92% | HIBP |
    """)

# Footer
st.markdown("---")
st.caption("FOEP Dashboard v2.1 • Built for Digital Forensics • SRM KTR")
