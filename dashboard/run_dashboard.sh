#!/bin/bash
# FOEP Dashboard Runner

echo "🚀 Starting FOEP Dashboard..."
echo "============================"

# Check if evidence file exists
if [ ! -f "../correlated.json" ]; then
    echo "⚠️  Warning: No correlated.json found"
    echo "💡 Run FOEP pipeline first:"
    echo "   foep-ingest --domain microsoft.com --output evidence.json"
    echo "   foep-correlate --input evidence.json --output correlated.json"
fi


# Start Streamlit
echo "🌐 Dashboard starting at http://localhost:8501"
streamlit run app.py --server.port=8501
