#!/usr/bin/env bash
# =============================================================================
# Phase 3 + Phase 4 End-to-End Run Script
# Run from project root. Edit the variables at the top before running.
# =============================================================================

set -euo pipefail

# ── Configuration — EDIT THESE ───────────────────────────────────────────────
INPUT_JSONL="./cve_entities_all.jsonl"      # Phase 2 output
EMBED_DIR="./embeddings"                    # where .npy + .jsonl go
GEMINI_OUT="./gemini_relations.jsonl"       # Gemini extraction output

NEO4J_URI="bolt://localhost:7687"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="your_password_here"         # <-- change this

QDRANT_HOST="localhost"
QDRANT_PORT="6333"

EMBED_MODEL="sentence-transformers/all-mpnet-base-v2"
# Alternative: "AI-Growth-Lab/SecBERT" — better for domain, slower to load

# GEMINI_API_KEY="your_key_here"            # <-- uncomment for Phase 3 Gemini step

PHASE3_DIR="./phase3"
PHASE4_DIR="./phase4"

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*"; }
section() { echo; echo "════════════════════════════════════════"; echo "  $*"; echo "════════════════════════════════════════"; }

# ── Phase 3: Structural Load ─────────────────────────────────────────────────
section "Phase 3-A: Structural load (CVE → Neo4j + CWE→ATT&CK edges)"
python "$PHASE3_DIR/pipeline.py" structural \
    --input "$INPUT_JSONL" \
    --neo4j-uri "$NEO4J_URI" \
    --neo4j-user "$NEO4J_USER" \
    --neo4j-password "$NEO4J_PASSWORD"

section "Phase 3-A: Validation queries"
python "$PHASE3_DIR/validate.py" \
    --neo4j-uri "$NEO4J_URI" \
    --neo4j-user "$NEO4J_USER" \
    --neo4j-password "$NEO4J_PASSWORD"

# ── Phase 3: Gemini (optional) ───────────────────────────────────────────────
# Uncomment to run. Free tier: set --batch-size 10 --rate-limit-delay 4.0
# Paid tier: set --batch-size 50 --rate-limit-delay 0.2

# section "Phase 3-B: Gemini relation extraction (high-quality subset)"
# GEMINI_API_KEY="$GEMINI_API_KEY" python "$PHASE3_DIR/pipeline.py" gemini \
#     --input "$INPUT_JSONL" \
#     --output "$GEMINI_OUT" \
#     --batch-size 10 \
#     --rate-limit-delay 4.0 \
#     --neo4j-uri "$NEO4J_URI" \
#     --neo4j-user "$NEO4J_USER" \
#     --neo4j-password "$NEO4J_PASSWORD"
#
# section "Phase 3-B: Load Gemini output into Neo4j"
# python "$PHASE3_DIR/pipeline.py" load-gemini \
#     --input "$GEMINI_OUT" \
#     --neo4j-uri "$NEO4J_URI" \
#     --neo4j-user "$NEO4J_USER" \
#     --neo4j-password "$NEO4J_PASSWORD"

# ── Phase 4: Qdrant setup ────────────────────────────────────────────────────
section "Phase 4-A: Start Qdrant (if not already running)"
if ! curl -sf "http://$QDRANT_HOST:$QDRANT_PORT/healthz" > /dev/null 2>&1; then
    log "Starting Qdrant via Docker..."
    docker run -d --name qdrant \
        -p 6333:6333 \
        -v "$(pwd)/qdrant_storage:/qdrant/storage" \
        qdrant/qdrant:latest
    sleep 5
    log "Qdrant started"
else
    log "Qdrant already running"
fi

# ── Phase 4: Embed CVEs ──────────────────────────────────────────────────────
section "Phase 4-B: Embed CVE descriptions"
mkdir -p "$EMBED_DIR"
python "$PHASE4_DIR/embedder.py" cves \
    --input "$INPUT_JSONL" \
    --output-dir "$EMBED_DIR" \
    --model "$EMBED_MODEL" \
    --batch-size 256

# ── Phase 4: Embed ATT&CK techniques ────────────────────────────────────────
section "Phase 4-C: Embed ATT&CK techniques"
python "$PHASE4_DIR/embedder.py" attack \
    --output-dir "$EMBED_DIR" \
    --model "$EMBED_MODEL" \
    --neo4j-uri "$NEO4J_URI" \
    --neo4j-user "$NEO4J_USER" \
    --neo4j-password "$NEO4J_PASSWORD"

# ── Phase 4: Load into Qdrant ────────────────────────────────────────────────
section "Phase 4-D: Load embeddings into Qdrant"
python "$PHASE4_DIR/qdrant_loader.py" \
    --qdrant-host "$QDRANT_HOST" \
    --qdrant-port "$QDRANT_PORT" \
    cves \
    --embeddings "$EMBED_DIR/cve_embeddings.npy" \
    --metadata   "$EMBED_DIR/cve_metadata.jsonl"

python "$PHASE4_DIR/qdrant_loader.py" \
    --qdrant-host "$QDRANT_HOST" \
    --qdrant-port "$QDRANT_PORT" \
    attack \
    --embeddings "$EMBED_DIR/attack_embeddings.npy" \
    --metadata   "$EMBED_DIR/attack_metadata.jsonl"

python "$PHASE4_DIR/qdrant_loader.py" \
    --qdrant-host "$QDRANT_HOST" \
    --qdrant-port "$QDRANT_PORT" \
    stats

# ── Phase 5: Start API ───────────────────────────────────────────────────────
section "Phase 5: Start investigator API"
log "Starting FastAPI on port 8000..."
NEO4J_URI="$NEO4J_URI" \
NEO4J_USER="$NEO4J_USER" \
NEO4J_PASSWORD="$NEO4J_PASSWORD" \
QDRANT_HOST="$QDRANT_HOST" \
QDRANT_PORT="$QDRANT_PORT" \
EMBED_MODEL="$EMBED_MODEL" \
uvicorn phase4.api:app --host 0.0.0.0 --port 8000 --reload

log "Done. API running at http://localhost:8000"
log "Docs at http://localhost:8000/docs"
