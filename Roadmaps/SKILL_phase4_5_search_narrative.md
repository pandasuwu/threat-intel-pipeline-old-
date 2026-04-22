# SKILL: Phase 4 & 5 — Hybrid Search + Narrative Generation + UI

> Read SKILL_project_context.md, SKILL_phase2_ner.md, SKILL_phase3_stix_graph.md first.

---

## Phase 4 Goal: Hybrid Search Layer

Build a unified query API that answers investigator questions by combining:
- **Semantic vector search** (Qdrant): "what's similar to this incident?"
- **Structured graph traversal** (Neo4j Cypher): "what techniques has APT29 used?"

This directly satisfies SOW requirement: "enabling searchability across historical event logs and threat reports."

---

## Step 1: Embeddings with SecBERT

```python
from sentence_transformers import SentenceTransformer
import qdrant_client
from qdrant_client.models import Distance, VectorParams, PointStruct

# Use SecBERT for domain-adapted embeddings
model = SentenceTransformer("AI-Growth-Lab/SecBERT")
# Fallback: "sentence-transformers/all-mpnet-base-v2" (better recall, less domain-specific)

client = qdrant_client.QdrantClient("localhost", port=6333)

# Create collection
client.create_collection(
    collection_name="threat_intel_chunks",
    vectors_config=VectorParams(size=768, distance=Distance.COSINE),
)

def embed_and_store(chunks: list[dict]):
    """Embed document chunks and store in Qdrant with full metadata payload."""
    texts = [c["text"] for c in chunks]
    embeddings = model.encode(texts, batch_size=64, show_progress_bar=True)
    
    points = []
    for i, (chunk, emb) in enumerate(zip(chunks, embeddings)):
        points.append(PointStruct(
            id=chunk["chunk_id_int"],  # Qdrant needs integer or UUID
            vector=emb.tolist(),
            payload={
                "text": chunk["text"],
                "source_doc": chunk["source_id"],
                "chunk_id": chunk["chunk_id"],
                "entities": [e["text"] for e in chunk.get("entities", [])],
                "stix_ids": [e["resolved"]["stix_id"] for e in chunk.get("entities", []) 
                            if e.get("resolved")],
            }
        ))
    
    client.upsert(collection_name="threat_intel_chunks", points=points)
```

---

## Step 2: Hybrid Query Function

```python
from neo4j import GraphDatabase
from qdrant_client.models import Filter, FieldCondition, MatchValue

neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

def hybrid_search(query: str, top_k: int = 10, alpha: float = 0.6) -> list[dict]:
    """
    alpha: weight for vector score vs graph score.
    alpha=1.0 → pure vector, alpha=0.0 → pure graph.
    """
    
    # 1. Vector search
    query_embedding = model.encode([query])[0].tolist()
    vector_results = client.search(
        collection_name="threat_intel_chunks",
        query_vector=query_embedding,
        limit=top_k * 2,
        with_payload=True
    )
    
    # 2. Extract entities from query (use CyNER or regex)
    query_entities = extract_entities_from_query(query)  # returns list of entity texts
    
    # 3. Graph traversal for each extracted entity
    graph_results = []
    if query_entities:
        with neo4j_driver.session() as session:
            for entity_text in query_entities:
                results = session.run("""
                    MATCH (n) WHERE n.name CONTAINS $name OR $name IN n.aliases
                    MATCH (n)-[r*1..2]-(related)
                    RETURN n.name, type(r[0]) as rel_type, related.name, 
                           related.stix_id, related.source_docs
                    LIMIT 50
                """, name=entity_text).data()
                graph_results.extend(results)
    
    # 4. Merge and score
    scored = {}
    for r in vector_results:
        chunk_id = r.payload["chunk_id"]
        scored[chunk_id] = {
            "payload": r.payload,
            "vector_score": r.score,
            "graph_score": 0.0,
            "final_score": alpha * r.score
        }
    
    # Boost chunks that contain graph-matched entities
    for gr in graph_results:
        for chunk_id, item in scored.items():
            if gr.get("n.name") in item["payload"].get("entities", []):
                item["graph_score"] += 0.1
                item["final_score"] = alpha * item["vector_score"] + (1-alpha) * item["graph_score"]
    
    # Sort and return top_k
    ranked = sorted(scored.values(), key=lambda x: x["final_score"], reverse=True)
    return ranked[:top_k]
```

---

## Step 3: Historical Threat Reference Endpoint

This is the core SOW deliverable: "identifying previously observed threats."

```python
def find_similar_historical_threats(
    new_indicator: str,  # e.g. "CVE-2024-12345" or TTP description
    top_k: int = 5
) -> dict:
    """
    Given a new IOC or TTP description, find historically similar incidents.
    Returns ranked list of matches with graph context.
    """
    results = hybrid_search(new_indicator, top_k=top_k, alpha=0.5)
    
    enriched = []
    for r in results:
        # Pull full graph context for this chunk's STIX IDs
        stix_ids = r["payload"].get("stix_ids", [])
        with neo4j_driver.session() as session:
            context = session.run("""
                MATCH (n) WHERE n.stix_id IN $ids
                OPTIONAL MATCH (n)-[rel]->(neighbor)
                RETURN n.name, n.attack_id, collect({
                    rel: type(rel), 
                    neighbor: neighbor.name, 
                    neighbor_attack_id: neighbor.attack_id
                }) as connections
            """, ids=stix_ids).data()
        
        enriched.append({
            "text": r["payload"]["text"],
            "source_doc": r["payload"]["source_doc"],
            "similarity_score": r["final_score"],
            "graph_context": context
        })
    
    return {"query": new_indicator, "matches": enriched}
```

---

## Phase 5 Goal: Narrative Generation & Investigator UI

---

## Step 4: DSPy Narrative Pipeline

```python
import dspy

class NarrativeGeneration(dspy.Signature):
    """Generate a concise investigative narrative from threat intelligence context.
    
    Rules:
    - Be factual. Only assert what's evidenced in the provided context.
    - Use ATT&CK technique IDs where available (e.g. T1059.001).
    - Structure: who → what → how → historical precedent → mitigation pointer.
    - Target length: 150-250 words. Investigators are busy.
    - Do NOT speculate. Flag uncertainty explicitly.
    """
    
    query: str = dspy.InputField(desc="The investigator's question or new threat indicator")
    retrieved_chunks: str = dspy.InputField(desc="JSON-serialized list of similar historical chunks with metadata")
    graph_context: str = dspy.InputField(desc="Relevant ATT&CK graph paths as JSON")
    narrative: str = dspy.OutputField(desc="Structured investigative narrative in plain English")
    confidence: str = dspy.OutputField(desc="HIGH/MEDIUM/LOW + one sentence justification")

class InvestigativeNarrativePipeline(dspy.Module):
    def __init__(self):
        self.search = hybrid_search  # from Phase 4
        self.generate = dspy.ChainOfThought(NarrativeGeneration)
    
    def forward(self, query: str) -> dict:
        # Retrieve
        results = self.search(query, top_k=8)
        graph_ctx = get_graph_context_for_results(results)  # your Neo4j traversal function
        
        # Generate
        output = self.generate(
            query=query,
            retrieved_chunks=str([r["payload"] for r in results]),
            graph_context=str(graph_ctx)
        )
        
        return {
            "query": query,
            "narrative": output.narrative,
            "confidence": output.confidence,
            "sources": [r["payload"]["source_doc"] for r in results],
            "graph_paths": graph_ctx
        }
```

### DSPy Optimization (run once, save compiled module)
```python
# Manually create 10-20 (query, good_narrative) training examples
trainset = [
    dspy.Example(
        query="APT29 campaign targeting email servers 2023",
        narrative="APT29 (Cozy Bear, G0016) conducted...",
    ).with_inputs("query"),
    # ... more examples
]

optimizer = dspy.MIPROv2(metric=narrative_quality_metric, num_trials=20)
compiled_pipeline = optimizer.compile(InvestigativeNarrativePipeline(), trainset=trainset)
compiled_pipeline.save("compiled_narrative_pipeline.json")
```

---

## Step 5: FastAPI Backend

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="UNICC Threat Intelligence API")
pipeline = InvestigativeNarrativePipeline()

class QueryRequest(BaseModel):
    query: str
    top_k: int = 5

@app.post("/investigate")
async def investigate(request: QueryRequest):
    """Main endpoint: investigative narrative from free-text query."""
    return pipeline(request.query)

@app.get("/similar/{indicator}")
async def similar_threats(indicator: str, top_k: int = 5):
    """Find historically similar threats to a given IOC or TTP."""
    return find_similar_historical_threats(indicator, top_k)

@app.get("/graph/entity/{name}")
async def entity_graph(name: str):
    """Return 2-hop graph neighborhood for neovis.js rendering."""
    with neo4j_driver.session() as session:
        result = session.run("""
            MATCH (n) WHERE n.name CONTAINS $name
            MATCH path = (n)-[*1..2]-()
            RETURN path LIMIT 100
        """, name=name)
        return {"paths": result.data()}

@app.get("/health")
async def health():
    return {"status": "ok"}
```

---

## Step 6: Minimal Investigator UI

```bash
mkdir ui && cd ui
# Create index.html with neovis.js + fetch to FastAPI
```

Key neovis.js config:
```javascript
const config = {
    serverBoltUrl: "bolt://localhost:7687",
    serverUser: "neo4j",
    serverPassword: "password",
    labels: {
        ThreatActor: { caption: "name", size: "pagerank", community: "community" },
        Malware: { caption: "name", size: "degree" },
        Technique: { caption: "attack_id" }
    },
    relationships: {
        RELATION: { caption: "type", thickness: "confidence" }
    },
    initialCypher: "MATCH (n)-[r]->(m) RETURN n,r,m LIMIT 100"
};
const viz = new NeoVis.default(config);
viz.render();
```

---

## Step 7: Evaluation Against SOW (August 2026)

Create a test set of 20 investigative queries with ground-truth answers:

```python
TEST_QUERIES = [
    {
        "query": "Is CVE-2023-23397 associated with any known threat actor?",
        "expected_actor": "APT28",
        "expected_technique": "T1566.001"
    },
    # ... 19 more
]

def evaluate_pipeline(pipeline, test_queries):
    results = []
    for tq in test_queries:
        import time
        t0 = time.time()
        output = pipeline(tq["query"])
        latency = time.time() - t0
        
        results.append({
            "query": tq["query"],
            "latency_s": latency,
            "correct_actor": tq["expected_actor"] in output["narrative"],
            "correct_technique": tq["expected_technique"] in output["narrative"],
        })
    
    print(f"Avg latency: {sum(r['latency_s'] for r in results)/len(results):.2f}s")
    print(f"Actor recall: {sum(r['correct_actor'] for r in results)/len(results):.0%}")
    print(f"Technique recall: {sum(r['correct_technique'] for r in results)/len(results):.0%}")
```

---

## Deployment Checklist (August 2026)

- [ ] Neo4j running with full ATT&CK + document-derived graph
- [ ] Qdrant populated with all chunk embeddings
- [ ] FastAPI running (Docker or systemd)
- [ ] neovis.js UI accessible on localhost
- [ ] Evaluation report: latency, precision, recall on 20-query test set
- [ ] `README.md` with setup instructions, architecture diagram, sample queries
- [ ] STIX bundles exported for each source document
- [ ] GitHub repo clean: no API keys, no internal UNICC data
