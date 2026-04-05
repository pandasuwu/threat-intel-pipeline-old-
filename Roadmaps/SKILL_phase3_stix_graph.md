# SKILL: Phase 3 — STIX 2.1 Graph Construction & Relationship Extraction

> Read SKILL_project_context.md and SKILL_phase2_ner.md before this.
> Phase 3 begins when Phase 2 outputs are validated.

---

## Phase 3 Goal

Convert Phase 2 entity annotations into a STIX 2.1 knowledge graph stored in Neo4j.
Extract relationships between co-occurring entities using Gemini Flash + DSPy.
The result is a queryable graph where every node is a STIX object anchored to ATT&CK where possible.

---

## What We're Building On

### From imouiche/Threat-Intelligence-Knowledge-Graphs (TiKG)
Clone and study this repo. Key components to adopt:
- **Entity-Relation triple format**: `(entity_1, relation_type, entity_2)` stored as triples
- **Domain ontology-guided error control**: filter misclassified relation triples using a predefined ontology
- **Neo4j triple storage schema**: nodes = entities, edges = relation type + confidence

Relation types used in TiKG (adopt these):
```
uses, targets, mitigates, indicates, attributed-to, exploits, delivers, drops, communicates-with, related-to
```

### From IS5882/Open-CyKG
- **KG canonicalization**: entity fusion using word embeddings — merge "Cozy Bear", "APT29", "The Dukes" into one canonical node
- **Open IE triples**: (subject, predicate, object) extraction — use as input to relation classifier

### From TRAM (center-for-threat-informed-defense/tram)
- **Sentence → ATT&CK technique classifier**: plug into Phase 3 to classify each sentence's primary technique
- Steal the training data format and model registry pattern

---

## Step 1: STIX Object Generation

```python
import stix2
import uuid
from datetime import datetime

def entity_to_stix(entity: dict, source_doc: str) -> stix2.base._STIXBase:
    """Convert a resolved Phase 2 entity to a STIX 2.1 object."""
    
    now = datetime.utcnow()
    ext_ref = []
    
    if entity.get("resolved"):
        ext_ref = [stix2.ExternalReference(
            source_name="mitre-attack",
            external_id=entity["resolved"]["attack_id"]
        )]
    
    label = entity["label"]
    text = entity["resolved"]["canonical_name"] if entity.get("resolved") else entity["text"]
    
    if label == "Threat Actor":
        return stix2.ThreatActor(
            id=f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, text)}",
            name=text,
            created=now,
            modified=now,
            external_references=ext_ref,
            custom_properties={"x_source_doc": source_doc, "x_confidence": entity["confidence"]}
        )
    elif label == "Malware":
        return stix2.Malware(
            id=f"malware--{uuid.uuid5(uuid.NAMESPACE_DNS, text)}",
            name=text,
            is_family=False,
            created=now,
            modified=now,
            external_references=ext_ref,
            custom_properties={"x_source_doc": source_doc}
        )
    elif label == "Attack Pattern":
        return stix2.AttackPattern(
            id=f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, text)}",
            name=text,
            created=now,
            modified=now,
            external_references=ext_ref
        )
    elif label == "Vulnerability":
        return stix2.Vulnerability(
            id=f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, text)}",
            name=text,
            created=now,
            modified=now,
            external_references=ext_ref
        )
    else:
        return stix2.Identity(
            id=f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, text)}",
            name=text,
            identity_class="system",
            created=now,
            modified=now
        )
```

**Critical:** Use `uuid.uuid5(uuid.NAMESPACE_DNS, canonical_name)` for deterministic IDs — same entity always gets same STIX ID. This is how deduplication works.

---

## Step 2: Relationship Extraction with Gemini Flash + DSPy

### DSPy Setup
```python
import dspy

lm = dspy.LM("gemini/gemini-1.5-flash", api_key="YOUR_KEY", max_tokens=1024)
dspy.configure(lm=lm)
```

### Relation Extraction Signature
```python
class RelationExtraction(dspy.Signature):
    """Extract typed relationships between cybersecurity entities in a sentence.
    
    Valid relation types: uses, targets, exploits, mitigates, delivers, attributed-to, indicates, related-to
    Only extract relations with clear textual evidence. Do not infer.
    """
    
    sentence: str = dspy.InputField(desc="A sentence from a cybersecurity report")
    entities: str = dspy.InputField(desc="JSON list of entity dicts with text and label fields")
    relations: list[dict] = dspy.OutputField(
        desc="List of {subject, relation_type, object, evidence} dicts. Empty list if no clear relation."
    )

class RelationExtractor(dspy.Module):
    def __init__(self):
        self.extract = dspy.ChainOfThought(RelationExtraction)
    
    def forward(self, sentence, entities):
        result = self.extract(sentence=sentence, entities=str(entities))
        # Filter to valid relation types only
        valid_types = {"uses", "targets", "exploits", "mitigates", "delivers", 
                      "attributed-to", "indicates", "related-to"}
        filtered = [r for r in (result.relations or []) if r.get("relation_type") in valid_types]
        return filtered
```

### Batch Processing
```python
extractor = RelationExtractor()

def process_chunk(chunk: dict) -> list[stix2.Relationship]:
    """Process one document chunk → list of STIX Relationship objects."""
    text = chunk["text"]
    entities = chunk["entities"]
    
    if len(entities) < 2:
        return []  # Can't form a relationship with 0 or 1 entity
    
    relations = extractor(sentence=text, entities=entities)
    stix_relations = []
    
    for rel in relations:
        subj_entity = next((e for e in entities if e["text"] == rel["subject"]), None)
        obj_entity = next((e for e in entities if e["text"] == rel["object"]), None)
        
        if not subj_entity or not obj_entity:
            continue
        
        subj_stix_id = get_stix_id_for_entity(subj_entity)  # from your entity registry
        obj_stix_id = get_stix_id_for_entity(obj_entity)
        
        stix_rel = stix2.Relationship(
            relationship_type=rel["relation_type"],
            source_ref=subj_stix_id,
            target_ref=obj_stix_id,
            description=rel.get("evidence", ""),
            custom_properties={
                "x_source_doc": chunk["source_id"],
                "x_chunk_id": chunk["chunk_id"]
            }
        )
        stix_relations.append(stix_rel)
    
    return stix_relations
```

---

## Step 3: Neo4j Ingestion Schema

```cypher
// Node creation (use MERGE to deduplicate by STIX ID)
MERGE (n:ThreatActor {stix_id: $stix_id})
SET n.name = $name,
    n.attack_id = $attack_id,
    n.confidence = $confidence,
    n.source_docs = coalesce(n.source_docs, []) + [$source_doc]

// Relationship creation
MATCH (a {stix_id: $source_ref})
MATCH (b {stix_id: $target_ref})
MERGE (a)-[r:RELATION {type: $relation_type}]->(b)
SET r.evidence = $evidence,
    r.source_doc = $source_doc,
    r.confidence = $confidence
```

### Python batch loader
```python
from neo4j import GraphDatabase

def load_stix_bundle_to_neo4j(bundle: stix2.Bundle, driver):
    with driver.session() as session:
        for obj in bundle.objects:
            if obj.type in ("threat-actor", "malware", "attack-pattern", "vulnerability", "identity"):
                session.execute_write(upsert_node, obj)
            elif obj.type == "relationship":
                session.execute_write(upsert_relationship, obj)
```

---

## Step 4: TiKG-style Ontology Filtering

Adapt from `imouiche/Threat-Intelligence-Knowledge-Graphs`. The ontology defines valid (subject_type, relation, object_type) triples. Invalid combinations are filtered before graph insertion.

```python
VALID_TRIPLES = {
    ("Threat Actor", "uses", "Malware"),
    ("Threat Actor", "uses", "Attack Pattern"),
    ("Threat Actor", "targets", "Identity"),
    ("Malware", "exploits", "Vulnerability"),
    ("Malware", "delivers", "Malware"),
    ("Attack Pattern", "mitigates", "Attack Pattern"),
    ("Indicator", "indicates", "Malware"),
    ("Indicator", "indicates", "Threat Actor"),
}

def ontology_filter(subj_label, relation_type, obj_label) -> bool:
    return (subj_label, relation_type, obj_label) in VALID_TRIPLES
```

---

## Step 5: TRAM Technique Classification (adopt directly)

Clone TRAM and use its sentence-level ATT&CK classifier as a component:
```bash
git clone https://github.com/center-for-threat-informed-defense/tram
cd tram
pip install -r requirements/requirements.txt
tram attackdata load
tram pipeline load-training-data
tram pipeline train --model logreg  # or nn_cls for neural
```

Wrap the trained model:
```python
# After TRAM training, use it programmatically:
from tram.ml.base import ModelManager
model = ModelManager.get_model('logreg')
predictions = model.get_attack_technique_predictions(sentence_text)
# Returns list of (technique_id, confidence) tuples
```

Add the top prediction as an ATT&CK technique edge in Neo4j for each chunk.

---

## Output Validation Queries (run in Neo4j Browser)

```cypher
// Total graph size
MATCH (n) RETURN labels(n), count(n) ORDER BY count(n) DESC

// Richest threat actors (most connections)
MATCH (g:ThreatActor)-[r]->(t)
RETURN g.name, count(r) as degree ORDER BY degree DESC LIMIT 10

// CVE → exploited by which malware
MATCH (v:Vulnerability)<-[:RELATION {type:'exploits'}]-(m:Malware)
RETURN v.name, collect(m.name) LIMIT 20

// Source document coverage
MATCH (n) WHERE n.source_docs IS NOT NULL
RETURN n.source_docs, count(n)

// Unresolved entities (for manual review)
MATCH (n) WHERE n.attack_id IS NULL
RETURN labels(n), n.name LIMIT 50
```

---

## What Phase 4 Needs From You

1. Neo4j graph populated with STIX objects (target: >5,000 document-derived nodes)
2. `stix_bundles/` directory — one `.json` STIX bundle per source document
3. `unresolved_entities.jsonl` — entities not matched to ATT&CK (for novel entity tracking)
4. Graph quality report: node count by type, edge count by type, avg degree
