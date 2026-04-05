# SKILL: Phase 2 — NER Extraction Execution Guide

> This skill tells an LLM exactly what to do to implement Phase 2 of the UNICC pipeline.
> Always read SKILL_project_context.md first to understand the broader project.

---

## Phase 2 Goal

Extract named entities from:
1. **323,647 CVE descriptions** in `cve_normalized.jsonl`
2. **8 parsed PDF reports** (AT&T, ENISA, Microsoft) in JSON format

Resolve all extracted entities against the Neo4j ATT&CK graph. Output: per-record entity annotations ready for STIX construction in Phase 3.

---

## Step 1: Confirm SLURM dry run passed

Before submitting the full array job, verify the single-shard dry run output exists:
```bash
ls /scratch/suhani/cyner_project/output/cve_shards/shard_000_entities.jsonl
# Should exist and have > 0 lines
head -5 /scratch/suhani/cyner_project/output/cve_shards/shard_000_entities.jsonl
```

Expected output format per line:
```json
{
  "cve_id": "CVE-2024-1212",
  "entities": [
    {"text": "LoadMaster", "label": "Software", "start": 12, "end": 22, "confidence": 0.94},
    {"text": "CWE-78", "label": "Vulnerability", "start": 45, "end": 51, "confidence": 0.99}
  ]
}
```

If `ModuleNotFoundError` persists: `pip install nltk && python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab')"`

---

## Step 2: Submit full CVE array job

```bash
# On Paramananta — confirm environment first
conda activate cyner_env   # or whatever your env is named
python -c "import cyner; print('ok')"

# Submit 50-shard array
sbatch /scratch/suhani/cyner_project/code/submit_ner_cves.sh

# Monitor
squeue -u suhani
# Watch logs
tail -f /scratch/suhani/cyner_project/logs/ner_cve_0.log
```

Expected runtime: ~2-4 hours for full 323k CVE corpus on Paramananta GPUs.

---

## Step 3: Submit PDF NER job

```bash
sbatch /scratch/suhani/cyner_project/code/submit_ner_pdfs.sh
# Each PDF processed separately; output: one JSONL per report
ls /scratch/suhani/cyner_project/output/pdfs/
```

---

## Step 4: Merge CVE shards

```bash
sbatch /scratch/suhani/cyner_project/code/merge_cve_shards.sh
# Output: /scratch/suhani/cyner_project/output/cve_entities_all.jsonl
wc -l /scratch/suhani/cyner_project/output/cve_entities_all.jsonl
# Should be ≈ 323,647
```

---

## Step 5: GLiNER gap-filling (run locally or on Paramananta)

CyNER entity coverage gaps — these types need GLiNER:
- `Campaign`, `Identity`, `Location`, `Infrastructure`

```python
from gliner import GLiNER

model = GLiNER.from_pretrained("urchade/gliner_medium-v2.1")
labels = ["Campaign", "Identity", "Location", "Infrastructure", "Threat Actor", "Malware"]

def gliner_extract(text):
    entities = model.predict_entities(text, labels, threshold=0.5)
    return [{"text": e["text"], "label": e["label"], "confidence": e["score"]} for e in entities]
```

Run only on PDF chunks (not CVE descriptions — CyNER handles those well).

---

## Step 6: Entity Resolution against Neo4j

This is the most critical step. Every extracted entity must attempt resolution against the ATT&CK graph.

```python
from neo4j import GraphDatabase
from rapidfuzz import fuzz
import numpy as np

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

def resolve_entity(entity_text: str, entity_label: str, threshold: float = 0.85):
    """Returns (attack_id, canonical_name, confidence) or None if unresolved."""
    
    label_to_node = {
        "Malware": "Software",
        "Tool": "Software", 
        "Threat Actor": "Group",
        "Attack Pattern": "Technique",
        "Vulnerability": "Technique",  # fallback if no CVE match
    }
    
    node_label = label_to_node.get(entity_label, entity_label)
    
    with driver.session() as session:
        # Exact match first (fast, uses index)
        result = session.run(
            f"MATCH (n:{node_label}) WHERE n.name = $name OR $name IN n.aliases "
            "RETURN n.attack_id, n.name LIMIT 1",
            name=entity_text
        )
        record = result.single()
        if record:
            return record["n.attack_id"], record["n.name"], 1.0
        
        # Fuzzy match fallback
        candidates = session.run(
            f"MATCH (n:{node_label}) RETURN n.attack_id, n.name, n.aliases LIMIT 500"
        ).data()
        
        best_score, best_candidate = 0, None
        for c in candidates:
            score = fuzz.token_sort_ratio(entity_text.lower(), c["n.name"].lower()) / 100
            aliases = c.get("n.aliases") or []
            alias_score = max((fuzz.token_sort_ratio(entity_text.lower(), a.lower()) / 100 
                              for a in aliases), default=0)
            final_score = max(score, alias_score)
            if final_score > best_score:
                best_score, best_candidate = final_score, c
        
        if best_score >= threshold and best_candidate:
            return best_candidate["n.attack_id"], best_candidate["n.name"], best_score
        
        return None  # Unresolved — novel entity, flag for manual review
```

---

## Step 7: Evaluation

Annotate 50–100 sentences from your PDF corpus using **LabelStudio** (free, local):
```bash
pip install label-studio
label-studio start --port 8080
```

Import your PDF chunk JSONL, create a NER project with these labels:
`Malware, Threat Actor, Vulnerability, Attack Pattern, Tool, Indicator, Campaign`

Compute precision/recall per entity type. **Target: >80% precision on Threat Actor, Malware, CVE ID.**

---

## Output Schema (per record, feeds Phase 3)

```json
{
  "source": "pdf",
  "source_id": "enisa_threat_landscape_2024",
  "chunk_id": "chunk_042",
  "text": "APT29 leveraged CVE-2023-23397...",
  "entities": [
    {
      "text": "APT29",
      "label": "Threat Actor",
      "model": "CyNER",
      "confidence": 0.96,
      "resolved": {
        "attack_id": "G0016",
        "canonical_name": "APT29",
        "resolution_score": 1.0
      }
    },
    {
      "text": "CVE-2023-23397",
      "label": "Vulnerability",
      "model": "CyNER",
      "confidence": 0.99,
      "resolved": null  // CVE IDs resolve against cve_normalized.jsonl, not ATT&CK
    }
  ]
}
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| SLURM job OOM | Reduce `--batch-size` in ner_worker.py, increase `--mem` in SLURM script |
| CyNER misses CVE IDs | Add regex post-processor: `re.findall(r'CVE-\d{4}-\d{4,7}', text)` |
| Low precision on Threat Actor | Increase confidence threshold to 0.85, enable ontology filtering |
| Neo4j connection refused | `systemctl start neo4j` or check bolt port 7687 |
| Empty shard output | Check GPU allocation in SLURM script — model won't load on CPU-only node |

---

## What Phase 3 Needs From You

Before moving to Phase 3, produce:
1. `cve_entities_all.jsonl` — all 323k CVEs with entity annotations
2. `pdf_entities_{report_name}.jsonl` — one file per PDF report
3. `resolution_report.json` — % resolved per entity type, novel entities list
4. Evaluation report: precision/recall table from LabelStudio annotations
