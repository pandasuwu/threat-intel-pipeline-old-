# architecture

Three diagrams, three levels of zoom.

1. **System architecture** — how the pieces fit.
2. **`/investigate` request flow** — what happens when you ask a question.
3. **Knowledge graph data model** — what's actually in Neo4j.

---

## 1. system architecture

```mermaid
flowchart TB
    subgraph SRC[" data sources "]
        CVE[("cvelistV5<br/>323k CVE records")]
        ATTACK[("MITRE ATT&CK<br/>STIX 2.1 bundle")]
        PDFS[("threat reports<br/>AT&T · ENISA · Microsoft")]
    end

    subgraph INGEST[" ingestion layer "]
        NORM["normalize_cves.py<br/>(CVE → JSONL)"]
        DOCL["docling parser<br/>(PDF → MD + JSON)"]
        STIX["stix_to_neo4j.py<br/>(ATT&CK → graph)"]
    end

    subgraph KNOW[" knowledge layer "]
        NEO[("Neo4j 5.13<br/>──────────<br/>325k nodes<br/>192k edges")]
        QDR[("Qdrant 1.7<br/>──────────<br/>249k CVE vectors<br/>691 ATT&CK vectors<br/>all-mpnet-base-v2")]
    end

    subgraph API[" retrieval + narrative "]
        FAST["FastAPI<br/>/search · /investigate<br/>/cve · /technique"]
        LLM["OpenRouter<br/>llama-3.1-8b-instruct"]
    end

    UI["vis-network UI<br/>(localhost:3000)"]

    CVE --> NORM --> NEO
    PDFS --> DOCL --> NEO
    ATTACK --> STIX --> NEO
    NORM --> QDR
    STIX --> QDR

    FAST --> QDR
    FAST --> NEO
    FAST -->|"grounded context only"| LLM
    LLM --> FAST
    FAST --> UI

    classDef src    fill:#e8f4f0,stroke:#2d8267,color:#1a3d2f
    classDef ing    fill:#fef3e2,stroke:#c47a1a,color:#5c3a0e
    classDef know   fill:#e8eef9,stroke:#3a5fa8,color:#1e2f54
    classDef api    fill:#f5e6f0,stroke:#a1467a,color:#4d2238
    classDef ui     fill:#f0e8d8,stroke:#8a6f3a,color:#3d3019

    class CVE,ATTACK,PDFS src
    class NORM,DOCL,STIX ing
    class NEO,QDR know
    class FAST,LLM api
    class UI ui
```

The arrow from FastAPI to the LLM is one-way and tightly bounded: only the
subgraph retrieved from Neo4j + the top-k vector hits cross that boundary.
The LLM never sees the raw corpus.

---

## 2. `/investigate` request flow

What happens when an analyst pastes a CVE or an incident description into
the UI:

```mermaid
sequenceDiagram
    autonumber
    participant U as Analyst (UI)
    participant API as FastAPI
    participant Q as Qdrant
    participant N as Neo4j
    participant L as LLM (OpenRouter)

    U->>API: POST /investigate {query}
    API->>API: embed(query) — all-mpnet-base-v2

    par vector retrieval
        API->>Q: top-k similar CVE vectors
        Q-->>API: [cve_id, score, payload] × k
    and ATT&CK retrieval
        API->>Q: top-k similar technique vectors
        Q-->>API: [tech_id, score, payload] × k
    end

    API->>N: MATCH subgraph<br/>(Vulnerability)-[:PATTERN_OF]->(AttackPattern)<br/>(AttackPattern)-[:USED_BY]->(Intrusion-Set)
    N-->>API: subgraph (nodes + edges)

    API->>API: serialize subgraph<br/>+ build grounded prompt<br/>(strict: narrate only what's here)

    API->>L: prompt + context
    L-->>API: narrative
    API-->>U: {narrative, subgraph, citations}

    Note over U,L: zero entities outside the subgraph<br/>can appear in the response
```

**Key invariant:** every entity name in the LLM's response must appear in
the subgraph payload. The frontend renders the subgraph in vis-network so
the analyst can visually trace any claim.

---

## 3. knowledge graph data model

What's in Neo4j after all loaders finish:

```mermaid
erDiagram
    Vulnerability ||--o{ CWE                : "has weakness"
    CWE           ||--o{ AttackPattern      : "maps to (PATTERN_OF)"
    AttackPattern }o--|| Tactic             : "kill-chain phase"
    AttackPattern }o--o{ IntrusionSet       : "used by"
    AttackPattern }o--o{ Malware            : "implemented by"
    AttackPattern }o--o{ Tool               : "implemented by"
    IntrusionSet  }o--o{ Malware            : "uses"
    Mitigation    }o--o{ AttackPattern      : "mitigates"

    Vulnerability {
        string  cve_id PK
        string  description
        string  cwe_id FK
        date    published
        date    modified
        float   cvss_score
        string  references
    }
    CWE {
        string id PK
        string name
        string description
    }
    AttackPattern {
        string  ext_id PK "T1190, T1059, …"
        string  stix_id
        string  name
        string  description
        string[] platforms
    }
    Tactic {
        string ext_id PK "TA0001, …"
        string name
    }
    IntrusionSet {
        string  stix_id PK
        string  name "APT29, FIN7, …"
        string  description
        string[] aliases
    }
    Malware {
        string  stix_id PK
        string  name
        string[] aliases
        string[] malware_types
    }
    Tool {
        string stix_id PK
        string name
    }
    Mitigation {
        string ext_id PK "M1041, …"
        string name
    }
```

### counts (current)

| node label       | count   |
|------------------|---------|
| Vulnerability    | 323,647 |
| AttackPattern    |   ~700  |
| Tactic           |    14   |
| IntrusionSet     |   ~150  |
| Malware          |   ~700  |
| Tool             |    ~80  |
| Mitigation       |    ~45  |
| **total nodes**  | **~325,400** |

| edge type        | count   |
|------------------|---------|
| PATTERN_OF       | 174,542 |
| (ATT&CK internal) | 18,022 |
| **total edges**  | **~192,500** |

### why two stores instead of one?

Neo4j answers structural questions: *what techniques is this CVE linked to,
which APTs are known to use them, what mitigations apply?* These are graph
traversals — Cypher is the right tool.

Qdrant answers semantic similarity: *find me CVEs that look like this
incident description even if the wording is different.* These are
vector-space queries — a graph DB would be the wrong tool.

The pipeline uses both: vector hits give you the entry points into the
graph, then graph traversal expands the context. This is the "hybrid"
in hybrid search.

---

## why this shape, not RAG-over-everything?

A naive design would dump the whole corpus into a vector store and let the
LLM RAG over it. We tried this in February. It hallucinates. The model
produced confident-sounding outputs citing CVE numbers that don't exist,
attributing campaigns to wrong groups, and inventing tool names.

The fix isn't a better prompt. The fix is to make hallucination
*structurally impossible*: only feed the LLM entities that already exist as
nodes in a verified graph. If an entity isn't in the subgraph, the LLM has
no token to generate that would reference it credibly. It has nowhere to
hallucinate *to*.

This is the core design decision. Everything else follows from it.
