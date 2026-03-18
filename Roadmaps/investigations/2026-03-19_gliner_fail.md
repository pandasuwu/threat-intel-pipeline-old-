## GLiNER same problem

zero-shot GLiNER over a 1k CVE sample. same empty-entity pattern. confirms
hypothesis: it's not the model, it's the input. CVE descriptions don't contain
the entity types we want (actors, malware, campaigns) — they describe
vulnerabilities, not attacks.

decision: drop NER for the CVE corpus. for threat-report PDFs, NER still has a
role (narrative text). for CVEs, switch to:
  - pull CWE id from the structured field
  - join CWE -> ATT&CK technique via the official mapping
  - link in neo4j as (Vulnerability)-[:PATTERN_OF]->(AttackPattern)

this turns a failed retrieval problem into a deterministic graph join. better.
