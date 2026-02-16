# threat intel pipeline — master roadmap

WIP planning doc.

## phases

- p1: ingest CVEs (cvelistV5 + NVD enrichment) + parse threat reports (AT&T, ENISA, MS)
- p2: domain NER over the corpus
- p3: build knowledge graph (Neo4j)
- p4: retrieval + narrative generation
- p5: eval

## stakeholders

- UNICC (United Nations International Computing Centre) — primary
- Prof. Sameer Kulkarni (IITGN) — supervisor
- Dr. Rajeev Shorey — faculty advisor

## SOW deliverables

- summarize threat landscape reports
- extract key info from source materials
- searchability across historical event logs / threat reports
- enriched contextual analysis for incident response

## decisions log

- 2026-02-16: pdfplumber drops table structure. trying docling next.
