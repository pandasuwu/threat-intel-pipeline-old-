"""
Phase 3 Validation — Spot-check queries to run after structural load.
Execute these in Neo4j Browser or via this script.

Run:
  python validate.py --neo4j-password your_password
"""

import argparse
from neo4j import GraphDatabase


QUERIES = [
    (
        "Total node counts by type",
        "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC",
    ),
    (
        "Total edge counts by type",
        "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS cnt ORDER BY cnt DESC",
    ),
    (
        "Sample high-severity CVEs with ATT&CK connections",
        """
        MATCH (v:Vulnerability)-[r:PATTERN_OF]->(t:Technique)
        WHERE v.cvss_score >= 9.0
        RETURN v.cve_id, v.cvss_score, v.severity, r.cwe_id, t.attack_id, t.name
        LIMIT 10
        """,
    ),
    (
        "Most connected ATT&CK techniques (top 10 by CVE count)",
        """
        MATCH (v:Vulnerability)-[:PATTERN_OF]->(t:Technique)
        RETURN t.attack_id, t.name, count(v) AS cve_count
        ORDER BY cve_count DESC LIMIT 10
        """,
    ),
    (
        "Tactic coverage — CVEs per tactic via technique",
        """
        MATCH (v:Vulnerability)-[:PATTERN_OF]->(t:Technique)-[:ENABLES_TACTIC]->(tac:Tactic)
        RETURN tac.name, count(DISTINCT v) AS cve_count
        ORDER BY cve_count DESC
        """,
    ),
    (
        "Critical CVEs (CVSS >= 9.0) by CWE distribution",
        """
        MATCH (v:Vulnerability)
        WHERE v.cvss_score >= 9.0
        UNWIND v.cwe_ids AS cwe
        RETURN cwe, count(v) AS cnt
        ORDER BY cnt DESC LIMIT 15
        """,
    ),
    (
        "Vulnerabilities NOT connected to any ATT&CK technique (no CWE mapping)",
        """
        MATCH (v:Vulnerability)
        WHERE NOT (v)-[:PATTERN_OF]->()
        RETURN count(v) AS unconnected
        """,
    ),
    (
        "CVE → ATT&CK path example (Log4Shell if loaded)",
        """
        MATCH (v:Vulnerability {cve_id: 'CVE-2021-44228'})-[r:PATTERN_OF]->(t:Technique)
        RETURN v.cve_id, v.cvss_score, r.cwe_id, t.attack_id, t.name
        """,
    ),
    (
        "ExtractedSW nodes (from Gemini, if run)",
        """
        MATCH (v:Vulnerability)-[:AFFECTS]->(s:ExtractedSW)
        RETURN s.name, count(v) AS cve_count
        ORDER BY cve_count DESC LIMIT 20
        """,
    ),
]


def run_validation(uri: str, user: str, password: str):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        for title, query in QUERIES:
            print(f"\n{'='*60}")
            print(f"  {title}")
            print(f"{'='*60}")
            try:
                results = session.run(query).data()
                if not results:
                    print("  (no results)")
                else:
                    for row in results:
                        print(" ", dict(row))
            except Exception as e:
                print(f"  ERROR: {e}")
    driver.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--neo4j-uri",      default="bolt://localhost:7687")
    p.add_argument("--neo4j-user",     default="neo4j")
    p.add_argument("--neo4j-password", required=True)
    args = p.parse_args()
    run_validation(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
