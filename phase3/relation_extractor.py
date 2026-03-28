"""
Phase 3: Relation Extractor — Gemini Flash + DSPy
Extracts (software_product, relation_type, vulnerability) triples from CVE descriptions.

Scope (CVE-specific):
  CVE descriptions are short (1-3 sentences) and describe vulnerabilities in software products.
  The relevant entity here is the AFFECTED SOFTWARE — not threat actors or malware.
  We extract: what software is affected, and what the attack class is.

Example input:
  "Buffer overflow in Microsoft Internet Explorer 6.0 allows remote attackers
   to execute arbitrary code via a crafted HTML page."

Expected output:
  [{
    "software": "Microsoft Internet Explorer 6.0",
    "relation": "affects",
    "evidence": "Buffer overflow in Microsoft Internet Explorer 6.0",
    "attack_class": "buffer overflow"
  }]

This is intentionally narrow. We are NOT trying to extract:
  - Threat actors (CVE descriptions don't name them)
  - IOCs (not present in CVE text)
  - Malware families (extremely rare in CVE descriptions)

The STIX output is: Vulnerability -[AFFECTS]-> ExtractedSW

Run only on HIGH-QUALITY subset:
  - CVSS score >= 7.0 (High/Critical)
  - Published date >= 2015 (pre-2015 descriptions are too sparse)
  Estimated: ~80-100k records out of 323k

Rate limiting:
  - Gemini Flash free tier: 15 requests/min, 1M tokens/day
  - Gemini Flash paid: 2000 requests/min
  - Default: 5 concurrent requests, 0.5s delay between batches
  - Use --batch-size 20 with free tier
"""

import json
import logging
import time
import os
from typing import Optional

import dspy

logger = logging.getLogger(__name__)


# ── DSPy Signatures ─────────────────────────────────────────────────────────

class CVESoftwareExtraction(dspy.Signature):
    """
    Extract software products mentioned in a CVE description.

    Rules:
    - Only extract explicitly named software products (product name + optional version).
    - Include vendor name if mentioned (e.g. "Microsoft Internet Explorer 6.0", not just "IE").
    - Do NOT infer software not mentioned by name.
    - Do NOT extract generic terms like "web application", "server", "browser".
    - Return empty list if no specific product name is present.
    - Each item: {"software": "<name>", "evidence": "<exact phrase from text>"}
    """
    description: str = dspy.InputField(desc="CVE description text")
    cve_id: str = dspy.InputField(desc="CVE identifier for context")
    software_entities: list[dict] = dspy.OutputField(
        desc="List of {software, evidence} dicts. Empty list if none found."
    )


class CVERelationClassification(dspy.Signature):
    """
    Classify the relationship between a CVE and an affected software product.

    Given the CVE description and a software product name, determine:
    1. The relationship type (always 'affects' for CVEs — software is the affected party)
    2. The attack class (e.g. 'buffer overflow', 'SQL injection', 'XSS', 'use-after-free')
    3. The attack impact (e.g. 'remote code execution', 'privilege escalation', 'DoS', 'info disclosure')

    Be precise. Use exact terminology from the description. Do not hallucinate impact if not stated.
    """
    description: str = dspy.InputField(desc="CVE description text")
    software: str = dspy.InputField(desc="The affected software product name")
    relation_type: str = dspy.OutputField(desc="Always 'affects' for CVEs")
    attack_class: str = dspy.OutputField(desc="Technical vulnerability class (e.g. 'buffer overflow')")
    attack_impact: str = dspy.OutputField(desc="Attack outcome (e.g. 'remote code execution') or empty string")


# ── Extractor Module ─────────────────────────────────────────────────────────

class CVERelationExtractor(dspy.Module):
    """
    Two-stage extraction:
    Stage 1: Extract named software products from description
    Stage 2: Classify relationship + attack metadata per software
    """

    def __init__(self):
        self.extract_sw = dspy.ChainOfThought(CVESoftwareExtraction)
        self.classify = dspy.Predict(CVERelationClassification)

    def forward(self, description: str, cve_id: str) -> list[dict]:
        """
        Returns list of relation triples:
        [{
            "software": str,
            "relation": "affects",
            "attack_class": str,
            "attack_impact": str,
            "evidence": str,
        }]
        """
        # Stage 1: find software names
        try:
            sw_result = self.extract_sw(description=description, cve_id=cve_id)
            software_entities = sw_result.software_entities or []
        except Exception as e:
            logger.warning(f"SW extraction failed for {cve_id}: {e}")
            return []

        if not software_entities:
            return []

        triples = []
        for sw_ent in software_entities:
            sw_name = sw_ent.get("software", "").strip()
            if not sw_name or len(sw_name) < 3:
                continue

            # Stage 2: classify
            try:
                cls_result = self.classify(description=description, software=sw_name)
                triples.append({
                    "software":      sw_name,
                    "relation":      "affects",
                    "attack_class":  cls_result.attack_class or "",
                    "attack_impact": cls_result.attack_impact or "",
                    "evidence":      sw_ent.get("evidence", ""),
                })
            except Exception as e:
                logger.warning(f"Classification failed for {cve_id} / {sw_name}: {e}")
                # Still emit the software with minimal metadata
                triples.append({
                    "software":      sw_name,
                    "relation":      "affects",
                    "attack_class":  "",
                    "attack_impact": "",
                    "evidence":      sw_ent.get("evidence", ""),
                })

        return triples


# ── Batch runner ─────────────────────────────────────────────────────────────

def setup_gemini(api_key: Optional[str] = None, model: str = "gemini/gemini-1.5-flash"):
    """Configure DSPy with Gemini Flash. Call once before using extractor."""
    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError(
            "Gemini API key required. Set GEMINI_API_KEY env var or pass api_key="
        )
    lm = dspy.LM(model, api_key=key, max_tokens=1024)
    dspy.configure(lm=lm)
    logger.info(f"DSPy configured with {model}")


def is_high_quality(record: dict) -> bool:
    """
    Filter to records worth running Gemini on.
    High-quality = CVSS >= 7.0 AND published >= 2015 AND description length >= 50 chars.
    """
    cvss = record.get("cvss_score")
    if cvss is None or float(cvss) < 7.0:
        return False
    date = record.get("published_date") or ""
    if date[:4] < "2015":
        return False
    desc = record.get("description") or ""
    return len(desc) >= 50


def run_extraction_batch(
    records: list[dict],
    extractor: CVERelationExtractor,
    output_path: str,
    rate_limit_delay: float = 0.5,
) -> dict:
    """
    Process a list of CVE records and write results to JSONL.

    Output format per line:
    {
        "cve_id": "CVE-2023-12345",
        "description": "...",
        "triples": [
            {"software": "Apache Log4j 2.14.1", "relation": "affects",
             "attack_class": "JNDI injection", "attack_impact": "remote code execution",
             "evidence": "..."}
        ]
    }
    """
    stats = {"processed": 0, "with_triples": 0, "total_triples": 0, "errors": 0}

    with open(output_path, "a", encoding="utf-8") as out:
        for record in records:
            cve_id = record.get("cve_id", "UNKNOWN")
            desc = record.get("description", "")

            try:
                triples = extractor(description=desc, cve_id=cve_id)
                result = {
                    "cve_id":      cve_id,
                    "description": desc,
                    "triples":     triples,
                }
                out.write(json.dumps(result) + "\n")

                stats["processed"] += 1
                if triples:
                    stats["with_triples"] += 1
                    stats["total_triples"] += len(triples)

                time.sleep(rate_limit_delay)

            except Exception as e:
                logger.error(f"Failed on {cve_id}: {e}")
                stats["errors"] += 1

    return stats
