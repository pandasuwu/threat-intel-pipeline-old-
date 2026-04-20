"""
eval.py — UNICC Pipeline Evaluation Script
===========================================
Measures investigative efficiency vs. manual baseline.
Metrics: avg latency, technique recall, actor recall, CVE recall.

Usage:
    python eval.py                        # full run, pretty-print + save results.json
    python eval.py --query-ids 0 3 7      # run subset by index
    python eval.py --endpoint http://...  # override base URL

Requirements:
    pip install requests tabulate colorama
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from tabulate import tabulate
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "http://localhost:8000"
RESULTS_FILE = "eval_results.json"

# ---------------------------------------------------------------------------
# Ground-truth test set  (20 queries)
#
# Conventions:
#   query_type  : "cve_id" | "technique_id" | "free_text"
#   hit_endpoint: which API endpoint carries the most signal for this query
#       "search"      → GET /search?q=<query>
#       "cve"         → GET /cve/<query>        (query IS the CVE-ID)
#       "technique"   → GET /technique/<query>  (query IS the ATT&CK ID)
#       "investigate" → POST /investigate {"query": <query>}
#   expected_techniques : ATT&CK IDs that MUST appear somewhere in response
#   expected_groups     : threat-actor canonical names (case-insensitive substring match)
#   expected_cves       : CVE IDs that MUST appear somewhere in response
#   manual_minutes      : conservative estimate of analyst time WITHOUT the tool
# ---------------------------------------------------------------------------

from eval_queries import TEST_QUERIES

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def search(base: str, q: str, timeout: int = 30) -> dict:
    r = requests.get(f"{base}/search", params={"q": q}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def cve_lookup(base: str, cve_id: str, timeout: int = 30) -> dict:
    r = requests.get(f"{base}/cve/{cve_id}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def technique_lookup(base: str, attack_id: str, timeout: int = 30) -> dict:
    r = requests.get(f"{base}/technique/{attack_id}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def investigate(base: str, query: str, timeout: int = 60) -> dict:
    r = requests.post(f"{base}/investigate", json={"query": query}, timeout=timeout)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Recall helpers
# ---------------------------------------------------------------------------

def _response_text(response: dict) -> str:
    """Flatten the full API response dict to a single searchable string."""
    return json.dumps(response).lower()


def recall(expected: list[str], text: str) -> tuple[float, list[str], list[str]]:
    """Return (recall_score, hits, misses) for a list of expected strings."""
    if not expected:
        return 1.0, [], []
    hits, misses = [], []
    for item in expected:
        if item.lower() in text:
            hits.append(item)
        else:
            misses.append(item)
    return len(hits) / len(expected), hits, misses


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class QueryResult:
    id: int
    label: str
    query: str
    hit_endpoint: str
    latency_ms: float
    error: Optional[str] = None

    technique_recall: float = 0.0
    technique_hits: list = field(default_factory=list)
    technique_misses: list = field(default_factory=list)

    actor_recall: float = 0.0
    actor_hits: list = field(default_factory=list)
    actor_misses: list = field(default_factory=list)

    cve_recall: float = 0.0
    cve_hits: list = field(default_factory=list)
    cve_misses: list = field(default_factory=list)

    manual_minutes: float = 0.0

    @property
    def overall_recall(self) -> float:
        scores = [
            s for s, exp in [
                (self.technique_recall, True),
                (self.actor_recall, True),
                (self.cve_recall, True),
            ]
        ]
        return sum(scores) / len(scores)

    @property
    def tool_minutes(self) -> float:
        return self.latency_ms / 60_000


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_query(tq: dict, base: str) -> QueryResult:
    qid = tq["id"]
    label = tq["label"]
    query = tq["query"]
    endpoint = tq["hit_endpoint"]

    result = QueryResult(
        id=qid,
        label=label,
        query=query,
        hit_endpoint=endpoint,
        latency_ms=0.0,
        manual_minutes=tq.get("manual_minutes", 0.0),
    )

    try:
        t0 = time.perf_counter()
        if endpoint == "cve":
            response = cve_lookup(base, query)
        elif endpoint == "technique":
            response = technique_lookup(base, query)
        elif endpoint == "investigate":
            response = investigate(base, query)
        else:  # "search" or fallback
            response = search(base, query)
        elapsed = (time.perf_counter() - t0) * 1000
        result.latency_ms = elapsed

        text = _response_text(response)
        r, h, m = recall(tq["expected_techniques"], text)
        result.technique_recall, result.technique_hits, result.technique_misses = r, h, m

        r, h, m = recall(tq["expected_groups"], text)
        result.actor_recall, result.actor_hits, result.actor_misses = r, h, m

        r, h, m = recall(tq["expected_cves"], text)
        result.cve_recall, result.cve_hits, result.cve_misses = r, h, m

    except requests.exceptions.ConnectionError:
        result.error = "CONNECTION_REFUSED — is the API running?"
    except requests.exceptions.Timeout:
        result.error = "TIMEOUT"
    except requests.exceptions.HTTPError as e:
        result.error = f"HTTP {e.response.status_code}"
    except Exception as e:
        result.error = str(e)

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def colour_recall(r: float) -> str:
    if r == 1.0:
        return Fore.GREEN + f"{r:.0%}" + Style.RESET_ALL
    if r >= 0.5:
        return Fore.YELLOW + f"{r:.0%}" + Style.RESET_ALL
    return Fore.RED + f"{r:.0%}" + Style.RESET_ALL


def print_summary(results: list[QueryResult]) -> None:
    rows = []
    for r in results:
        status = Fore.RED + r.error + Style.RESET_ALL if r.error else "OK"
        rows.append([
            r.id,
            r.label[:42],
            r.hit_endpoint,
            f"{r.latency_ms:.0f} ms" if not r.error else "—",
            colour_recall(r.technique_recall) if not r.error else "—",
            colour_recall(r.actor_recall) if not r.error else "—",
            colour_recall(r.cve_recall) if not r.error else "—",
            status,
        ])

    print("\n" + "═" * 100)
    print("  UNICC PIPELINE — EVALUATION RESULTS")
    print("═" * 100)
    print(tabulate(
        rows,
        headers=["#", "Label", "Endpoint", "Latency", "Tech↑", "Actor↑", "CVE↑", "Status"],
        tablefmt="simple",
    ))

    valid = [r for r in results if not r.error]
    if not valid:
        print("\nNo successful queries — check API connectivity.\n")
        return

    avg_latency = sum(r.latency_ms for r in valid) / len(valid)
    avg_tech = sum(r.technique_recall for r in valid) / len(valid)
    avg_actor = sum(r.actor_recall for r in valid) / len(valid)
    avg_cve = sum(r.cve_recall for r in valid) / len(valid)

    total_manual = sum(r.manual_minutes for r in valid)
    total_tool = sum(r.latency_ms for r in valid) / 60_000
    efficiency_gain = total_manual / total_tool if total_tool > 0 else float("inf")

    print("\n" + "─" * 60)
    print("  AGGREGATE METRICS")
    print("─" * 60)
    print(f"  Queries run          : {len(valid)} / {len(results)}")
    print(f"  Avg latency          : {avg_latency:.0f} ms")
    print(f"  Avg technique recall : {avg_tech:.1%}")
    print(f"  Avg actor recall     : {avg_actor:.1%}")
    print(f"  Avg CVE recall       : {avg_cve:.1%}")
    print()
    print(f"  Manual baseline est  : {total_manual:.0f} min  ({total_manual/60:.1f} h)")
    print(f"  Tool time            : {total_tool:.1f} min")
    print(f"  Efficiency multiplier: {efficiency_gain:.0f}×")
    print("─" * 60 + "\n")

    # Per-query misses — useful for debugging
    misses_exist = any(
        r.technique_misses or r.actor_misses or r.cve_misses
        for r in valid
    )
    if misses_exist:
        print("  MISSES (items not found in response):")
        for r in valid:
            m_all = (
                [f"TECH:{x}" for x in r.technique_misses]
                + [f"ACTOR:{x}" for x in r.actor_misses]
                + [f"CVE:{x}" for x in r.cve_misses]
            )
            if m_all:
                print(f"    [{r.id:02d}] {r.label[:40]}: {', '.join(m_all)}")
        print()


def save_results(results: list[QueryResult], path: str) -> None:
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_queries": len(results),
        "successful": len([r for r in results if not r.error]),
        "results": [asdict(r) for r in results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Results saved → {path}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="UNICC Pipeline Evaluation")
    p.add_argument("--endpoint", default=DEFAULT_BASE_URL,
                   help=f"API base URL (default: {DEFAULT_BASE_URL})")
    p.add_argument("--query-ids", nargs="+", type=int, default=None,
                   help="Run only specific query IDs (e.g. --query-ids 0 3 7)")
    p.add_argument("--output", default=RESULTS_FILE,
                   help=f"JSON output file (default: {RESULTS_FILE})")
    p.add_argument("--no-save", action="store_true",
                   help="Don't write results.json")
    return p.parse_args()


def main():
    args = parse_args()
    base = args.endpoint.rstrip("/")

    queries = TEST_QUERIES
    if args.query_ids is not None:
        id_set = set(args.query_ids)
        queries = [q for q in TEST_QUERIES if q["id"] in id_set]
        if not queries:
            print(f"No queries matched IDs: {args.query_ids}")
            sys.exit(1)

    print(f"\n  Target : {base}")
    print(f"  Queries: {len(queries)}\n")

    results = []
    for tq in queries:
        sys.stdout.write(f"  [{tq['id']:02d}] {tq['label'][:50]:<50s} ... ")
        sys.stdout.flush()
        r = run_query(tq, base)
        results.append(r)
        if r.error:
            print(Fore.RED + r.error)
        else:
            print(f"{r.latency_ms:.0f} ms")

    print_summary(results)

    if not args.no_save:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
