"""Quick profiling of cve_normalized.jsonl - runs wherever the file is."""
import json, sys
from collections import Counter
from pathlib import Path

# Accept path as arg or search common locations
candidates = [
    Path("cve_normalized.jsonl"),
    Path.home() / "Workspace" / "cve_normalized.jsonl",
    Path.home() / "data" / "json" / "cve_normalized.jsonl",
]
if len(sys.argv) > 1:
    candidates.insert(0, Path(sys.argv[1]))

src = next((p for p in candidates if p.exists()), None)
if not src:
    print("Cannot find cve_normalized.jsonl. Pass path as argument.")
    sys.exit(1)

print(f"Profiling: {src}\n")

total = has_cvss = has_cwe = has_products = has_desc = 0
year_counter     = Counter()
severity_counter = Counter()
cwe_counter      = Counter()
vendor_counter   = Counter()
both_cvss_cwe    = cvss_only = cwe_only = neither = 0

with open(src) as f:
    for line in f:
        r = json.loads(line)
        total += 1

        # Year breakdown
        pub = r.get("published_date") or ""
        year = pub[:4] if pub else "unknown"
        year_counter[year] += 1

        # Field presence
        has_d = bool(r.get("description"))
        has_c = bool(r.get("cvss_v3"))
        has_w = bool(r.get("cwe_ids"))
        has_p = bool(r.get("affected_products"))

        has_desc     += has_d
        has_cvss     += has_c
        has_cwe      += has_w
        has_products += has_p

        # CVSS × CWE combinations
        if has_c and has_w:   both_cvss_cwe += 1
        elif has_c:           cvss_only     += 1
        elif has_w:           cwe_only      += 1
        else:                 neither       += 1

        # Severity distribution
        if has_c:
            severity_counter[r["cvss_v3"]["severity"]] += 1

        # Top CWEs
        for cw in (r.get("cwe_ids") or []):
            cwe_counter[cw] += 1

        # Top vendors
        for p in (r.get("affected_products") or []):
            v = p.get("vendor", "").strip()
            if v and v.lower() not in ("n/a", "unknown", ""):
                vendor_counter[v] += 1

pct = lambda n: f"{n:>7,}  ({100*n/total:5.1f}%)"

print("=" * 56)
print("FIELD COVERAGE")
print("=" * 56)
print(f"  Total records    : {total:,}")
print(f"  Has description  : {pct(has_desc)}")
print(f"  Has CVSS v3      : {pct(has_cvss)}")
print(f"  Has CWE          : {pct(has_cwe)}")
print(f"  Has products     : {pct(has_products)}")

print()
print("CVSS × CWE COMBINATIONS (ground-truth richness)")
print("=" * 56)
print(f"  Both CVSS + CWE  : {pct(both_cvss_cwe)}  ← fully enriched")
print(f"  CVSS only        : {pct(cvss_only)}")
print(f"  CWE only         : {pct(cwe_only)}")
print(f"  Neither          : {pct(neither)}  ← description-only records")

print()
print("CVSS v3 SEVERITY DISTRIBUTION")
print("=" * 56)
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
    n = severity_counter.get(sev, 0)
    bar = "█" * int(30 * n / max(severity_counter.values(), default=1))
    print(f"  {sev:<10} {n:>7,}  {bar}")

print()
print("YEAR DISTRIBUTION (published_date, top 12)")
print("=" * 56)
for yr, n in sorted(year_counter.items(), reverse=True)[:12]:
    bar = "█" * int(30 * n / max(year_counter.values()))
    print(f"  {yr}  {n:>7,}  {bar}")

print()
print("TOP 20 CWEs")
print("=" * 56)
for cwe, n in cwe_counter.most_common(20):
    print(f"  {cwe:<12}  {n:>6,}")

print()
print("TOP 20 VENDORS (by CVE count)")
print("=" * 56)
for vendor, n in vendor_counter.most_common(20):
    print(f"  {n:>6,}  {vendor}")