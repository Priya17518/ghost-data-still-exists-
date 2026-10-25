import csv
import json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUTPUT_FILE = ROOT / "output.csv"
DASHBOARD_DIR = ROOT / "dashboard"
DASHBOARD_DIR.mkdir(exist_ok=True)

with open(DATASET / "deletion_requests.csv", encoding="utf-8-sig") as f:
    requests = {r["case_id"]: r for r in csv.DictReader(f)}

with open(OUTPUT_FILE, encoding="utf-8-sig") as f:
    outputs = {r["case_id"]: r for r in csv.DictReader(f)}

with open(DATASET / "deletion_rules.csv", encoding="utf-8-sig") as f:
    rules = list(csv.DictReader(f))

# Gather system stats and operations
system_counter = Counter()
operation_counter = Counter()
cases = []
ghost_count = 0
status_counts = Counter()

for cid in sorted(requests.keys(), key=lambda x: int(x.split("_")[1]) if "_" in x and x.split("_")[1].isdigit() else 0):
    req = requests[cid]
    out = outputs.get(cid, {})
    del_status = out.get("deletion_status", "UNKNOWN")
    status_counts[del_status] += 1
    
    steps_raw = out.get("steps_json", "[]")
    try:
        steps = json.loads(steps_raw)
    except Exception:
        steps = []
    
    is_ghost = (req.get("reported_status") == "COMPLETE" and del_status == "INCOMPLETE")
    if is_ghost:
        ghost_count += 1
        
    findings = []
    remediations = []
    verifications = []
    
    for s in steps:
        p = s.get("phase")
        op = s.get("operation")
        sys_id = s.get("system_id")
        if sys_id:
            system_counter[sys_id] += 1
        if op:
            operation_counter[op] += 1
            
        if p == "FINDING":
            findings.append(s)
        elif p == "REMEDIATION":
            remediations.append(s)
        elif p == "VERIFICATION":
            verifications.append(s)

    cases.append({
        "case_id": cid,
        "email": req.get("email", ""),
        "requested_at": req.get("requested_at", ""),
        "reported_status": req.get("reported_status", ""),
        "reported_at": req.get("reported_at", ""),
        "audit_at": req.get("audit_at", ""),
        "request_text": req.get("request_text", ""),
        "deletion_status": del_status,
        "is_ghost": is_ghost,
        "steps": steps,
        "finding_count": len(findings),
        "remediation_count": len(remediations),
        "verification_count": len(verifications),
    })

data = {
    "meta": {
        "title": "HackerRank Orchestrate: Ghost Data Still Exists",
        "subtitle": "AI-Powered Deletion Audit System & Investigation Dashboard",
        "generated_at": "2026-10-25T03:35:00Z",
        "total_cases": len(cases),
        "ghost_cases": ghost_count,
        "status_distribution": dict(status_counts),
        "top_systems": system_counter.most_common(10),
        "top_operations": operation_counter.most_common(10),
        "rules_count": len(rules),
    },
    "rules": rules,
    "cases": cases,
}

out_path = DASHBOARD_DIR / "data.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Generated {out_path} with {len(cases)} cases, {ghost_count} ghost cases.")
