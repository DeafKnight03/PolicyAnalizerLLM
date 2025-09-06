import argparse, json, pathlib
from rules import scan_text, CHECKLIST_HINTS
from llm import call_llm

TEMPLATE = """Sei un revisore privacy. Leggi l’estratto della policy e rispondi alla checklist.
Le *regex hints* sono facoltative e possono essere rumorose: fai tu la valutazione finale.

[POLICY]
{policy}

[HINTS – opzionali]
{hints}

[CHECKLIST]
{checklist}

Rispondi SOLO in JSON: 
[{"id": "...", "status": "present|ambiguous|missing", "evidence_snippet": "...", "reasoning": "..."}]
"""

def compact_hints(text: str, max_hints: int = 12) -> str:
    hits = scan_text(text)
    seen, rows = set(), []
    for h in hits:
        key = (h["category"], h["pattern"], h["snippet"])
        if key in seen: 
            continue
        seen.add(key)
        label = "/".join(h["checklist_ids"])
        rows.append(f"- [{h['category']}::{h['pattern']} -> {label}] …{h['snippet'][:180]}…")
        if len(rows) >= max_hints:
            break
    return "\n".join(rows) if rows else "(none)"

def checklist_to_text(ids):
    return "\n".join(f"- {cid}: {CHECKLIST_HINTS.get(cid, '')}" for cid in ids)

def run(policy_path: str, checklist_ids, with_hints: bool, max_chars: int = 6000):
    policy = pathlib.Path(policy_path).read_text(encoding="utf-8")
    policy_excerpt = policy[:max_chars]
    hints = compact_hints(policy_excerpt) if with_hints else "(none)"
    prompt = TEMPLATE.format(policy=policy_excerpt, hints=hints, checklist=checklist_to_text(checklist_ids))
    return call_llm(prompt)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("policy")
    ap.add_argument("--checklist", nargs="+", default=[
        "GDPR_13_1_a_titolare",
        "GDPR_13_2_a_conservazione",
        "GDPR_15_22_diritti",
        "GARANTE_2021_cookie_banner",
        "CPI_2_quinquies_minori",
    ])
    ap.add_argument("--with-hints", action="store_true")
    args = ap.parse_args()
    result = run(args.policy, args.checklist, args.with_hints)
    print(json.dumps(result, ensure_ascii=False, indent=2))
