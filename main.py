# main.py — analisi completa sempre
import json, argparse, pathlib
from rules import scan_text
from llm import call_llm

MAX_CHARS = 32000  # alza/abbassa in base al contesto del modello

TEMPLATE = """Sei un revisore privacy. Le HINTS sono indizi opzionali e possono essere rumorose.
Leggi la POLICY e valuta ogni item della checklist completa. Non copiare le hints: estrai evidenza dalla POLICY.

[POLICY]
{policy}

[HINTS_JSON]
{hints_json}

[CHECKLIST]
{checklist}

Output SOLO JSON: lista di oggetti con campi:
- id: string
- status: one of {present, ambiguous, missing}
- evidence_snippet: string (dal testo POLICY)
- reasoning: string
"""

def load_checklist(path="checklist.json"):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

def checklist_block(items):
    lines = []
    for it in items:
        lines.append(f"- {it['id']} :: {it['title']}")
        lines.append(f"  Q: {it['question']}")
        if it.get("accept"):
            lines.append("  Accept: " + "; ".join(it["accept"]))
        if it.get("reject"):
            lines.append("  Reject: " + "; ".join(it["reject"]))
        if it.get("evidence_requirements"):
            lines.append(f"  Evidence: {it['evidence_requirements']}")
    return "\n".join(lines)

def pack_hints_json(text, max_items=40):
    hits = scan_text(text)
    seen, packed = set(), []
    for h in hits:
        key = (h["category"], h["pattern"], h["start"], h["end"])
        if key in seen:
            continue
        seen.add(key)
        packed.append({
            "category": h["category"],
            "pattern": h["pattern"],
            "checklist_ids": h["checklist_ids"],
            "span": [h["start"], h["end"]],
            "snippet": h["snippet"][:240]
        })
        if len(packed) >= max_items:
            break
    return json.dumps(packed, ensure_ascii=False)

def analyze_one(policy_path: pathlib.Path, checklist_as_prompt: str):
    text = policy_path.read_text(encoding="utf-8")
    policy_excerpt = text[:MAX_CHARS]
    hints_json = pack_hints_json(policy_excerpt)  # sempre con hints
    prompt = TEMPLATE.format(
        policy=policy_excerpt,
        hints_json=hints_json,
        checklist=checklist_as_prompt,
    )
    try:
        return call_llm(prompt)  # deve restituire già JSON (dict/list)
    except Exception as e:
        # fallback utile per debug/log
        return {"error": str(e), "prompt_head": prompt[:800]}

def main():
    checklist_as_prompt = checklist_block(load_checklist())
    ap = argparse.ArgumentParser(description="Analisi completa privacy policy (sempre tutta la checklist).")
    ap.add_argument("policy", help="File di policy (.txt)")
    ap.add_argument("--outdir", default="outputs", help="Cartella output JSON")
    args = ap.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    pth = pathlib.Path(args.policy)
    result = analyze_one(pth, checklist_as_prompt)
    out_path = outdir / (pth.stem + ".json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[OK] {pth.name} → {out_path}")

if __name__ == "__main__":
    main()