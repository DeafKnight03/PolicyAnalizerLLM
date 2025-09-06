import os, json
from typing import Dict, Any, List

PROVIDER = os.getenv("LLM_PROVIDER", "MOCK").upper()
MODEL    = os.getenv("LLM_MODEL", "gpt-4o-mini")

SYSTEM_INSTR = (
    "Sei un revisore privacy. Rispondi SOLO in JSON. "
    "Per ogni item: status in {present, ambiguous, missing}; "
    "evidence_snippet deve provenire dal testo policy."
)

def _build_messages(prompt: str) -> List[Dict[str, str]]:
    return [{"role":"system","content":SYSTEM_INSTR},{"role":"user","content": prompt}]

def call_llm(prompt: str) -> Dict[str, Any]:
    if PROVIDER == "OPENAI":
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        resp = client.chat.completions.create(model=MODEL, messages=_build_messages(prompt), temperature=0)
        return json.loads(resp.choices[0].message.content.strip())

    if PROVIDER == "HF":
        from huggingface_hub import InferenceClient
        client = InferenceClient(token=os.getenv("HF_API_TOKEN"))
        full = SYSTEM_INSTR + "\n\n" + prompt + "\n\nRispondi in JSON puro."
        text = client.text_generation(model=MODEL, prompt=full, max_new_tokens=800)
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end+1])

    if PROVIDER == "OLLAMA":
        import requests
        url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
        payload = {"model": MODEL, "messages": _build_messages(prompt), "options": {"temperature": 0}}
        r = requests.post(url, json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        text = data["message"]["content"]
        return json.loads(text.strip())

    if PROVIDER == "MOCK":
        items = []
        for line in prompt.splitlines():
            if line.startswith("- ") and ":" in line:
                cid = line[2:].split(":")[0].strip()
                if cid.startswith(("GDPR_","GARANTE_","CPI_","STATUTO_")):
                    items.append(cid)
        return [{"id": cid, "status": "ambiguous", "evidence_snippet": "", "reasoning": "Mock mode."} for cid in items]

    raise RuntimeError("Unknown LLM_PROVIDER")
