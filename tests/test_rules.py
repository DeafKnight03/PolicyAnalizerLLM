from rules import scan_text

def test_retention_signals():
    txt = "I dati saranno conservati per un massimo di 10 anni e poi cancellazione."
    hits = scan_text(txt, categories=["retention"])
    names = {(h["category"], h["pattern"]) for h in hits}
    assert ("retention", "durata_massima") in names
    assert ("retention", "fine_conservazione_azioni") in names
