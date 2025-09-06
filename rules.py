"""
rules.py — Pattern library & helpers for scanning Italian privacy notices (GDPR/CPI)
====================================================================================

Goal
----
Provide a **comprehensive, ready-to-use** set of regex patterns to detect common
phrases and signals in Italian privacy policies, mapped to your checklist IDs.
This module **does not decide** present/ambiguous/missing; it only **finds evidence**
snippets you can pass to an LLM or your aggregator.

Usage (quick):
--------------
from rules import scan_text, evidence_by_checklist, CHECKLIST_HINTS

hits = scan_text(doc_text)
for h in hits:
    print(h['category'], h['pattern'], h['snippet'], h['checklist_ids'])

Author: you
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Optional

# -----------------------------
# Core dataclass & containers
# -----------------------------

@dataclass
class PatternDef:
    name: str
    regex: str
    description: str
    checklist_ids: List[str]

@dataclass
class CompiledPattern:
    name: str
    compiled: Pattern
    description: str
    checklist_ids: List[str]


# -----------------------------
# Checklist IDs (as per your checklist.json)
# -----------------------------

CHECKLIST_HINTS = {
    "GDPR_13_1_a_titolare": "Titolare (identità/contatti)",
    "GDPR_13_1_a_rappresentanteUE": "Rappresentante UE (art. 27)",
    "GDPR_13_1_b_dpo": "DPO contatti",
    "GDPR_13_1_c_finalita": "Finalità del trattamento",
    "GDPR_6_1_base_giuridica": "Base giuridica (art. 6)",
    "GDPR_9_2_dati_particolari": "Dati particolari (art. 9(2))",
    "GDPR_13_1_d_interesse_legittimo": "Interesse legittimo specificato",
    "GDPR_14_1_d_categorie_dati": "Categorie di dati (art. 14(1)(d))",
    "GDPR_14_2_f_origine_dati": "Origine dei dati (art. 14(2)(f))",
    "GDPR_13_1_e_destinatari": "Destinatari",
    "GDPR_26_28_ruoli": "Ruoli privacy (26–28)",
    "GDPR_13_1_f_44_49_trasferimenti_extraUE": "Trasferimenti extra-UE",
    "GDPR_13_2_a_conservazione": "Periodo di conservazione",
    "GDPR_15_22_diritti": "Diritti interessato",
    "GDPR_12_1_modalita_esercizio": "Modalità di esercizio (art. 12)",
    "GDPR_13_2_d_reclamo_garante": "Reclamo al Garante",
    "CPI_2_quinquies_minori": "Consenso minori (14 anni)",
    "GARANTE_2021_cookie_informativa": "Cookie informativa",
    "GARANTE_2021_cookie_banner": "Cookie banner & preferenze",
    "GDPR_13_2_f_22_profilazione": "Profilazione/decisioni automatizzate",
    "GDPR_13_videosorveglianza": "Videosorveglianza",
    "GDPR_13_geolocalizzazione": "Geolocalizzazione",
    "STATUTO_4_CPI_114_lavoratori": "Lavoratori/controlli a distanza",
    "GDPR_12_1_linguaggio": "Linguaggio chiaro",
    "GARANTE_accessibilita_italiano": "Italiano/accessibilità",
    "GDPR_12_1_minori_linguaggio": "Linguaggio per minori",
}

# -----------------------------
# Regex building blocks
# -----------------------------

SP = r"[ \t\u00A0]+"                         # spaces incl. nbsp
NUM = r"(?:\d{1,3}(?:[.,]\d{3})*|\d+)"       # number
YEARS = r"(?:anni|anno|annuale|annuali)"
MONTHS = r"(?:mesi|mese|mensile|mensili)"
DAYS = r"(?:giorni|giorno)"
WEEKS = r"(?:settimane|settimana)"
DUR = rf"(?:{NUM}{SP}?(?:{YEARS}|{MONTHS}|{WEEKS}|{DAYS}))"
EMAIL = r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"
PHONE = r"(?:\+?\d{1,3}[ \-]?)?(?:\(?\d{2,4}\)?[ \-]?)?\d{5,8}"

# Some vague formulas for conservazione
VAGUE_CONSERVAZIONE = [
    r"per"+SP+r"il"+SP+r"tempo"+SP+r"(?:strettamente"+SP+r")?necessario",
    r"nei"+SP+r"limiti"+SP+r"(?:previsti|stabiliti)"+SP+r"dalla"+SP+r"legge",
    r"fino"+SP+r"a(?:l)?"+SP+r"raggiungimento"+SP+r"delle?"+SP+r"finalità",
]

# -----------------------------
# Category -> pattern definitions (shortened for space)
# -----------------------------

CATEGORIES: Dict[str, List[PatternDef]] = {
    # 1) IDENTITÀ & CONTATTI
    "identity_contacts": [
        # Identità/denominazione/sede
        PatternDef("titolare_block", r"titolare"+SP+r"del"+SP+r"trattamento", "Menzione del titolare", ["GDPR_13_1_a_titolare"]),
        PatternDef("denominazione_ragione_sociale", r"(denominazion[ea]|ragione"+SP+r"sociale|societ[aà]|S\.?p\.?A\.?|S\.?r\.?l\.?)", "Denominazione/ragione sociale", ["GDPR_13_1_a_titolare"]),
        PatternDef("sede_legale", r"sede"+SP+r"legal[ea]", "Sede legale indicata", ["GDPR_13_1_a_titolare"]),
        PatternDef("indirizzo_postale", r"(via|viale|corso|piazza|largo|strada)\s+[A-Za-zÀ-ÖØ-öø-ÿ0-9\.\- ]+,\s*\d{1,4}", "Indirizzo postale plausibile", ["GDPR_13_1_a_titolare"]),
        # Contatti
        PatternDef("email_any", EMAIL, "Email presente", ["GDPR_13_1_a_titolare","GDPR_12_1_modalita_esercizio"]),
        PatternDef("pec", r"\bPEC\b|posta"+SP+r"elettronic[ae]"+SP+r"certificat[ae]", "PEC presente", ["GDPR_12_1_modalita_esercizio"]),
        PatternDef("telefono", PHONE, "Numero di telefono plausibile", ["GDPR_13_1_a_titolare"]),
        # DPO
        PatternDef("dpo_kw", r"(responsabile"+SP+r"della"+SP+r"protezione"+SP+r"dei"+SP+r"dati|data"+SP+r"protection"+SP+r"officer|DPO)", "Menzione DPO", ["GDPR_13_1_b_dpo"]),
        PatternDef("dpo_contatto", r"(DPO|data"+SP+r"protection"+SP+r"officer).{0,40}"+EMAIL, "Contatto email DPO", ["GDPR_13_1_b_dpo"]),
        # Rappresentante UE (per titolari extra-UE)
        PatternDef("rappresentante_ue", r"rappresentante"+SP+r"nell(?:'|a)"+SP+r"unione"+SP+r"europea|art\.?"+SP+r"27", "Rappresentante UE (art. 27)", ["GDPR_13_1_a_rappresentanteUE"]),
    ],

    # 2) FINALITÀ & BASI GIURIDICHE
    "purposes_bases": [
        PatternDef("finalita_kw", r"\b(finalit[aà]|scopi|purpose)\b", "Parola chiave 'finalità/scopi'", ["GDPR_13_1_c_finalita"]),
        # Basi art. 6(1)
        PatternDef("base_giuridica_kw", r"base"+SP+r"giuridic[ae]|ai"+SP+r"sensi"+SP+r"dell'?art\.?"+SP+r"6", "Rinvio all’art. 6", ["GDPR_6_1_base_giuridica"]),
        PatternDef("consenso_kw", r"\bconsens[oi]\b|\bconsent\b", "Base: consenso", ["GDPR_6_1_base_giuridica"]),
        PatternDef("contratto_kw", r"\bcontratt\w+\b|\bnecessario"+SP+r"all'?esecuzione"+SP+r"del"+SP+r"contratto\b", "Base: contratto", ["GDPR_6_1_base_giuridica"]),
        PatternDef("obbligo_legale_kw", r"\bobblig[oi]"+SP+r"legal[ei]\b", "Base: obbligo legale", ["GDPR_6_1_base_giuridica"]),
        PatternDef("interesse_legittimo_kw", r"interesse"+SP+r"legittim[oa]|legitimate"+SP+r"interest", "Base: interesse legittimo", ["GDPR_13_1_d_interesse_legittimo","GDPR_6_1_base_giuridica"]),
        PatternDef("pubblico_vitale_kw", r"interess[oi]"+SP+r"vital[ei]|compit[oi]"+SP+r"di"+SP+r"interesse"+SP+r"pubblic[oi]|pubblic[oi]"+SP+r"poteri", "Basi: vitale/pubblico", ["GDPR_6_1_base_giuridica"]),
        # Dati particolari art. 9(2)
        PatternDef("dati_particolari_kw", r"categor\w+"+SP+r"particolar\w+|dati"+SP+r"(sensibil[ie]|sanitar[ie]|biometric[ie]|genetic[ie]|relativi"+SP+r"alla"+SP+r"salute|vita"+SP+r"sessuale|orientamento"+SP+r"sessuale)", "Dati particolari", ["GDPR_9_2_dati_particolari"]),
        PatternDef("consenso_esplicito_kw", r"consenso"+SP+r"esplicit[oa]", "Consenso esplicito (utile per 9(2))", ["GDPR_9_2_dati_particolari"]),
        PatternDef("LIA_bilanciamento_kw", r"\bbilanciam[eo]\w*|LIA\b|legitimate"+SP+r"interest"+SP+r"assessment", "Rinvio a bilanciamento (LIA)", ["GDPR_13_1_d_interesse_legittimo"]),
    ],

    # 3) CATEGORIE & ORIGINE (art. 14)
    "categories_origin": [
        PatternDef("categorie_dati_kw", r"categorie"+SP+r"di"+SP+r"dati", "Categorie di dati", ["GDPR_14_1_d_categorie_dati"]),
        PatternDef("origine_dati_kw", r"(origine|provenienza|fonte)"+SP+r"dei?"+SP+r"dati", "Origine/provenienza dei dati", ["GDPR_14_2_f_origine_dati"]),
        PatternDef("raccolta_da_terzi", r"raccolt[oi]"+SP+r"da"+SP+r"terz[ie]", "Raccolta da terzi", ["GDPR_14_1_d_categorie_dati","GDPR_14_2_f_origine_dati"]),
    ],

    # 4) DESTINATARI & RUOLI (26–28)
    "recipients_roles": [
        PatternDef("destinatari_kw", r"destinatari|categorie"+SP+r"di"+SP+r"destinatari|comunicati?"+SP+r"a", "Destinatari/categorie di destinatari", ["GDPR_13_1_e_destinatari"]),
        PatternDef("responsabile_28_kw", r"responsabile"+SP+r"del"+SP+r"trattamento|accordo"+SP+r"ex"+SP+r"art\.?"+SP+r"28", "Responsabile ex art. 28", ["GDPR_26_28_ruoli"]),
        PatternDef("contitolarita_26_kw", r"contitolari?(?:t[aà])?"+SP+r"del"+SP+r"trattamento|accordo"+SP+r"di"+SP+r"contitolarit[aà]|art\.?"+SP+r"26", "Contitolarità art. 26", ["GDPR_26_28_ruoli"]),
        PatternDef("fornitori_cloud_kw", r"(fornitor[ei]|provider)"+SP+r"(cloud|serviz[io] digital[ie])", "Fornitori/Cloud (spesso responsabili)", ["GDPR_13_1_e_destinatari","GDPR_26_28_ruoli"]),
    ],

    # 5) TRASFERIMENTI EXTRA-UE (44–49)
    "transfers": [
        PatternDef("trasferimenti_kw", r"trasferiment[io]|paes[ei]"+SP+r"terz[io]|extra[- ]?UE|al"+SP+r"di"+SP+r"fuori"+SP+r"dell(?:'|a)"+SP+r"UE|SEE", "Trasferimenti verso paesi terzi/extra-UE/SEE", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
        PatternDef("SCC_kw", r"clausole"+SP+r"contrattuali"+SP+r"standard|standard"+SP+r"contractual"+SP+r"clauses|SCC", "Clausole contrattuali standard", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
        PatternDef("adeguatezza_kw", r"decisione"+SP+r"di"+SP+r"adeguatezza|adequacy"+SP+r"decision", "Decisione di adeguatezza", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
        PatternDef("BCR_kw", r"binding"+SP+r"corporate"+SP+r"rules|BCR", "Binding Corporate Rules", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
        PatternDef("DPF_kw", r"(EU[- ]?US|UE[- ]?USA).{0,20}(data"+SP+r"privacy"+SP+r"framework|DPF)", "EU-US Data Privacy Framework", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
        PatternDef("USA_kw", r"\bUSA\b|\bStati"+SP+r"Unit[ie]\b|United"+SP+r"States", "Riferimenti a USA", ["GDPR_13_1_f_44_49_trasferimenti_extraUE"]),
    ],

    # 6) CONSERVAZIONE (art. 13(2)(a))
    "retention": [
        PatternDef("durata_esplicita", DUR, "Durata esplicita (anni/mesi/settimane/giorni)", ["GDPR_13_2_a_conservazione"]),
        PatternDef("durata_massima", r"(non"+SP+r"oltre|comunque"+SP+r"non"+SP+r"oltre|per"+SP+r"un"+SP+r"massimo"+SP+r"di)\s+"+DUR, "Durata massima dichiarata", ["GDPR_13_2_a_conservazione"]),
        PatternDef("kw_conservazione", r"(conservazion[ea]|durat[ae]|periodo|termine)", "Parole chiave conservazione", ["GDPR_13_2_a_conservazione"]),
        # Formule vaghe comuni
        PatternDef("vaghezza_tempo_necessario", r"per"+SP+r"il"+SP+r"tempo"+SP+r"(?:strettamente"+SP+r")?necessario", "Formula vaga: tempo necessario", ["GDPR_13_2_a_conservazione"]),
        PatternDef("vaghezza_limiti_legge", r"nei"+SP+r"limiti"+SP+r"(?:previsti|stabiliti)"+SP+r"dalla"+SP+r"legge", "Formula vaga: limiti di legge", ["GDPR_13_2_a_conservazione"]),
        PatternDef("vaghezza_finalita", r"fino"+SP+r"a(?:l)?"+SP+r"raggiungimento"+SP+r"delle?"+SP+r"finalit[aà]", "Formula vaga: fino a finalità", ["GDPR_13_2_a_conservazione"]),
        PatternDef("vaghezza_periodo_necessario", r"per"+SP+r"il"+SP+r"periodo"+SP+r"necessario", "Formula vaga: periodo necessario", ["GDPR_13_2_a_conservazione"]),
        PatternDef("vaghezza_tempo_previsto_norma", r"per"+SP+r"il"+SP+r"tempo"+SP+r"previsto"+SP+r"dalla"+SP+r"(?:normativa|legge)", "Formula vaga: tempo previsto da norma", ["GDPR_13_2_a_conservazione"]),
        PatternDef("vaghezza_ragionevole", r"per"+SP+r"un"+SP+r"periodo"+SP+r"di"+SP+r"tempo"+SP+r"ragionevole", "Formula vaga: periodo ragionevole", ["GDPR_13_2_a_conservazione"]),
        # Azioni fine conservazione
        PatternDef("fine_conservazione_azioni", r"(cancellazion[ea]|eliminazion[ea]|rimozion[ea]|distruzion[ea]|anonimizzazion[ea]|pseudonimizzazion[ea])", "Azioni di fine conservazione", ["GDPR_13_2_a_conservazione"]),
    ],

    # 7) DIRITTI DELL’INTERESSATO (15–22, 12)
    "rights": [
        PatternDef("diritti_kw", r"\bdiritt[oi]\b", "Sezione diritti", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_accesso", r"\baccesso\b", "Diritto di accesso", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_rettifica", r"\brettifica\b", "Diritto di rettifica", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_cancellazione_oblio", r"\b(cancellazione|oblio)\b", "Diritto cancellazione/oblio", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_limitazione", r"\blimitazion[ea]\b", "Diritto di limitazione", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_portabilita", r"\bportabilit[aà]\b", "Diritto alla portabilità", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_opposizione", r"\bopposizion[ea]\b", "Diritto di opposizione", ["GDPR_15_22_diritti"]),
        PatternDef("diritto_revoca_consenso", r"\brevoc(a|are|abile)\b.*\bconsens[oi]\b", "Revoca del consenso", ["GDPR_15_22_diritti"]),
        # Modalità di esercizio & canali
        PatternDef("modalita_esercizio_frase", r"(come|modalit[aà]|modo)"+SP+r"(?:di|per)"+SP+r"esercit\w+"+SP+r"i"+SP+r"diritt[oi]", "Frase modalità di esercizio", ["GDPR_12_1_modalita_esercizio"]),
        PatternDef("canale_email", EMAIL, "Email contatti/diritti", ["GDPR_12_1_modalita_esercizio","GDPR_13_1_a_titolare"]),
        PatternDef("canale_pec", r"\bPEC\b|posta"+SP+r"elettronic[ae]"+SP+r"certificat[ae]", "PEC", ["GDPR_12_1_modalita_esercizio"]),
        PatternDef("canale_modulo_form", r"\b(modul[oi]|form|modulo"+SP+r"online)\b", "Modulo/form", ["GDPR_12_1_modalita_esercizio"]),
        PatternDef("canale_postale", r"(indirizzo"+SP+r"postale|raccomandata|lettera)", "Indirizzo postale", ["GDPR_12_1_modalita_esercizio"]),
        PatternDef("tempo_riscontro", r"(30|trenta)"+SP+r"giorni|\bun"+SP+r"mese\b", "Tempi di riscontro", ["GDPR_12_1_modalita_esercizio"]),
        # Reclamo al Garante
        PatternDef("reclamo_garante_kw", r"garante"+SP+r"per"+SP+r"la"+SP+r"protezione"+SP+r"dei"+SP+r"dati(?:\s+personali)?", "Reclamo al Garante", ["GDPR_13_2_d_reclamo_garante"]),
        # Automatizzate/profilazione (spesso citate tra i diritti)
        PatternDef("no_decisioni_automatizzate", r"no"+SP+r"decisioni"+SP+r"automatizzat[ae]|assenza"+SP+r"di"+SP+r"processi"+SP+r"automatizzati", "Assenza decisioni automatizzate", ["GDPR_13_2_f_22_profilazione"]),
        PatternDef("profilazione_kw", r"(decisioni?"+SP+r"(?:unicamente"+SP+r")?automatizzat[ae]|profilazion[ea]|scoring)", "Profilazione/decisioni automatizzate", ["GDPR_13_2_f_22_profilazione"]),
    ],

    # 8) COOKIE & TRACCIAMENTO (Provv. Garante 10/06/2021)
    "cookies": [
        PatternDef("cookie_kw", r"\bcookie\b|pixel|tracker|SDK|tag(?:\smanager)?", "Cookie/pixel/tracker", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("cookie_policy_kw", r"(cookie"+SP+r"policy|informativa"+SP+r"cookie)", "Pagina/Informativa cookie", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("terze_parti_kw", r"\bterze?"+SP+r"parti\b", "Riferimento a terze parti", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("durate_cookie", DUR, "Durate cookie (generico)", ["GARANTE_2021_cookie_informativa"]),
        # Strumenti/terze parti comuni
        PatternDef("tools_google_analytics", r"google"+SP+r"analytics|GA4", "Google Analytics/GA4", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("tools_meta_pixel", r"(meta|facebook)"+SP+r"pixel", "Meta/Facebook Pixel", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("tools_hotjar", r"\bhotjar\b", "Hotjar", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("tools_matomo", r"\bmatomo\b", "Matomo", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("tools_tag_manager", r"tag"+SP+r"manager", "Tag Manager", ["GARANTE_2021_cookie_informativa"]),
        PatternDef("tools_consent_mgr", r"(cookiebot|iubenda|onetrust)", "Consent manager", ["GARANTE_2021_cookie_informativa","GARANTE_2021_cookie_banner"]),
        # Banner & preferenze
        PatternDef("banner_kw", r"\bbanner\b|\bpop[- ]?up\b", "Banner cookie", ["GARANTE_2021_cookie_banner"]),
        PatternDef("pulsante_accetta", r"\baccetta(re)?\b|\bconsenti\b", "Pulsante 'Accetta/Consenti'", ["GARANTE_2021_cookie_banner"]),
        PatternDef("pulsante_rifiuta", r"\brifiuta(re)?\b|\bnega\b|\brifiuta"+SP+r"tutto\b", "Pulsante 'Rifiuta/Nega'", ["GARANTE_2021_cookie_banner"]),
        PatternDef("gestisci_preferenze", r"(gestisc[ie]|impostazion[ei]|preferenz[ei])"+SP+r"(?:dei|sui)?"+SP+r"cookie", "Gestione preferenze", ["GARANTE_2021_cookie_banner"]),
        PatternDef("solo_necessari", r"(solo|accetta)"+SP+r"(i)?"+SP+r"necessar[ie]?", "Opzione 'solo necessari'", ["GARANTE_2021_cookie_banner"]),
        PatternDef("categorie_cookie", r"(tecnic[ie]|statistic[he]|marketing|profilazione|preferenze)", "Categorie cookie", ["GARANTE_2021_cookie_informativa"]),
    ],

    # 9) MINORI (CPI 2-quinquies)
    "minors": [
        PatternDef("minori_kw", r"\bminor[ei]\b|\bet[aà]\b|under\s?\d{1,2}", "Menzione minori/età", ["CPI_2_quinquies_minori","GDPR_12_1_minori_linguaggio"]),
        PatternDef("eta_anni", r"\b\d{1,2}"+SP+r"anni\b", "Età indicata (anni)", ["CPI_2_quinquies_minori"]),
        PatternDef("consenso_genitori", r"(genitor[ie]|tutor[ei]|responsabilit[aà]"+SP+r"genitorial[ea])", "Consenso genitori/tutori", ["CPI_2_quinquies_minori"]),
    ],

    # 10) TRATTAMENTI PARTICOLARI
    "special_processing": [
        # Profilazione/decisioni automatizzate (art. 22 + 13(2)(f))
        PatternDef("profilazione_kw", r"(profilazion[ea]|decisioni?"+SP+r"(?:unicamente"+SP+r")?automatizzat[ae]|scoring)", "Profilazione/automatizzate", ["GDPR_13_2_f_22_profilazione"]),
        PatternDef("intervento_umano_kw", r"intervento"+SP+r"umano|diritto"+SP+r"di"+SP+r"contestazione|spiegazion[ei]", "Diritti contro decisioni automatizzate", ["GDPR_13_2_f_22_profilazione"]),
        # Videosorveglianza
        PatternDef("videosorveglianza_kw", r"videosorveglianz[ae]|CCTV|telecamer[ae]", "Videosorveglianza", ["GDPR_13_videosorveglianza"]),
        PatternDef("cartelli_kw", r"\bcartell[oi]\b|informazion[ei]"+SP+r"sintetic[he]", "Cartelli informativi", ["GDPR_13_videosorveglianza"]),
        # Geolocalizzazione
        PatternDef("geolocalizzazione_kw", r"geolocalizzazion[ea]|posizion[ea]|GPS|geofencing|tracking", "Geolocalizzazione/posizione", ["GDPR_13_geolocalizzazione"]),
        PatternDef("parametri_geo_kw", r"(frequenza|accuratezza|precisione|intervalli|sampling)", "Parametri tecnici geoloc.", ["GDPR_13_geolocalizzazione"]),
    ],

    # 11) LAVORATORI / CONTROLLI A DISTANZA
    "workers_controls": [
        PatternDef("statuto_kw", r"controlli"+SP+r"a"+SP+r"distanza|statuto"+SP+r"dei"+SP+r"lavoratori|art\.?"+SP+r"4"+SP+r"L\.?"+SP+r"300/1970", "Controlli a distanza/statuto", ["STATUTO_4_CPI_114_lavoratori"]),
        PatternDef("accordo_autorizzazione_kw", r"(accordo"+SP+r"sindacal[ea]|autorizzazione"+SP+r"ispettorato)", "Accordo sindacale/autorizzazione", ["STATUTO_4_CPI_114_lavoratori"]),
        PatternDef("strumenti_lavoro_kw", r"(strument[io]"+SP+r"di"+SP+r"lavoro|badge|dispositiv[io]|software"+SP+r"di"+SP+r"monitoraggio)", "Strumenti di controllo", ["STATUTO_4_CPI_114_lavoratori"]),
    ],

    # 12) LINGUAGGIO & ACCESSIBILITÀ
    "language_accessibility": [
        PatternDef("linguaggio_chiaro_kw", r"(in"+SP+r"modo"+SP+r"chiaro|trasparente|intelligibile|semplice)", "Linguaggio chiaro", ["GDPR_12_1_linguaggio","GARANTE_accessibilita_italiano"]),
        PatternDef("accessibilita_kw", r"accessibilit[aà]|leggibilit[aà]|usabilit[aà]|WCAG|accessibile", "Accessibilità/usabilità", ["GARANTE_accessibilita_italiano"]),
        PatternDef("struttura_aiuto_kw", r"(indice|sommario|titoli|faq|glossario)", "Strutture di aiuto alla lettura", ["GARANTE_accessibilita_italiano"]),
        PatternDef("linguaggio_minori_kw", r"(versione|sezione)"+SP+r"per"+SP+r"minori|icone|esempi"+SP+r"semplici", "Adattamento per minori", ["GDPR_12_1_minori_linguaggio"]),
    ],
}



# -----------------------------
# Compile & scanner
# -----------------------------

def _compile_categories(categories: Dict[str, List[PatternDef]]) -> Dict[str, List[CompiledPattern]]:
    compiled: Dict[str, List[CompiledPattern]] = {}
    for cat, defs in categories.items():
        compiled[cat] = []
        for d in defs:
            c = re.compile(d.regex, flags=re.IGNORECASE | re.MULTILINE)
            compiled[cat].append(CompiledPattern(d.name, c, d.description, d.checklist_ids))
    return compiled

COMPILED = _compile_categories(CATEGORIES)

def _safe_snippet(text: str, start: int, end: int, ctx: int = 80) -> str:
    s = max(0, start - ctx)
    e = min(len(text), end + ctx)
    snippet = text[s:e].strip()
    return re.sub(r"\s+", " ", snippet)

def scan_text(text: str, categories: Optional[List[str]] = None) -> List[Dict]:
    results: List[Dict] = []
    selected = COMPILED if not categories else {k:v for k,v in COMPILED.items() if k in categories}
    for cat, patterns in selected.items():
        for p in patterns:
            for m in p.compiled.finditer(text):
                results.append({
                    "category": cat,
                    "pattern": p.name,
                    "start": m.start(),
                    "end": m.end(),
                    "snippet": _safe_snippet(text, m.start(), m.end()),
                    "checklist_ids": p.checklist_ids,
                    "description": p.description
                })
    return results

def evidence_by_checklist(text: str) -> Dict[str, List[str]]:
    hits = scan_text(text)
    buckets: Dict[str, List[str]] = {}
    for h in hits:
        for cid in h["checklist_ids"]:
            buckets.setdefault(cid, [])
            if h["snippet"] not in buckets[cid]:
                buckets[cid].append(h["snippet"])
    return buckets

