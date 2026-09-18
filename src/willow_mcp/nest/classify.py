"""
nest-seed/classify.py — tiered hybrid classifier.

A document flows through up to three tiers, cheapest first:

  1. regex      — deterministic facts (dates, titled names). Always runs as
                  enrichment; also the final fallback when nothing else is
                  available. Free, offline.
  2. embeddings — semantic classification. The document is embedded
                  (nomic-embed-text) and matched to the nearest category
                  centroid by cosine similarity. The score *is* the confidence.
                  Fast, local, deterministic. Handles the confident majority.
  3. generative — a local LLM (llm.py) reads the text. Fires ONLY when the
                  embedding tier is uncertain (low score, or top-2 too close),
                  and is handed the embedding's top candidates as a constrained
                  choice. Expensive, so used sparingly. Also classifies images
                  via a vision model.

Every tier degrades gracefully: if embeddings are unavailable the doc goes
straight to the LLM (or regex); if the LLM is unavailable the embedding verdict
(or regex) stands. Nothing ever hard-fails on a missing model.

Fragment types: person, date, location, event, document, photo, note,
receipt, unknown. The topical category (legal, journal, code, financial, …)
is stored in the fragment `label`.
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

try:  # works both as a package (apps.nest_seed) and as a plain script dir
    from . import llm as _llm
    from . import embed as _embed
    from . import taxonomy as _tax
    from . import secrets as _secrets
except ImportError:
    import llm as _llm
    import embed as _embed
    import taxonomy as _tax
    import secrets as _secrets

# --- embedding-tier thresholds (env-overridable; calibrated on real dump) ----
# Absolute cosine is NOT discriminative (nomic rates everything ~0.55-0.74), so
# confidence is judged by the MARGIN over the mean category similarity — how far
# the winner stands out from the field.
# Calibrated on the full 186-file dump with exemplar centroids: margin spans
# 0.042–0.140 (mean 0.087). At 0.07, ~69% of files resolve on this cheap tier
# and the least-distinctive ~31% escalate to the LLM — the right safety balance.
# Lower NEST_EMBED_MARGIN for more speed (fewer escalations), raise for more
# LLM verification.
MARGIN_CONFIDENT = float(os.environ.get("NEST_EMBED_MARGIN", "0.07"))
MARGIN_FLOOR = float(os.environ.get("NEST_EMBED_MARGIN_FLOOR", "0.03"))

# Loose candidate finder; _plausible_date() does the real validation so we reject
# version strings ("0.4.27"), out-of-range numbers, and epoch-sentinel artifacts.
_DATE_RE = re.compile(
    r"\b(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{1,4}"
    r"|\w+ \d{1,2},? \d{4}"
    r"|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})\b"
)

_MONTH_ABBR = {"jan", "feb", "mar", "apr", "may", "jun",
               "jul", "aug", "sep", "oct", "nov", "dec"}

# Personal dumps don't contain real pre-1990 events; what looks like one is an
# epoch-zero timestamp (1970-01-xx from a 0-ms export) or a null/default date.
MIN_PLAUSIBLE_YEAR = int(os.environ.get("NEST_MIN_DATE_YEAR", "1990"))


def _plausible_date(s: str) -> bool:
    """True only for a real calendar date — not a semver/version string."""
    s = s.strip()
    m = re.fullmatch(r"(\d{1,4})([/\-.])(\d{1,2})\2(\d{1,4})", s)
    if m:
        a, sep, c = m.group(1), m.group(2), m.group(4)
        ai, bi, ci = int(a), int(m.group(3)), int(c)
        if len(a) == 4:                       # ISO yyyy-mm-dd
            return 1 <= bi <= 12 and 1 <= ci <= 31 and ai >= MIN_PLAUSIBLE_YEAR
        if sep == ".":                        # dotted → need 4-digit year (else semver)
            return len(c) == 4 and 1 <= ai <= 31 and 1 <= bi <= 12 and ci >= MIN_PLAUSIBLE_YEAR
        if len(c) in (2, 4):                  # slash/dash dd-mm-yy(yy)
            yr = ci if len(c) == 4 else (2000 + ci if ci < 70 else 1900 + ci)
            return 1 <= ai <= 31 and 1 <= bi <= 31 and (ai <= 12 or bi <= 12) and yr >= MIN_PLAUSIBLE_YEAR
        return False
    mm = re.fullmatch(r"([A-Za-z]+) \d{1,2},? (\d{4})", s)
    if mm:
        return mm.group(1).lower()[:3] in _MONTH_ABBR and int(mm.group(2)) >= MIN_PLAUSIBLE_YEAR
    return False


# Case-insensitivity is scoped to the TITLE only — a global re.IGNORECASE makes
# the name group's [A-Z][a-z]+ match any case, so "Mr. Martinez gave" yields the
# junk name "Martinez gave". The name must stay genuinely Capitalized.
_PERSON_PREFIXES = re.compile(
    r"\b(?i:(mr|mrs|ms|dr|prof|rev)\.?)\s+([A-Z][a-z]+ [A-Z][a-z]+)\b"
)
_CAPITALIZED_NAME = re.compile(r"\b([A-Z][a-z]{2,} [A-Z][a-z]{2,})\b")
_LOCATION_WORDS = re.compile(
    r"\b(street|st\.|avenue|ave\.|blvd|road|rd\.|city|town|county|state|"
    r"country|province|district|zip|postal)\b",
    re.IGNORECASE,
)
_RECEIPT_WORDS = re.compile(
    r"\b(total|subtotal|receipt|invoice|tax|paid|amount due|"
    r"credit card|cash|change|qty|quantity)\b",
    re.IGNORECASE,
)
_EVENT_WORDS = re.compile(
    r"\b(birthday|anniversary|wedding|graduation|funeral|ceremony|"
    r"appointment|meeting|event|conference|born|died|married)\b",
    re.IGNORECASE,
)

# Two Capitalized words ("General Insurance", "State Farm", "United States") sail
# through _CAPITALIZED_NAME and become bogus `person` fragments. Reject a candidate
# when EITHER token is an organisation/place/role marker — these never name a person.
_ORG_TOKENS = frozenset((
    # corporate / legal forms
    "insurance", "llc", "inc", "incorporated", "corp", "corporation", "company",
    "co", "ltd", "limited", "gmbh", "plc", "group", "holdings", "partners",
    "associates", "enterprises", "industries", "ventures", "capital",
    # financial / institutional
    "bank", "trust", "fund", "foundation", "financial", "mutual", "savings",
    "credit", "union", "insurer", "underwriters", "brokerage",
    # public bodies / civic
    "department", "dept", "agency", "bureau", "office", "court", "county",
    "state", "federal", "national", "commission", "authority", "administration",
    "council", "committee", "board", "division", "district", "municipal",
    "ministry", "embassy", "consulate", "tribunal",
    # institutions / services
    "university", "college", "school", "academy", "institute", "hospital",
    "clinic", "center", "centre", "services", "service", "systems", "solutions",
    "technologies", "tech", "media", "press", "network", "society", "association",
    "organization", "organisation", "corp",
    # generic descriptors that pair with the above to form org names
    "general", "united", "international", "global", "american", "northern",
    "southern", "eastern", "western", "central", "first", "premier", "allied",
    "standard", "republic", "states", "kingdom", "province",
))


def _looks_like_org(name: str) -> bool:
    """True when a capitalized two-word phrase reads as an org/place, not a person."""
    return any(w in _ORG_TOKENS for w in name.lower().split())


_IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp")


@dataclass
class Fragment:
    fragment_type: str
    content: str
    label: str = ""
    confidence: str = "uncertain"
    date_ref: str = ""


# --- cheap deterministic extractors (shared by all tiers) -------------------

def _date_fragments(text: str) -> list[Fragment]:
    return [
        Fragment(fragment_type="date", content=m.group(),
                 confidence="likely", date_ref=m.group())
        for m in _DATE_RE.finditer(text)
        if _plausible_date(m.group())
    ]


def _titled_person_fragments(text: str, seen: set[str]) -> list[Fragment]:
    frags: list[Fragment] = []
    for m in _PERSON_PREFIXES.finditer(text):
        name = m.group(2)
        if name not in seen and not _looks_like_org(name):
            seen.add(name)
            frags.append(Fragment(fragment_type="person", content=name,
                                  label=m.group(1).rstrip(".").lower(), confidence="likely"))
    return frags


def _enrich(text: str) -> list[Fragment]:
    """Cheap, high-precision deterministic fragments to attach to any primary."""
    return _titled_person_fragments(text, set()) + _date_fragments(text)


def _confidence_from_margin(margin: float) -> str:
    if margin >= 0.10:
        return "confirmed"
    if margin >= MARGIN_CONFIDENT:
        return "likely"
    if margin >= MARGIN_FLOOR:
        return "uncertain"
    return "speculative"


def _frag_from_category(cat: str, confidence: str, content: str) -> Fragment:
    ftype = _tax.CATEGORY_FRAGMENT_TYPE.get(cat, "document")
    return Fragment(fragment_type=ftype, content=content, label=cat, confidence=confidence)


def _frag_from_verdict(verdict: dict, text: str, is_image: bool) -> Fragment:
    return Fragment(
        fragment_type="photo" if is_image else verdict["fragment_type"],
        content=verdict["summary"] or text[:300],
        label=verdict["category"],
        confidence=verdict["confidence"],
    )


# --- main entry -------------------------------------------------------------

def classify(text: str, filename: str = "", path: "Path | None" = None,
             use_llm: bool = False, use_embed: bool = True,
             centroids: "dict[str, list[float]] | None" = None,
             text_model: str | None = None, vision_model: str | None = None,
             embed_model: str | None = None,
             learn_sink: "Callable[[str, list, float, str], None] | None" = None,
             escalation_sink: "Callable[[dict], None] | None" = None) -> list[Fragment]:
    """Public entry. Scrubs credentials FIRST: any secret becomes a flagged,
    redacted `secret` fragment and is removed from the text before any other tier
    embeds or stores it — the Nest never persists a raw credential.

    `escalation_sink`, when given, is called once per tier-3 LLM escalation with
    the (excerpt, margin, candidates, verdict, teacher_model) row — the redacted
    text only, since it runs after the scrub above."""
    secret_frags: list[Fragment] = []
    found = _secrets.find_secrets(text)
    if found:
        text = _secrets.redact_text(text)
        secret_frags = [
            Fragment(fragment_type="secret",
                     content=f"{kind}: {_secrets.redact_value(val)}",
                     label=kind, confidence="confirmed")
            for kind, val in found
        ]
    core = _classify_core(text, filename, path, use_llm, use_embed, centroids,
                          text_model, vision_model, embed_model, learn_sink,
                          escalation_sink)
    return secret_frags + core


def _classify_core(text: str, filename: str = "", path: "Path | None" = None,
                   use_llm: bool = False, use_embed: bool = True,
                   centroids: "dict[str, list[float]] | None" = None,
                   text_model: str | None = None, vision_model: str | None = None,
                   embed_model: str | None = None,
                   learn_sink: "Callable[[str, list, float, str], None] | None" = None,
                   escalation_sink: "Callable[[dict], None] | None" = None) -> list[Fragment]:
    name_lower = filename.lower()
    is_image = any(name_lower.endswith(x) for x in _IMAGE_EXTS)

    if not text.strip() and not (is_image and use_llm):
        return _classify_regex(text, filename, name_lower, is_image)

    # --- images: vision tier (embeddings don't apply to raw pixels) ---------
    if is_image and use_llm and path is not None:
        verdict = _llm.describe_image(path, model=vision_model or _llm.DEFAULT_VISION_MODEL)
        if verdict is not None:
            return [_frag_from_verdict(verdict, text, True)] + _date_fragments(text)
        if not text.strip():
            return _classify_regex(text, filename, name_lower, is_image)
        # had OCR text, vision failed → classify that text below.

    primary = _classify_text_tiers(
        text, filename, is_image, use_llm, use_embed, centroids,
        text_model=text_model, embed_model=embed_model, learn_sink=learn_sink,
        escalation_sink=escalation_sink,
    )
    if primary is None:
        # No tier produced a verdict (all models down) → pure regex.
        return _classify_regex(text, filename, name_lower, is_image)

    return [primary] + _enrich(text)


def _classify_text_tiers(text: str, filename: str, is_image: bool,
                         use_llm: bool, use_embed: bool,
                         centroids: "dict[str, list[float]] | None",
                         text_model: str | None,
                         embed_model: str | None,
                         learn_sink: "Callable[[str, list, float, str], None] | None" = None,
                         escalation_sink: "Callable[[dict], None] | None" = None) -> "Fragment | None":
    """Run the embedding → generative cascade for a text document.

    Returns the primary fragment, or None if no tier was available.
    """
    excerpt = text[:300]

    # --- tier 2: embeddings -------------------------------------------------
    if use_embed and centroids and text.strip():
        vec = _embed.embed_document(text, model=embed_model or _embed.DEFAULT_EMBED_MODEL)
        if vec:
            ranked = _tax.rank(vec, centroids)
            st = _tax.margin_stats(ranked)
            # Self-learning / discovery hook: observe every embedded doc once,
            # reusing the vector we just computed (no extra model call).
            if learn_sink is not None:
                learn_sink(st["cat"], vec, st["margin"], _confidence_from_margin(st["margin"]))
            confident = st["margin"] >= MARGIN_CONFIDENT

            if confident:
                return _frag_from_category(st["cat"], _confidence_from_margin(st["margin"]), excerpt)

            # --- tier 3: escalate the uncertain tail to the LLM -------------
            if use_llm:
                cands = [c for _, c in ranked[:3]]
                teacher = text_model or _llm.DEFAULT_TEXT_MODEL
                verdict = _llm.classify_text(text, filename, model=teacher,
                                             candidates=cands)
                # Escalation log: the (excerpt, margin, top-3, verdict) tuple is
                # the distillation corpus for a tier-2.5 student. Logged even
                # when the teacher returned nothing, so "asked, no answer" is
                # distinguishable from "never asked".
                if escalation_sink is not None:
                    escalation_sink({
                        "excerpt": excerpt,
                        "margin": st["margin"],
                        "embed_best": st["cat"],
                        "candidates": cands,
                        "verdict": verdict,
                        "teacher_model": teacher,
                        "embed_model": embed_model or _embed.DEFAULT_EMBED_MODEL,
                    })
                if verdict is not None:
                    return _frag_from_verdict(verdict, text, is_image)

            # LLM off or failed → trust the embedding best if it stands out at
            # all (margin above the floor); otherwise it's genuinely unclear.
            if st["margin"] >= MARGIN_FLOOR:
                return _frag_from_category(st["cat"], "uncertain", excerpt)
            return Fragment(fragment_type="unknown", content=excerpt,
                            label="", confidence="speculative")

    # --- embeddings unavailable: go straight to the LLM ---------------------
    if use_llm and text.strip():
        verdict = _llm.classify_text(text, filename,
                                     model=text_model or _llm.DEFAULT_TEXT_MODEL)
        if verdict is not None:
            return _frag_from_verdict(verdict, text, is_image)

    return None  # caller falls back to regex


# --- tier 1 / fallback: pure regex (original behaviour) ---------------------

def _classify_regex(text: str, filename: str, name_lower: str,
                    is_image: bool) -> list[Fragment]:
    if not text.strip():
        if is_image:
            return [Fragment(fragment_type="photo",
                            content=f"[image: {filename}]",
                            label=filename, confidence="uncertain")]
        return []

    frags: list[Fragment] = []

    if _RECEIPT_WORDS.search(text):
        frags.append(Fragment(fragment_type="receipt", content=text[:500],
                              label=filename, confidence="likely"))
        frags.extend(_date_fragments(text))
        return frags

    event_matches = _EVENT_WORDS.findall(text)
    if event_matches:
        frags.append(Fragment(fragment_type="event", content=text[:800],
                              label=", ".join(set(m.lower() for m in event_matches[:3])),
                              confidence="uncertain"))

    seen_names: set[str] = set()
    frags.extend(_titled_person_fragments(text, seen_names))
    for m in _CAPITALIZED_NAME.finditer(text):
        name = m.group(1)
        if name not in seen_names and not _looks_like_org(name) and not any(
            w in name.lower() for w in ("the", "this", "that", "dear", "from", "with")
        ):
            seen_names.add(name)
            frags.append(Fragment(fragment_type="person", content=name, confidence="speculative"))

    frags.extend(_date_fragments(text))

    if _LOCATION_WORDS.search(text):
        for s in re.split(r"[.!?\n]", text):
            if _LOCATION_WORDS.search(s) and len(s.strip()) > 10:
                frags.append(Fragment(fragment_type="location", content=s.strip()[:300],
                                      confidence="speculative"))
                break

    if is_image:
        frags.append(Fragment(fragment_type="photo",
                              content=text[:400] if text.strip() else f"[image: {filename}]",
                              label=filename,
                              confidence="confirmed" if text.strip() else "uncertain"))

    if not frags:
        frags.append(Fragment(fragment_type="document", content=text[:600],
                              label=filename, confidence="uncertain"))

    return frags
