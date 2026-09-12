"""
nest-seed/llm.py — optional local-AI classification via Ollama.

Pure stdlib (urllib + json + base64). No third-party client, no cloud.
Talks to a local Ollama daemon (default http://localhost:11434). If the
daemon is unreachable or the models are missing, every function returns
None and the caller falls back to the pure-regex classifier — so the app
stays portable and works offline-with-no-models exactly as before.

Two capabilities:
  classify_text(text, filename)  → verdict dict | None   (text models)
  describe_image(path)           → verdict dict | None   (vision model)

A "verdict" is:
  {"fragment_type": str, "category": str, "confidence": str, "summary": str}
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_TEXT_MODEL = os.environ.get("NEST_TEXT_MODEL", "llama3.2:3b")
DEFAULT_VISION_MODEL = os.environ.get("NEST_VISION_MODEL", "qwen2.5vl:7b")

# Fragment types the DB accepts (mirror db.FRAGMENT_TYPES).
_FRAGMENT_TYPES = {
    "person", "date", "location", "event",
    "document", "photo", "note", "receipt", "unknown",
}
# Topical categories — what kills the "unknown" pile. Stored in fragment.label.
CATEGORIES = (
    "legal", "journal", "knowledge", "narrative", "specs", "code",
    "correspondence", "financial", "education", "personal", "media",
    "config", "data", "other",
)
_CONFIDENCE = {"confirmed", "likely", "uncertain", "speculative"}

_SYSTEM = (
    "You are a file classifier for a personal knowledge 'nest'. "
    "You receive the text (or a description) of one file and sort it. "
    "Reply with ONLY a single JSON object, no prose, no markdown fence. "
    "Schema: {\"fragment_type\": one of "
    "[document, note, event, receipt, person, location, date, photo, unknown], "
    "\"category\": one of [" + ", ".join(CATEGORIES) + "], "
    "\"confidence\": one of [confirmed, likely, uncertain, speculative], "
    "\"summary\": a one-sentence description (max 160 chars)}. "
    "Pick the single best category. Use 'unknown' only when genuinely "
    "unclassifiable. Be decisive."
)

_TIMEOUT = float(os.environ.get("NEST_LLM_TIMEOUT", "60"))

# Module-level availability cache: None=unchecked, True/False=result.
_available: bool | None = None
_installed_models: set[str] | None = None


def _http_json(path: str, payload: dict, timeout: float = _TIMEOUT) -> dict | None:
    url = f"{DEFAULT_HOST}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - local Ollama host; egress gated at the tool boundary (model_egress)
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def installed_models() -> set[str]:
    """Return the set of model tags Ollama reports, or empty set if down."""
    global _installed_models
    if _installed_models is not None:
        return _installed_models
    try:
        with urllib.request.urlopen(f"{DEFAULT_HOST}/api/tags", timeout=5) as resp:  # nosec B310 - local Ollama host; egress gated at the tool boundary (model_egress)
            tags = json.loads(resp.read().decode("utf-8"))
        _installed_models = {m.get("name", "") for m in tags.get("models", [])}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        _installed_models = set()
    return _installed_models


def available(model: str = DEFAULT_TEXT_MODEL) -> bool:
    """True if Ollama is reachable and the named model is installed."""
    models = installed_models()
    if not models:
        return False
    # Accept exact tag or bare name match (llama3.2 vs llama3.2:3b).
    base = model.split(":", 1)[0]
    return model in models or any(m.split(":", 1)[0] == base for m in models)


def _resolve(model: str) -> str | None:
    """Map a requested model to an actually-installed tag, or None."""
    models = installed_models()
    if model in models:
        return model
    base = model.split(":", 1)[0]
    for m in models:
        if m.split(":", 1)[0] == base:
            return m
    return None


def _coerce_verdict(raw: str) -> dict | None:
    """Parse a model reply into a normalized verdict, or None."""
    if not raw:
        return None
    s = raw.strip()
    # Strip an accidental ```json fence.
    if s.startswith("```"):
        s = s.strip("`")
        s = s[4:].strip() if s.lower().startswith("json") else s
    # Grab the first {...} block.
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        obj = json.loads(s[start:end + 1])
    except ValueError:
        return None

    ft = str(obj.get("fragment_type", "document")).lower().strip()
    if ft not in _FRAGMENT_TYPES:
        ft = "document"
    cat = str(obj.get("category", "other")).lower().strip()
    if cat not in CATEGORIES:
        cat = "other"
    conf = str(obj.get("confidence", "uncertain")).lower().strip()
    if conf not in _CONFIDENCE:
        conf = "uncertain"
    summary = str(obj.get("summary", "")).strip()[:160]
    return {"fragment_type": ft, "category": cat, "confidence": conf, "summary": summary}


def classify_text(text: str, filename: str = "",
                  model: str = DEFAULT_TEXT_MODEL,
                  candidates: "list[str] | None" = None) -> dict | None:
    """Classify a text document with a local Ollama model. None on any failure.

    `candidates` (when given) are the top categories from the semantic embedding
    pre-pass — the model is told these are the likely fits and asked to choose
    among them or override. This both speeds the call and improves agreement.
    """
    tag = _resolve(model)
    if not tag or not text.strip():
        return None
    # Cap the payload — first ~6k chars is plenty for a type/category call.
    excerpt = text[:6000]
    hint = ""
    if candidates:
        hint = ("A semantic pre-pass suggests these likely categories, best first: "
                f"{', '.join(candidates)}. Choose the best fit among them, or "
                "override if they are all clearly wrong.\n\n")
    prompt = (
        f"Filename: {filename}\n\n"
        f"{hint}"
        f"File text (may be truncated):\n{excerpt}\n\n"
        "Classify this file. Return only the JSON object."
    )
    resp = _http_json("/api/chat", {
        "model": tag,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    })
    if not resp:
        return None
    content = (resp.get("message") or {}).get("content", "")
    return _coerce_verdict(content)


def describe_image(path: Path, model: str = DEFAULT_VISION_MODEL) -> dict | None:
    """Classify an image with a local vision model. None on any failure."""
    tag = _resolve(model)
    if not tag:
        return None
    try:
        b64 = base64.b64encode(Path(path).read_bytes()).decode("ascii")
    except OSError:
        return None
    resp = _http_json("/api/chat", {
        "model": tag,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {
                "role": "user",
                "content": (
                    f"Filename: {path.name}\n"
                    "Look at this image and classify it. Return only the JSON object."
                ),
                "images": [b64],
            },
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }, timeout=_TIMEOUT * 2)
    if not resp:
        return None
    content = (resp.get("message") or {}).get("content", "")
    verdict = _coerce_verdict(content)
    if verdict:
        # An image is always a photo at the fragment level; category is the signal.
        verdict["fragment_type"] = "photo"
    return verdict
