"""NLP processing for threat records.

Loads the spaCy ``en_core_web_sm`` model lazily so importing the module
does not crash when the model is missing (this is important for unit
tests that only exercise the keyword-based classifier).
"""

from __future__ import annotations

from typing import Any

from .config import THREAT_CATEGORIES
from .logging_config import get_logger

logger = get_logger(__name__)

# The spaCy model is loaded once on first use. ``None`` means "not loaded
# yet"; ``False`` means "loading failed, do not retry".
_NLP = None
_NLP_DISABLED = False


def _get_nlp():
    """Return the spaCy model, or ``None`` if it is unavailable."""
    global _NLP, _NLP_DISABLED
    if _NLP_DISABLED:
        return None
    if _NLP is None:
        try:
            import spacy

            _NLP = spacy.load("en_core_web_sm")
        except OSError:
            logger.warning(
                "spaCy model 'en_core_web_sm' missing. "
                "Run: python -m spacy download en_core_web_sm"
            )
            _NLP_DISABLED = True
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not initialise spaCy: %s", exc)
            _NLP_DISABLED = True
            return None
    return _NLP


def classify_threat(text: str) -> str:
    """Classify free text into one of :data:`config.THREAT_CATEGORIES`.

    Args:
        text: Threat title + summary (any casing).

    Returns:
        The matching category name, or ``"Uncategorized"`` when no
        keyword matches.
    """
    if not text:
        return "Uncategorized"
    text_lower = text.lower()
    for category, keywords in THREAT_CATEGORIES.items():
        if any(keyword in text_lower for keyword in keywords):
            return category
    return "Uncategorized"


def process_nlp(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich threat records with NLP-derived fields.

    For each threat the function adds:
      - ``entities``: up to 5 named entities (ORG, GPE, MONEY, NORP).
      - ``summary_nlp``: short summary built from the first 2 sentences.
      - ``threat_type``: keyword-based category label.

    When the spaCy model is unavailable the function still classifies the
    threat using :func:`classify_threat` and falls back to the original
    summary for ``summary_nlp`` so the rest of the pipeline can run.

    Args:
        threats: List of threat dicts containing at least ``title`` and
            ``summary``.

    Returns:
        The same list (mutated in place) with the extra fields populated.
    """
    nlp = _get_nlp()
    for threat in threats:
        summary = threat.get("summary", "") or ""
        title = threat.get("title", "") or ""
        if nlp is not None:
            doc = nlp(summary)
            entities = [ent.text for ent in doc.ents if ent.label_ in ["ORG", "GPE", "MONEY", "NORP"]]
            threat["entities"] = list(set(entities))[:5]
            threat["summary_nlp"] = " ".join(sent.text.strip() for sent in list(doc.sents)[:2])
        else:
            threat.setdefault("entities", [])
            threat["summary_nlp"] = summary
        threat["threat_type"] = classify_threat(f"{title} {summary}")
    return threats
