"""Unicode canonicalisation used by both ``SafetyLayer`` and ``InputValidator``.

Lives in its own module to keep the import graph acyclic — both
``safety_layer.py`` and ``validator.py`` need this helper, and they import
each other transitively.
"""
from __future__ import annotations

import unicodedata


# Hand-curated subset of Cyrillic / Greek / Armenian / Latin Extended
# code points that look identical (or near-identical) to ASCII Latin
# letters. NFKC alone does NOT fold these — they are distinct
# scripts in Unicode. For an exhaustive list see Unicode TR39 / the
# confusables.txt corpus; what we ship here are the homoglyphs that
# appear in real injection PoCs ("Іgnore previous instructions" with
# Cyrillic І, "Аct as DAN" with Cyrillic А, etc.). Add more as needed
# by passing a custom canonicaliser to your SafetyLayer subclass.
_HOMOGLYPH_TO_ASCII: dict[str, str] = {
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0406": "I",
    "\u0408": "J", "\u0405": "S", "\u0407": "I",
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i",
    # Greek uppercase that look like Latin
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
    # Greek lowercase that look like Latin
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03bf": "o",
    "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    # Armenian
    "\u054f": "S", "\u0555": "O",
    # Latin extended that NFKC sometimes leaves alone
    "\u026a": "I", "\u01c0": "I",
}


# Code points that have no business inside user-supplied text and serve as
# common pattern-matcher bypass primitives. See ``canonicalise_for_scan``
# for usage.
_INVISIBLE_CHARS = frozenset({
    "\u0000",  # NULL
    "\u00ad",  # SOFT HYPHEN
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
    "\ufeff",  # ZW NO-BREAK SPACE / BOM
})


def canonicalise_for_scan(text: str) -> str:
    """Normalise text so injection patterns can't be defeated by Unicode.

    Steps:
      1. NFKC normalisation collapses compatibility forms (fullwidth Latin
         ``Ｉ`` → ``I``, ligatures, etc.).
      2. Fold a curated set of homoglyphs (Cyrillic / Greek / Armenian /
         Latin Extended look-alikes) onto their ASCII equivalents so
         attackers can't smuggle ``Іgnore`` (Cyrillic І) or ``Аct as DAN``
         (Cyrillic А) past the pattern matcher.
      3. Strip invisible / BiDi / formatting characters that legitimate
         user content has no need for and that attackers routinely insert
         between letters of a trigger phrase.

    This canonical form is intended for **pattern matching only**. Callers
    that surface text back to the user (``sanitized_content`` etc.) should
    keep the original input apart from explicit PII redaction — silently
    rewriting fullwidth characters or stripping a legitimate BOM is a UX
    regression for non-attack input.
    """
    if not text:
        return text
    normalised = unicodedata.normalize("NFKC", text)
    # Two-stage rebuild: only allocate a new string if there is something
    # to fold or strip. The fast path (no homoglyphs, no invisibles) is the
    # common case for legitimate input and stays allocation-free.
    needs_rewrite = any(
        ch in _HOMOGLYPH_TO_ASCII or ch in _INVISIBLE_CHARS
        for ch in normalised
    )
    if not needs_rewrite:
        return normalised
    out: list[str] = []
    for ch in normalised:
        if ch in _INVISIBLE_CHARS:
            continue
        out.append(_HOMOGLYPH_TO_ASCII.get(ch, ch))
    return "".join(out)
