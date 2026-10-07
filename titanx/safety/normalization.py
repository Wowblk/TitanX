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


# Code points that render as nothing and serve as pattern-matcher bypass
# primitives. Most fall under the Unicode ``Cf`` (format) category and are
# caught by :func:`_is_invisible`'s category check; the entries here are
# the ones that are *not* ``Cf`` but are equally invisible (blank glyphs
# and filler letters), which no single Unicode property names for us.
_INVISIBLE_CHARS = frozenset({
    "\u0000",  # NULL
    "\u034f",  # COMBINING GRAPHEME JOINER (Mn)
    "\u115f",  # HANGUL CHOSEONG FILLER (Lo)
    "\u1160",  # HANGUL JUNGSEONG FILLER (Lo)
    "\u17b4",  # KHMER VOWEL INHERENT AQ (Mn)
    "\u17b5",  # KHMER VOWEL INHERENT AA (Mn)
    "\u180b",  # MONGOLIAN FREE VARIATION SELECTOR ONE (Mn)
    "\u180c",  # MONGOLIAN FREE VARIATION SELECTOR TWO (Mn)
    "\u180d",  # MONGOLIAN FREE VARIATION SELECTOR THREE (Mn)
    "\u180f",  # MONGOLIAN FREE VARIATION SELECTOR FOUR (Mn)
    "\u2065",  # unassigned (reserved invisible)
    "\u2800",  # BRAILLE PATTERN BLANK (So — renders as blank)
    "\u3164",  # HANGUL FILLER (Lo)
    "\uffa0",  # HALFWIDTH HANGUL FILLER (Lo)
    "\ufffc",  # OBJECT REPLACEMENT CHARACTER (So — zero-width)
})


def _is_invisible(ch: str) -> bool:
    """True for characters that render as nothing and can only be abuse.

    Rather than enumerate every invisible code point (a game the attacker
    wins by finding one more), we lean on the Unicode **``Cf`` (format)**
    category — the general class for characters that exist only to affect
    rendering: BiDi overrides and isolates, interlinear annotation, the
    shorthand/musical format controls, the deprecated ``U+206A``–``U+206F``
    run, and the whole tag block (``U+E0020``–``U+E007F``). Two further
    *ranges* are equally invisible and equally effective at splitting a
    trigger word: the variation-selector blocks (``U+FE00``–``U+FE0F`` and
    ``U+E0100``–``U+E01EF``). The curated set above then covers the
    remaining blanks/fillers that are *not* ``Cf`` (Hangul fillers, the
    Braille blank, Mongolian free variation selectors, ...).
    """
    if ch in _INVISIBLE_CHARS:
        return True
    code = ord(ch)
    if (
        0xE0000 <= code <= 0xE007F
        or 0xFE00 <= code <= 0xFE0F
        or 0xE0100 <= code <= 0xE01EF
    ):
        return True
    return unicodedata.category(ch) == "Cf"


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
        ch in _HOMOGLYPH_TO_ASCII or _is_invisible(ch)
        for ch in normalised
    )
    if not needs_rewrite:
        return normalised
    out: list[str] = []
    for ch in normalised:
        if _is_invisible(ch):
            continue
        out.append(_HOMOGLYPH_TO_ASCII.get(ch, ch))
    return "".join(out)


def strip_invisible_chars(text: str) -> str:
    """Remove invisible / formatting characters, keeping everything else.

    Unlike :func:`canonicalise_for_scan` this does **not** NFKC-normalise or
    fold homoglyphs — it only drops characters that render as nothing. It
    exists so pattern matchers that are not allowed to rewrite visible text
    (notably the PII redactor, which returns text to the user) can still
    match a token an attacker split with a zero-width byte, e.g.
    ``victim@exa\\u200bmple.com``.
    """
    if not text:
        return text
    if not any(_is_invisible(ch) for ch in text):
        return text
    return "".join(ch for ch in text if not _is_invisible(ch))
