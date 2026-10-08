"""Input normalisation: undo common obfuscation tricks before analysis."""
import base64
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u202e\u202d"), None)

# Cyrillic / Greek look-alikes -> latin
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s",
    "ј": "j", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "ɑ": "a", "ӏ": "l", "һ": "h",
})
LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Leetspeak is only "undone" when the result is a word an attacker is likely to hide.
# This avoids false positives on things like "10k", "3rd", "401k", "2FA".
SENSITIVE_WORDS = set("""ignore ignoring previous instructions instruction system prompt prompts reveal rules rule bypass
override disregard forget unrestricted unfiltered uncensored jailbreak password passwords secret secrets confidential
hidden developer restrictions safety api key keys credentials token tokens all above prior earlier show tell print
pretend now guidelines policies environment variables variable admin root sudo""".split())

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
# symbols that are almost never inside normal words (NOT - . ' which are common in real text)
SPLIT_SYMBOLS_RE = re.compile(r"(?<=[A-Za-z])[#*_|^~`+\\]+(?=[A-Za-z])")
# "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e"
SPACED_LETTERS_RE = re.compile(r"\b(?:[A-Za-z][\s.\-_*]){4,}[A-Za-z]\b")
MIXED_TOKEN_RE = re.compile(r"[A-Za-z0-9@$]{3,}")


def _decode_b64(text: str):
    found = []
    for m in B64_RE.finditer(text):
        token = m.group(0)
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.95 and " " in decoded:
            found.append(decoded)
    return found


def _fix_token(m: re.Match) -> str:
    tok = m.group(0)
    has_letter = any(c.isalpha() for c in tok)
    has_leet = any(c in "013457@$" for c in tok)
    if has_letter and has_leet:
        for table in (LEET_I, LEET_L):
            cand = tok.translate(table).lower()
            if cand in SENSITIVE_WORDS:
                return cand
    return tok


def normalize(text: str) -> dict:
    techniques = []
    out = text

    n = unicodedata.normalize("NFKC", out)
    if n != out:
        techniques.append("unicode_compatibility_chars")
    out = n

    n = out.translate(ZERO_WIDTH)
    if n != out:
        techniques.append("zero_width_characters")
    out = n

    n = out.translate(HOMOGLYPHS)
    if n != out:
        techniques.append("homoglyph_substitution")
    out = n

    n = SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), out)
    if n != out:
        techniques.append("letter_spacing")
    out = n

    n = SPLIT_SYMBOLS_RE.sub("", out)
    if n != out:
        techniques.append("symbol_insertion")
    out = n

    n = MIXED_TOKEN_RE.sub(_fix_token, out)
    if n != out:
        techniques.append("leetspeak")
    out = n

    decoded = _decode_b64(out)
    if decoded:
        techniques.append("base64_payload")
        out = out + " " + " ".join(decoded)

    out = re.sub(r"\s+", " ", out).strip()
    return {"original": text, "normalized": out, "lower": out.lower(), "techniques": techniques}
