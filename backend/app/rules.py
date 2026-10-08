"""Layer 1 - rule / pattern detector (fast, deterministic, explainable)."""
import re

# (regex, attack_type, weight 0-100, human readable reason)
RULES = [
    # ---- Prompt injection ----
    (r"\b(ignore|disregard|forget|override|bypass|drop|discard)\b.{0,40}\b(all|any|every|previous|prior|above|earlier|preceding|your|the|these|those)\b.{0,40}\b(instructions?|rules?|prompts?|directives?|guidelines?|constraints?|policies|programming)\b",
     "PROMPT_INJECTION", 92, "Attempts to override or discard higher-priority instructions"),
    (r"\b(forget|ignore|disregard|erase)\b.{0,30}\b(what|everything|anything|all)\b.{0,30}\b(told|said|instructed|given|taught|configured|programmed|learned)\b",
     "PROMPT_INJECTION", 82, "Asks the assistant to forget what it was told"),
    (r"\bnew (instructions?|rules?|task|directive)s?\s*[:\-]", "PROMPT_INJECTION", 70, "Injects a new set of instructions"),
    (r"\byou are now\b", "PROMPT_INJECTION", 55, "Tries to reassign the assistant's identity or role"),
    (r"\bfrom now on\b.{0,50}\b(you|ignore|act|respond|answer)\b", "PROMPT_INJECTION", 55, "Tries to permanently change assistant behaviour"),
    (r"(<\s*/?\s*(system|instructions?|admin)\s*>|\[\s*/?(system|inst|admin)\s*\]|###\s*(system|instruction))", "PROMPT_INJECTION", 75, "Fake system/instruction delimiters"),
    (r"\b(end|stop) of (the )?(system|previous|prior) (prompt|instructions?|message)\b", "PROMPT_INJECTION", 80, "Pretends the trusted instructions have ended"),
    (r"\b(instead|rather),? (of that,? )?(do|follow|obey|execute)\b.{0,30}\b(this|the following|my)\b", "PROMPT_INJECTION", 55, "Redirects the assistant to follow attacker instructions"),
    # ---- Jailbreak ----
    (r"\b(dan|do anything now)\b", "JAILBREAK", 85, "References the DAN / 'do anything now' jailbreak persona"),
    (r"\b(pretend|act|behave|roleplay|role-play|imagine)\b.{0,50}\b(unrestricted|unfiltered|uncensored|jailbroken|no (restrictions?|rules?|limits?|filters?|ethics))",
     "JAILBREAK", 90, "Asks the model to adopt an unrestricted persona"),
    (r"\b(unrestricted|unfiltered|uncensored|jailbroken)\s+(ai|assistant|model|mode|version|chatbot)", "JAILBREAK", 82, "Requests an unrestricted model mode"),
    (r"\b(developer|god|admin|sudo|debug) mode\b", "JAILBREAK", 78, "Requests a privileged 'mode' to bypass safeguards"),
    (r"\bjailbreak(ed|ing)?\b", "JAILBREAK", 75, "Explicit jailbreak keyword"),
    (r"\b(without|with no|free of|free from)\s+(any\s+)?(restrictions?|safety|filters?|limitations?|guardrails?|censorship)", "JAILBREAK", 72, "Asks to operate without safety restrictions"),
    (r"\b(no|ignore (your )?)(safety|ethical|content) (rules|guidelines|restrictions|policies)", "JAILBREAK", 75, "Asks the model to drop its safety rules"),
    # ---- System prompt extraction ----
    (r"\b(reveal|show|tell|print|display|repeat|output|leak|give|share|expose|dump|disclose|recite)\b.{0,40}\b(system|hidden|initial|original|secret|internal|underlying|developer)\b.{0,20}\b(prompt|instructions?|message|rules?|configuration|config)\b",
     "SYSTEM_PROMPT_EXTRACTION", 94, "Requests the hidden system prompt / instructions"),
    (r"\b(repeat|print|output|echo|copy)\b.{0,30}\b(text|everything|words|content|message)\b.{0,25}\b(above|before this|prior)\b",
     "SYSTEM_PROMPT_EXTRACTION", 86, "Asks the model to echo text preceding the user message"),
    (r"\bwhat (are|were|is) your (initial|original|system|hidden|secret|first) (instructions?|rules?|prompt|message)\b",
     "SYSTEM_PROMPT_EXTRACTION", 86, "Asks what the model's hidden instructions are"),
    (r"\b(your|the) (system|hidden|secret) (prompt|instructions?)\b", "SYSTEM_PROMPT_EXTRACTION", 60, "Refers to the hidden system prompt"),
    # ---- Data exfiltration ----
    (r"\b(give|show|reveal|print|send|tell|list|dump|leak|share|extract|read|fetch|expose|return)\b.{0,40}\b(your|stored|internal|environment|backend|server|system|secret|private|confidential|admin|database)\b.{0,30}\b(api[\s_-]?keys?|secret keys?|access tokens?|auth tokens?|passwords?|credentials?|private keys?|env(ironment)? (variables?|vars?|file)|\.env|connection strings?|database (url|password|credentials?))\b",
     "DATA_EXFILTRATION", 96, "Requests secrets, credentials or environment variables"),
    (r"\b(api[\s_-]?keys?|secret keys?|access tokens?|private keys?|environment variables?)\b.{0,25}\b(stored|saved|in your|you have|you hold|you use)\b",
     "DATA_EXFILTRATION", 90, "Asks for secrets the system holds"),
    (r"\b(dump|export|list|print|show me)\b.{0,30}\b(entire |full |whole )?(database|all (users?|customers?|accounts?|records?|emails?)|confidential (data|information|files?)|other users)\b",
     "DATA_EXFILTRATION", 86, "Requests bulk or confidential data"),
    (r"\b(send|post|forward|email|upload|exfiltrate|transmit)\b.{0,50}(https?://|\bto\b\s+\S+@\S+|webhook)", "DATA_EXFILTRATION", 68, "Asks to send data to an external destination"),
    (r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*(data|prompt|secret|key)=", "DATA_EXFILTRATION", 85, "Markdown image used to leak data to an external URL"),
]

COMPILED = [(re.compile(p, re.I | re.S), t, w, r) for p, t, w, r in RULES]


def run_rules(lower_text: str) -> dict:
    matches = []
    for rx, attack, weight, reason in COMPILED:
        m = rx.search(lower_text)
        if m:
            matches.append({"attack_type": attack, "weight": weight, "reason": reason, "span": [m.start(), m.end()], "matched": m.group(0)[:120]})
    if not matches:
        return {"score": 0, "attack_type": "NONE", "matches": [], "by_type": {}}

    by_type = {}
    for m in matches:
        by_type.setdefault(m["attack_type"], []).append(m["weight"])
    # per-type score: strongest rule + small bonus for each extra corroborating rule
    type_scores = {t: min(100, max(ws) + 4 * (len(ws) - 1)) for t, ws in by_type.items()}
    top_type = max(type_scores, key=type_scores.get)
    score = type_scores[top_type]
    # multi-vector attacks (e.g. override + extraction) are riskier
    if len(type_scores) > 1:
        score = min(100, score + 4 * (len(type_scores) - 1))
    return {"score": score, "attack_type": top_type, "matches": matches, "by_type": type_scores}
