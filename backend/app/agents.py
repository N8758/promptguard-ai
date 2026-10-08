"""The five security agents. Each takes a shared context dict and returns its own output."""
import re
import time

from . import config, llm
from .normalizer import normalize
from .rules import run_rules
from .semantic import run_semantic

BENIGN_CONTEXT = re.compile(
    r"\b(what is|what are|explain|define|how (do|does|can|to)|why (do|does|is)|tell me about|describe|example of|article|course|research|"
    r"protect|prevent|defend|detect|mitigate|learn about)\b.{0,60}\b(prompt injection|jailbreak|system prompt|prompt leak|llm security|ai security|data exfiltration)\b", re.I)
IMPERATIVE_ATTACK = re.compile(r"\b(ignore|disregard|forget|reveal|print|give me|show me|you are now|pretend|from now on)\b", re.I)


def _timed(fn):
    def wrap(ctx):
        t = time.perf_counter()
        out = fn(ctx)
        return {"name": fn.__name__.replace("_agent", "").upper(), "status": out.pop("_status", "OK"),
                "summary": out.pop("_summary"), "output": out, "duration_ms": round((time.perf_counter() - t) * 1000)}
    return wrap


@_timed
def detection_agent(ctx):
    """What is happening? Normalise, then run rule, semantic and LLM layers."""
    norm = normalize(ctx["prompt"])
    rules = run_rules(norm["lower"])
    sem = run_semantic(norm["normalized"])
    llm_res = llm.classify(norm["normalized"])
    ctx.update(norm=norm, rules=rules, sem=sem, llm=llm_res)
    layers = [f"rules {rules['score']}", f"semantic {sem['score']}", f"LLM {llm_res['score'] if llm_res else 'n/a'}"]
    return {
        "_summary": "Layer scores: " + ", ".join(layers),
        "obfuscation_techniques": norm["techniques"],
        "rule_matches": [{"attack_type": m["attack_type"], "reason": m["reason"], "weight": m["weight"]} for m in rules["matches"]],
        "semantic": {"score": sem["score"], "engine": sem["engine"], "closest": sem["top_matches"][:1]},
        "llm": llm_res,
    }


@_timed
def verification_agent(ctx):
    """Is this really an attack? Cross-check layers, resolve attack type, discount educational questions."""
    rules, sem, llm_res, norm = ctx["rules"], ctx["sem"], ctx["llm"], ctx["norm"]
    votes = {}
    for src, t, s in (("rules", rules["attack_type"], rules["score"]), ("semantic", sem["attack_type"], sem["score"]),
                      ("llm", llm_res["attack_type"] if llm_res else "NONE", llm_res["score"] if llm_res else 0)):
        if t != "NONE" and s >= 30:
            votes[t] = votes.get(t, 0) + s
    attack = max(votes, key=votes.get) if votes else "NONE"
    layers_flagging = sum(1 for s in (rules["score"], sem["score"], llm_res["score"] if llm_res else 0) if s >= 50)

    educational = bool(BENIGN_CONTEXT.search(norm["normalized"])) and not IMPERATIVE_ATTACK.search(norm["normalized"])
    # An attack with obfuscation applied is its own category (the normaliser had to unmask it)
    hidden = [t for t in norm["techniques"] if t != "unicode_compatibility_chars"]
    if attack != "NONE" and hidden and (rules["score"] >= 50 or (llm_res and llm_res["score"] >= 50)):
        ctx["underlying_attack"] = attack
        attack = "OBFUSCATION"
    ctx.update(attack=attack, educational=educational, layers_flagging=layers_flagging)
    verdict = "benign discussion of a security topic" if educational else ("confirmed" if layers_flagging >= 1 else "no confirmed attack")
    return {"_summary": f"{verdict.capitalize()} ({layers_flagging} layer(s) flagged)",
            "attack_type": attack, "layers_flagging": layers_flagging, "educational_context": educational,
            "underlying_attack": ctx.get("underlying_attack"), "verdict": verdict}


@_timed
def risk_agent(ctx):
    """How dangerous is it? Weighted layer score with a floor for any single high-confidence layer."""
    rules, sem, llm_res = ctx["rules"], ctx["sem"], ctx["llm"]
    layers = {"rules": (rules["score"], config.WEIGHT_RULES), "semantic": (sem["score"], config.WEIGHT_SEMANTIC)}
    if llm_res:
        layers["llm"] = (llm_res["score"], config.WEIGHT_LLM)
    total_w = sum(w for _, w in layers.values()) or 1
    weighted = sum(s * w for s, w in layers.values()) / total_w
    # semantic similarity alone is weaker evidence than a rule or LLM verdict, so it is discounted when it stands alone
    strongest = max(rules['score'], llm_res['score'] if llm_res else 0, 0.75 * sem['score'])
    risk = max(weighted, strongest * 0.9)           # one confident detector is enough to escalate
    if ctx["layers_flagging"] >= 2:
        risk = min(100, risk + 5)                    # agreement between layers raises confidence
    if ctx["norm"]["techniques"] and ctx["attack"] == "OBFUSCATION":
        risk = min(100, risk + 4)
    if ctx["educational"]:
        risk = min(risk, 20)                         # asking ABOUT attacks is not an attack
    risk = int(round(risk))
    level = ("CRITICAL" if risk >= config.THRESHOLD_CRITICAL else "HIGH" if risk >= config.THRESHOLD_HIGH
             else "SUSPICIOUS" if risk >= config.THRESHOLD_SUSPICIOUS else "SAFE")
    ctx.update(risk=risk, level=level)
    if risk < config.THRESHOLD_SUSPICIOUS:
        ctx["attack"] = "NONE"
    return {"_summary": f"Risk {risk}/100 - {level}", "risk_score": risk, "threat_level": level,
            "weighted_score": round(weighted, 1), "strongest_layer": round(strongest, 1),
            "layers_used": list(layers.keys())}


def _sanitize(ctx):
    text = ctx["prompt"]
    norm_text = ctx["norm"]["normalized"]
    spans = sorted((m["span"] for m in ctx["rules"]["matches"]), reverse=True)
    if ctx["norm"]["techniques"]:   # spans refer to the normalised text, so clean that version
        text = norm_text
    for a, b in spans:
        # widen to the surrounding sentence/clause so no dangling fragments remain
        s = max(text.rfind(".", 0, a), text.rfind("?", 0, a), text.rfind("!", 0, a), text.rfind(",", 0, a)) + 1
        e_candidates = [i for i in (text.find(".", b), text.find("?", b), text.find("!", b), text.find(",", b)) if i != -1]
        e = min(e_candidates) + 1 if e_candidates else len(text)
        text = text[:s] + " " + text[e:]
    return re.sub(r"\s+", " ", text).strip(" ,;:-")


@_timed
def policy_agent(ctx):
    """What do we do? ALLOW / SANITIZE / BLOCK."""
    risk = ctx["risk"]
    sanitized = None
    monitor = False
    if risk >= config.BLOCK_ABOVE:
        decision = "BLOCK"
    elif risk >= config.THRESHOLD_SUSPICIOUS:
        sanitized = _sanitize(ctx)
        if len(sanitized) >= 8 and sanitized.lower() != ctx["prompt"].lower():
            decision = "SANITIZE"
        else:   # nothing specific to strip (semantic/LLM suspicion only): allow, but flag for monitoring
            decision, sanitized, monitor = "ALLOW", None, True
    else:
        decision = "ALLOW"
    ctx.update(decision=decision, sanitized=sanitized)
    action = {"ALLOW": "Forward prompt to the LLM" + (" and flag it for monitoring (suspicious, but no specific malicious fragment to remove)" if monitor else ""), "SANITIZE": "Strip malicious fragments, forward the rest", "BLOCK": "Stop the request before it reaches the LLM"}[decision]
    return {"_summary": f"{decision}: {action}", "decision": decision, "action": action, "monitor": monitor, "sanitized_prompt": sanitized,
            "thresholds": {"suspicious": config.THRESHOLD_SUSPICIOUS, "block_above": config.BLOCK_ABOVE}}


LABEL = {"PROMPT_INJECTION": "Prompt Injection", "JAILBREAK": "Jailbreak", "SYSTEM_PROMPT_EXTRACTION": "System Prompt Extraction",
         "DATA_EXFILTRATION": "Data Exfiltration", "OBFUSCATION": "Obfuscated Attack", "NONE": "None"}


@_timed
def explanation_agent(ctx):
    """Why did we decide that? Human-readable reasons + recommendation."""
    reasons = []
    for m in ctx["rules"]["matches"]:
        if m["reason"] not in reasons:
            reasons.append(m["reason"])
    if ctx["norm"]["techniques"]:
        reasons.append("Obfuscation detected and removed: " + ", ".join(t.replace("_", " ") for t in ctx["norm"]["techniques"]))
    if ctx["sem"]["score"] >= 50 and ctx["sem"]["top_matches"]:
        reasons.append(f"Semantically similar ({ctx['sem']['top_matches'][0]['similarity']:.2f}) to a known {LABEL[ctx['sem']['top_matches'][0]['attack_type']].lower()} pattern")
    if ctx["llm"] and ctx["llm"]["score"] >= 50 and ctx["llm"]["reason"]:
        reasons.append("LLM security classifier: " + ctx["llm"]["reason"].rstrip("."))
    if ctx["educational"]:
        reasons = ["Question about a security topic, with no instruction aimed at this assistant"]
    if not reasons:
        reasons = ["No instruction override, extraction or exfiltration behaviour found"]
    rec = {"BLOCK": "Block the request and prevent it from reaching the downstream AI agent.",
           "SANITIZE": "Forward only the sanitized prompt and keep monitoring this user.",
           "ALLOW": "Request is safe to forward." if ctx["risk"] < config.THRESHOLD_SUSPICIOUS else "Forwarded with monitoring: suspicious signals, but nothing specific to remove."}[ctx["decision"]]
    narrative = llm.explain(f"Decision: {ctx['decision']}; risk {ctx['risk']}/100; attack type {ctx['attack']}; reasons: {'; '.join(reasons)}")
    ctx.update(reasons=reasons, recommendation=rec, narrative=narrative)
    return {"_summary": f"{len(reasons)} reason(s) generated", "reasons": reasons, "recommendation": rec, "narrative": narrative}


PIPELINE = [detection_agent, verification_agent, risk_agent, policy_agent, explanation_agent]


def run_pipeline(prompt: str) -> dict:
    ctx = {"prompt": prompt}
    agents = [step(ctx) for step in PIPELINE]
    return {"ctx": ctx, "agents": agents}
