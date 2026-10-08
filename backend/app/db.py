"""Storage layer: Supabase when configured, otherwise in-memory (so the demo never breaks)."""
import hashlib
import logging
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone

from . import config

log = logging.getLogger("promptguard.db")


def hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


class Store:
    def __init__(self):
        self.mem = []          # analysis rows
        self.mem_logs = []     # agent logs
        self.lock = threading.Lock()
        self.sb = None
        if config.SUPABASE_URL and config.SUPABASE_SERVICE_ROLE_KEY:
            try:
                from supabase import create_client
                self.sb = create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_ROLE_KEY)
                self.sb.table("prompt_analyses").select("id").limit(1).execute()
                log.info("Connected to Supabase")
            except Exception as e:
                log.warning("Supabase unavailable (%s) - using in-memory storage", e)
                self.sb = None

    @property
    def backend(self) -> str:
        return "supabase" if self.sb else "memory"

    # ------------------------------------------------------------------ write
    def save_analysis(self, result: dict, agents: list) -> str:
        row = {
            "prompt_text": result["prompt"],
            "prompt_hash": hash_prompt(result["prompt"]),
            "normalized_prompt": result["normalization"]["normalized"],
            "attack_type": result["attack_type"],
            "risk_score": result["risk_score"],
            "threat_level": result["threat_level"],
            "decision": result["decision"],
            "rule_score": result["scores"]["rules"],
            "semantic_score": result["scores"]["semantic"],
            "llm_score": result["scores"]["llm"] or 0,
            "reason": "; ".join(result["reasons"]),
            "reasons": result["reasons"],
            "sanitized_prompt": result.get("sanitized_prompt"),
            "llm_response": result.get("llm_response"),
            "latency_ms": result["latency_ms"],
        }
        logs = [{"agent_name": a["name"], "status": a["status"], "output": a["output"], "duration_ms": a["duration_ms"]} for a in agents]
        if self.sb:
            try:
                ins = self.sb.table("prompt_analyses").insert(row).execute()
                aid = ins.data[0]["id"]
                if logs:
                    self.sb.table("agent_logs").insert([{**l, "analysis_id": aid} for l in logs]).execute()
                return aid
            except Exception as e:
                log.warning("Supabase insert failed (%s) - saved in memory instead", e)
        aid = str(uuid.uuid4())
        with self.lock:
            self.mem.append({**row, "id": aid, "created_at": datetime.now(timezone.utc).isoformat()})
            self.mem_logs.extend({**l, "analysis_id": aid} for l in logs)
        return aid

    # ------------------------------------------------------------------- read
    def _all_rows(self):
        if self.sb:
            try:
                return self.sb.table("prompt_analyses").select("attack_type,risk_score,decision,latency_ms,created_at").order("created_at", desc=True).limit(5000).execute().data
            except Exception as e:
                log.warning("Supabase read failed: %s", e)
        with self.lock:
            return list(self.mem)

    def get_stats(self) -> dict:
        rows = self._all_rows()
        total = len(rows)
        threats = [r for r in rows if r["attack_type"] != "NONE"]
        by_type = Counter(r["attack_type"] for r in threats)
        blocked = sum(r["decision"] == "BLOCK" for r in rows)
        sanitized = sum(r["decision"] == "SANITIZE" for r in rows)
        avg_risk = round(sum(r["risk_score"] for r in rows) / total, 1) if total else 0
        lat = [r["latency_ms"] for r in rows if r.get("latency_ms") is not None]
        # "security score": share of risky traffic that was stopped (100 when nothing risky happened)
        risky = [r for r in rows if r["risk_score"] >= config.THRESHOLD_SUSPICIOUS]
        stopped = [r for r in risky if r["decision"] in ("BLOCK", "SANITIZE")]
        sec = round(100 * len(stopped) / len(risky)) if risky else 100
        return {
            "total_requests": total,
            "threats_detected": len(threats),
            "blocked": blocked,
            "sanitized": sanitized,
            "allowed": total - blocked - sanitized,
            "avg_risk_score": avg_risk,
            "avg_latency_ms": round(sum(lat) / len(lat)) if lat else 0,
            "security_score": sec,
            "threats_by_type": [{"attack_type": k, "total": v} for k, v in by_type.most_common()],
            "storage": self.backend,
        }

    def get_history(self, limit=20) -> list:
        cols = "id,created_at,prompt_text,attack_type,risk_score,threat_level,decision"
        if self.sb:
            try:
                return self.sb.table("prompt_analyses").select(cols).order("created_at", desc=True).limit(limit).execute().data
            except Exception as e:
                log.warning("Supabase read failed: %s", e)
        with self.lock:
            rows = sorted(self.mem, key=lambda r: r["created_at"], reverse=True)[:limit]
        return [{k: r[k] for k in cols.split(",")} for r in rows]

    def get_attack_patterns(self) -> list:
        if not self.sb:
            return []
        return self.sb.table("attack_patterns").select("pattern_text,attack_type").execute().data


store = Store()
