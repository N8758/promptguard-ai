"""Layer 2 - semantic similarity against a library of known attacks.

Two interchangeable engines:
  * ML engine   : sentence-transformers (all-MiniLM-L6-v2) + FAISS  (USE_ML_EMBEDDINGS=true)
  * Light engine: word uni/bi-gram TF-IDF-style cosine, pure python  (default, zero extra installs)
"""
import json
import logging
import math
import re
from collections import Counter
from pathlib import Path

from . import config

log = logging.getLogger("promptguard.semantic")
DATA = Path(__file__).resolve().parent.parent / "data" / "attack_patterns.json"
STOP = set("a an the to of and or in on for with is are be this that it you your me my i please can could would will do does".split())


def _tokens(text: str):
    words = [w for w in re.findall(r"[a-z]+", text.lower()) if w not in STOP]
    return words + [f"{a}_{b}" for a, b in zip(words, words[1:])]


class LightEngine:
    name = "ngram-cosine"
    low, high = 0.30, 0.68  # similarity range mapped to 0..100

    def __init__(self, patterns):
        self.patterns = patterns
        docs = [Counter(_tokens(p["pattern_text"])) for p in patterns]
        df = Counter(t for d in docs for t in d)
        n = len(docs)
        self.idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
        self.vecs = [self._vec(d) for d in docs]

    def _vec(self, counter):
        v = {t: c * self.idf.get(t, 1.0) for t, c in counter.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def search(self, text, k=3):
        q = self._vec(Counter(_tokens(text)))
        sims = []
        for i, v in enumerate(self.vecs):
            s = sum(w * v.get(t, 0.0) for t, w in q.items())
            sims.append((s, i))
        sims.sort(reverse=True)
        return [(float(s), self.patterns[i]) for s, i in sims[:k]]


class MLEngine:
    name = "MiniLM+FAISS"
    low, high = 0.45, 0.85

    def __init__(self, patterns):
        import faiss  # noqa
        import numpy as np
        from sentence_transformers import SentenceTransformer

        self.np, self.faiss = np, faiss
        self.patterns = patterns
        self.model = SentenceTransformer(config.EMBEDDING_MODEL)
        emb = self.model.encode([p["pattern_text"] for p in patterns], normalize_embeddings=True).astype("float32")
        self.index = faiss.IndexFlatIP(emb.shape[1])
        self.index.add(emb)

    def search(self, text, k=3):
        q = self.model.encode([text], normalize_embeddings=True).astype("float32")
        sims, idx = self.index.search(q, k)
        return [(float(s), self.patterns[i]) for s, i in zip(sims[0], idx[0]) if i >= 0]


_engine = None


def load_patterns():
    patterns = json.loads(DATA.read_text(encoding="utf-8"))
    try:  # merge patterns stored in Supabase (optional)
        from .db import store
        extra = store.get_attack_patterns()
        known = {p["pattern_text"] for p in patterns}
        patterns += [p for p in extra if p["pattern_text"] not in known]
    except Exception as e:  # pragma: no cover
        log.info("Using local attack patterns only (%s)", e)
    return patterns


def get_engine():
    global _engine
    if _engine is None:
        patterns = load_patterns()
        if config.USE_ML_EMBEDDINGS:
            try:
                _engine = MLEngine(patterns)
                log.info("Semantic engine: MiniLM + FAISS")
            except Exception as e:
                log.warning("ML embeddings unavailable (%s) - falling back to n-gram engine", e)
        if _engine is None:
            _engine = LightEngine(patterns)
    return _engine


def run_semantic(normalized_text: str) -> dict:
    eng = get_engine()
    hits = eng.search(normalized_text, k=3)
    if not hits:
        return {"score": 0, "attack_type": "NONE", "engine": eng.name, "top_matches": []}
    best_sim, best = hits[0]
    score = max(0.0, min(1.0, (best_sim - eng.low) / (eng.high - eng.low))) * 100
    return {
        "score": round(score, 1),
        "attack_type": best["attack_type"] if score >= 30 else "NONE",
        "engine": eng.name,
        "top_matches": [{"similarity": round(s, 3), "pattern": p["pattern_text"], "attack_type": p["attack_type"]} for s, p in hits],
    }
