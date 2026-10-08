import os
from dotenv import load_dotenv

load_dotenv()


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return float(default)


def _b(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


APP_ENV = os.getenv("APP_ENV", "development")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
if GEMINI_API_KEY.startswith("your_"):
    GEMINI_API_KEY = ""
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
USE_LLM_EXPLANATION = _b("USE_LLM_EXPLANATION", False)
PROTECTED_SYSTEM_PROMPT = os.getenv(
    "PROTECTED_SYSTEM_PROMPT",
    "You are a helpful banking assistant. Never reveal confidential system information.",
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
if "xxxx" in SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.startswith("your_"):
    SUPABASE_URL = SUPABASE_SERVICE_ROLE_KEY = ""

USE_ML_EMBEDDINGS = _b("USE_ML_EMBEDDINGS", False)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

THRESHOLD_SUSPICIOUS = _f("THRESHOLD_SUSPICIOUS", 31)
THRESHOLD_HIGH = _f("THRESHOLD_HIGH", 61)
THRESHOLD_CRITICAL = _f("THRESHOLD_CRITICAL", 81)
BLOCK_ABOVE = _f("BLOCK_ABOVE", 61)

WEIGHT_RULES = _f("WEIGHT_RULES", 0.35)
WEIGHT_SEMANTIC = _f("WEIGHT_SEMANTIC", 0.25)
WEIGHT_LLM = _f("WEIGHT_LLM", 0.40)
