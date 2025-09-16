# detector_sql.py
import re
import json
import logging
from typing import Tuple
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger("sqlidefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# ---------- Patrones de ataques SQL ----------
PATTERNS = [
    (re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.I), "UNION SELECT"),
    (
        re.compile(r"\bselect\b.*\bfrom\b.*\bwhere\b.*\b(or|and)\b.*=", re.I),
        "SELECT con OR/AND",
    ),
    (re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.I), "OR/AND 1=1"),
    (
        re.compile(r"\b(drop|truncate|delete|insert|update)\b", re.I),
        "Manipulación de tabla",
    ),
    (re.compile(r"(--|#|;)", re.I), "Comentario o terminador sospechoso"),
    (re.compile(r"exec\s*\(", re.I), "Ejecución de procedimiento"),
]


# ---------- Helpers ----------
def extract_payload_text(request) -> str:
    parts = []
    content_type = request.META.get("CONTENT_TYPE", "")
    try:
        if "application/json" in content_type:
            body_json = json.loads(request.body.decode("utf-8") or "{}")
            parts.append(json.dumps(body_json))
        else:
            parts.append(request.body.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    if request.META.get("QUERY_STRING"):
        parts.append(request.META.get("QUERY_STRING"))
    parts.append(request.META.get("HTTP_USER_AGENT", ""))
    parts.append(request.META.get("HTTP_REFERER", ""))
    return " ".join([p for p in parts if p])


def detect_sqli_text(text: str) -> Tuple[bool, list]:
    matches = []
    for patt, message in PATTERNS:
        if patt.search(text):
            matches.append(message)
    return (len(matches) > 0, matches)


# ---------- Middleware ----------
class SQLIDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        text = extract_payload_text(request)
        if not text:
            return None

        flagged, matches = detect_sqli_text(text)
        if flagged:
            logger.warning(f"Ataque detectado: {matches}, payload: {text}")
            return JsonResponse(
                {"mensaje": "Ataque detectado", "tipos": matches}, status=403
            )

        return None
