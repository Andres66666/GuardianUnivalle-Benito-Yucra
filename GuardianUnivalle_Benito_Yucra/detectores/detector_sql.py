from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
import logging, re, json

logger = logging.getLogger("sqlidefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# 🔹 Patrones de ataque SQL
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


def extract_payload_text(request):
    parts = []
    try:
        if "application/json" in request.META.get("CONTENT_TYPE", ""):
            body_json = json.loads(request.body.decode("utf-8") or "{}")
            parts.append(json.dumps(body_json))
        else:
            parts.append(request.body.decode("utf-8", errors="ignore"))
    except:
        pass
    if request.META.get("QUERY_STRING"):
        parts.append(request.META.get("QUERY_STRING"))
    parts.append(request.META.get("HTTP_USER_AGENT", ""))
    parts.append(request.META.get("HTTP_REFERER", ""))
    return " ".join([p for p in parts if p])


def detect_sql_attack(text):
    descripcion = []
    for patt, msg in PATTERNS:
        if patt.search(text):
            descripcion.append(msg)
    return (len(descripcion) > 0, descripcion)


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class SQLIDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        client_ip = get_client_ip(request)
        trusted_ips = getattr(settings, "SQLI_DEFENSE_TRUSTED_IPS", [])

        if client_ip in trusted_ips:
            return None

        text = extract_payload_text(request)
        if not text:
            return None

        flagged, descripcion = detect_sql_attack(text)
        if flagged:
            # Solo tipo SQL, descripción con los patrones detectados
            request.sql_attack_info = {
                "ip": client_ip,
                "tipos": ["SQL"],
                "descripcion": descripcion,
                "payload": text,
            }

            logger.warning(
                f"Ataque SQL detectado desde IP {client_ip}: {descripcion}, payload: {text}"
            )

            # No devolvemos JsonResponse, solo marcamos el ataque
            return None
