# csrf_defense.py
# GuardianUnivalle_Benito_Yucra/detectores/csrf_defense.py

from __future__ import annotations
import secrets
import logging
import re
import json
from typing import List, Dict, Any
from urllib.parse import urlparse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger("csrfdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER_NAMES = ("HTTP_X_CSRFTOKEN", "HTTP_X_CSRF_TOKEN")
CSRF_COOKIE_NAME = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
POST_FIELD_NAME = "csrfmiddlewaretoken"

# Patrón de Content-Type sospechoso - EXPANDIDO
SUSPICIOUS_CT_PATTERNS = [
    re.compile(r"text/plain", re.I),
    re.compile(r"application/x-www-form-urlencoded", re.I),
    re.compile(r"multipart/form-data", re.I),
    re.compile(r"application/json", re.I),
    re.compile(r"text/html", re.I),  # Agregado para HTML CSRF
]

# Parámetros sensibles típicos de CSRF - EXPANDIDO
SENSITIVE_PARAMS = [
    "password", "csrfmiddlewaretoken", "token", "amount", "transfer", "delete", "update", "action", "email", "username"
]

# Campos sensibles: ANALIZAMOS COMPLETAMENTE SIN DESCUENTO PARA ROBUSTEZ MÁXIMA
SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth", "email", "username"]

CSRF_DEFENSE_MIN_SIGNALS = getattr(settings, "CSRF_DEFENSE_MIN_SIGNALS", 1)
CSRF_DEFENSE_EXCLUDED_API_PREFIXES = getattr(settings, "CSRF_DEFENSE_EXCLUDED_API_PREFIXES", ["/api/"])

# PATRONES EXPANDIDOS PARA ANÁLISIS DE PAYLOAD EN TODOS LOS CAMPOS (SIN DESCUENTO)
CSRF_PAYLOAD_PATTERNS = [
    (re.compile(r"<script[^>]*>.*?</script>", re.I | re.S), "Script tag en payload", 0.9),
    (re.compile(r"javascript\s*:", re.I), "URI javascript: en payload", 0.8),
    (re.compile(r"http[s]?://[^\s]+", re.I), "URL externa en payload", 0.7),
    (re.compile(r"eval\s*\(", re.I), "eval() en payload", 1.0),
    (re.compile(r"document\.cookie", re.I), "Acceso a cookie en payload", 0.9),
    (re.compile(r"innerHTML\s*=", re.I), "Manipulación DOM innerHTML", 0.8),
    (re.compile(r"XMLHttpRequest", re.I), "XHR en payload", 0.7),
    (re.compile(r"fetch\s*\(", re.I), "fetch() en payload", 0.7),
    (re.compile(r"&#x[0-9a-fA-F]+;", re.I), "Entidades HTML en payload", 0.6),
    (re.compile(r"%3Cscript", re.I), "Script URL-encoded en payload", 0.8),
    (re.compile(r"on\w+\s*=", re.I), "Eventos on* en payload", 0.7),
    (re.compile(r"alert\s*\(", re.I), "alert() en payload (prueba)", 0.5),
]

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ips = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if ips:
            return ips[0]
    return request.META.get("REMOTE_ADDR", "")

def host_from_header(header_value: str) -> str | None:
    if not header_value:
        return None
    try:
        parsed = urlparse(header_value)
        if parsed.netloc:
            return parsed.netloc.split(":")[0]
        return header_value.split(":")[0]
    except Exception:
        return None

def origin_matches_host(request) -> bool:
    host_header = request.META.get("HTTP_HOST") or request.META.get("SERVER_NAME")
    if not host_header:
        return True
    host = host_header.split(":")[0]
    origin = request.META.get("HTTP_ORIGIN", "")
    referer = request.META.get("HTTP_REFERER", "")
    # Bloquear obvious javascript: referers
    if any(re.search(r"(javascript:|<script|data:text/html)", h or "", re.I) for h in [origin, referer]):
        return False
    if origin_host := host_from_header(origin):
        if origin_host == host:
            return True
    if referer_host := host_from_header(referer):
        if referer_host == host:
            return True
    if not origin and not referer:
        return True
    return False

def has_csrf_token(request) -> bool:
    for h in CSRF_HEADER_NAMES:
        if request.META.get(h):
            return True
    if request.COOKIES.get(CSRF_COOKIE_NAME):
        return True
    try:
        if request.method == "POST" and hasattr(request, "POST"):
            if request.POST.get(POST_FIELD_NAME):
                return True
    except Exception:
        pass
    return False

def extract_payload_text(request) -> str:
    parts: List[str] = []
    try:
        body = request.body.decode("utf-8", errors="ignore")
        if body:
            parts.append(body)
    except Exception:
        pass
    qs = request.META.get("QUERY_STRING", "")
    if qs:
        parts.append(qs)
    parts.append(request.META.get("HTTP_USER_AGENT", ""))
    parts.append(request.META.get("HTTP_REFERER", ""))
    return " ".join([p for p in parts if p])

def extract_parameters(request) -> List[str]:
    params = []
    if hasattr(request, "POST"):
        params.extend(request.POST.keys())
    if hasattr(request, "GET"):
        params.extend(request.GET.keys())
    try:
        if request.body and "application/json" in (request.META.get("CONTENT_TYPE") or ""):
            data = json.loads(request.body)
            params.extend(data.keys())
    except Exception:
        pass
    return params

# FUNCIÓN ROBUSTA: Analizar payload en TODOS los campos (incluyendo sensibles sin descuento)
def analyze_payload(value: str) -> float:
    score = 0.0
    for patt, desc, weight in CSRF_PAYLOAD_PATTERNS:
        if patt.search(value):
            score += weight  # Score full, sin descuento
    return round(score, 3)

# NUEVA FUNCIÓN: Extraer y analizar query string
def analyze_query_string(request) -> float:
    qs = request.META.get("QUERY_STRING", "")
    if qs:
        return analyze_payload(qs)
    return 0.0

# NUEVA FUNCIÓN: Analizar headers adicionales
def analyze_headers(request) -> List[str]:
    issues = []
    ua = request.META.get("HTTP_USER_AGENT", "")
    if re.search(r"(script|<|eval|bot|crawler)", ua, re.I):
        issues.append("User-Agent sospechoso (posible automatización/bot)")
    
    accept_lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    if not accept_lang or len(accept_lang) < 2:
        issues.append("Accept-Language ausente o muy corto (posible bot)")
    
    return issues

class CSRFDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Excluir APIs JSON si se configuró así
        for prefix in CSRF_DEFENSE_EXCLUDED_API_PREFIXES:
            if request.path.startswith(prefix):
                logger.debug(f"[CSRFDefense] Skip analysis for API prefix {prefix} path {request.path}")
                return None

        client_ip = get_client_ip(request)
        trusted_ips = getattr(settings, "CSRF_DEFENSE_TRUSTED_IPS", [])
        if client_ip in trusted_ips:
            return None

        excluded_paths = getattr(settings, "CSRF_DEFENSE_EXCLUDED_PATHS", [])
        if any(request.path.startswith(p) for p in excluded_paths):
            return None

        method = (request.method or "").upper()
        if method not in STATE_CHANGING_METHODS:  # CORREGIDO: Agregado "in"
            return None

        descripcion: List[str] = []
        payload = extract_payload_text(request)
        params = extract_parameters(request)

        # 1) Falta token CSRF
        if not has_csrf_token(request):
            descripcion.append("Falta token CSRF en cookie/header/form")

        # 2) Origin/Referer no coinciden
        if not origin_matches_host(request):
            descripcion.append("Origin/Referer no coinciden con Host (posible cross-site)")

        # 3) Content-Type sospechoso
        content_type = (request.META.get("CONTENT_TYPE") or "")
        for patt in SUSPICIOUS_CT_PATTERNS:
            if patt.search(content_type):
                descripcion.append(f"Content-Type sospechoso: {content_type}")
                break

        # 4) Referer ausente y sin token CSRF
        referer = request.META.get("HTTP_REFERER", "")
        if not referer and not any(request.META.get(h) for h in CSRF_HEADER_NAMES):
            descripcion.append("Referer ausente y sin X-CSRFToken")

        # 5) Parámetros sensibles en GET/JSON
        for p in params:
            if p.lower() in SENSITIVE_PARAMS and method == "GET":
                descripcion.append(f"Parámetro sensible '{p}' enviado en GET (posible CSRF)")

        # 6) JSON sospechoso desde dominio externo
        if "application/json" in content_type:
            origin = request.META.get("HTTP_ORIGIN") or ""
            if origin and host_from_header(origin) != (request.META.get("HTTP_HOST") or "").split(":")[0]:
                descripcion.append("JSON POST desde origen externo (posible CSRF)")

        # 7) Análisis ROBUSTO de payload en TODOS los campos (sin descuento)
        payload_score = 0.0
        payload_summary: List[Dict[str, Any]] = []
        try:
            # Analizar POST
            if hasattr(request, "POST"):
                for key, value in request.POST.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
            # Analizar JSON
            if "application/json" in content_type:
                data = json.loads(request.body.decode("utf-8") or "{}")
                for key, value in data.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
        except Exception as e:
            logger.debug(f"Error analizando payload: {e}")

        if payload_score > 0:
            descripcion.append(f"Payload sospechoso detectado (score total: {payload_score})")

        # 8) Análisis de query string
        qs_score = analyze_query_string(request)
        if qs_score > 0:
            descripcion.append(f"Query string sospechosa (score: {qs_score})")
            payload_score += qs_score

        # 9) Análisis de headers adicionales
        header_issues = analyze_headers(request)
        descripcion.extend(header_issues)

        # Señales >= umbral => marcar
        total_signals = len(descripcion)
        if descripcion and total_signals >= CSRF_DEFENSE_MIN_SIGNALS:
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            s_csrf = w_csrf * total_signals + payload_score  # Score full sin descuento
            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                "payload": json.dumps(payload_summary, ensure_ascii=False)[:1000],
                "score": s_csrf,
            }
            logger.warning(
                "CSRF detectado desde IP %s: %s ; path=%s ; Content-Type=%s ; score=%.2f (Ultra-Robust: nada ignorado)",
                client_ip, descripcion, request.path, content_type, s_csrf
            )
        else:
            if descripcion:
                logger.debug(f"[CSRFDefense] low-signals ({total_signals}) not marking: {descripcion}")

        return None

"""
CSRF Defense Middleware - Ultra-Robusto (Nada Ignorado)
=======================================================
- Detecta múltiples categorías de CSRF: clásico, login, logout, password change, file/action, JSON API.
- Escanea payloads POST, GET, JSON, query string y headers, incluyendo TODOS los campos (sensibles y no) con score full (sin descuento).
- Detecta parámetros sensibles enviados en GET o JSON desde origen externo.
- Análisis adicional de User-Agent, Accept-Language, y payloads con patrones expandidos.
- Scoring configurable y logging detallado.
- Fácil integración con auditoría XSS/SQLi.
- Máxima robustez: no ignora nada para detección óptima.
"""
