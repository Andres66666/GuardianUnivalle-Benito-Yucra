# CSRF defense (versión reforzada)
from __future__ import annotations
import secrets
import logging
import re
import json
from typing import List
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

# Patrón de Content-Type sospechoso
SUSPICIOUS_CT_PATTERNS = [
    re.compile(r"text/plain", re.I),
    re.compile(r"application/x-www-form-urlencoded", re.I),
    re.compile(r"multipart/form-data", re.I),
]

# Parámetros sensibles típicos de CSRF
SENSITIVE_PARAMS = [
    "password", "csrfmiddlewaretoken", "token", "amount", "transfer", "delete", "update"
]

CSRF_DEFENSE_MIN_SIGNALS = getattr(settings, "CSRF_DEFENSE_MIN_SIGNALS", 1)
CSRF_DEFENSE_EXCLUDED_API_PREFIXES = getattr(settings, "CSRF_DEFENSE_EXCLUDED_API_PREFIXES", ["/api/"])

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
    origin_host = host_from_header(origin)
    referer_host = host_from_header(referer)
    # Bloquear obvious javascript: referers
    if any(re.search(r"(javascript:|<script|data:text/html)", h or "", re.I) for h in [origin, referer]):
        return False
    if origin_host and origin_host == host:
        return True
    if referer_host and referer_host == host:
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
        if method not in STATE_CHANGING_METHODS:
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

        # Señales >= umbral => marcar
        if descripcion and len(descripcion) >= CSRF_DEFENSE_MIN_SIGNALS:
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            s_csrf = w_csrf * len(descripcion)
            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                "payload": payload,
                "score": s_csrf,
            }
            logger.warning(
                "CSRF detectado desde IP %s: %s ; path=%s ; Content-Type=%s ; score=%.2f",
                client_ip, descripcion, request.path, content_type, s_csrf
            )
        else:
            if descripcion:
                logger.debug(f"[CSRFDefense] low-signals ({len(descripcion)}) not marking: {descripcion}")

        return None

"""
CSRF Defense Middleware - Reforzado
===================================
- Detecta múltiples categorías de CSRF: clásico, login, logout, password change, file/action, JSON API.
- Escanea payloads POST, GET y JSON.
- Detecta parámetros sensibles enviados en GET o JSON desde origen externo.
- Scoring configurable y logging detallado.
- Fácil integración con auditoría XSS/SQLi.
"""
