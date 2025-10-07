"""
CSRF Defense Middleware
========================
Detecta y registra posibles ataques CSRF (Cross-Site Request Forgery).

Algoritmos relacionados:
    * Uso de secreto aleatorio criptográfico (generar_token_csrf).
    * Validación simple por comparación (validar_token_csrf).
    * Contribución a fórmula de amenaza S:
        S_csrf = w_csrf * intentos_csrf
        S_csrf = 0.2 * 1
"""

from __future__ import annotations
import secrets
import logging
import re
import json
from typing import List
from urllib.parse import urlparse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# ======================================================
# === CONFIGURACIÓN DE LOGGER ===
# ======================================================
logger = logging.getLogger("csrfdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


# ======================================================
# === FUNCIONES AUXILIARES DE TOKEN CSRF ===
# ======================================================
def registrar_evento(tipo: str, mensaje: str):
    """Registra eventos importantes en los logs."""
    logger.warning(f"[{tipo}] {mensaje}")


def generar_token_csrf() -> str:
    """Genera un token CSRF seguro."""
    token = secrets.token_hex(32)
    registrar_evento("CSRF", "Token CSRF generado")
    return token


def validar_token_csrf(token: str, token_sesion: str) -> bool:
    """Valida que el token recibido coincida con el token en sesión."""
    valido = token == token_sesion
    if not valido:
        registrar_evento("CSRF", "Intento de CSRF detectado (token no coincide)")
    return valido


# ======================================================
# === CONSTANTES Y CONFIGURACIONES ===
# ======================================================
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER_NAMES = (
    "HTTP_X_CSRFTOKEN",
    "HTTP_X_CSRF_TOKEN",
)
CSRF_COOKIE_NAME = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
POST_FIELD_NAME = "csrfmiddlewaretoken"

SUSPICIOUS_CT_PATTERNS = [
    re.compile(r"application/x-www-form-urlencoded", re.I),
    re.compile(r"multipart/form-data", re.I),
]


# ======================================================
# === FUNCIONES DE APOYO ===
# ======================================================
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
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
    """Verifica si Origin/Referer coinciden con Host."""
    host_header = request.META.get("HTTP_HOST") or request.META.get("SERVER_NAME")
    if not host_header:
        return True

    host = host_header.split(":")[0]
    origin = request.META.get("HTTP_ORIGIN", "")
    referer = request.META.get("HTTP_REFERER", "")

    origin_host = host_from_header(origin)
    referer_host = host_from_header(referer)

    if origin_host and origin_host == host:
        return True
    if referer_host and referer_host == host:
        return True
    if not origin and not referer:
        return True

    return False


def has_csrf_token(request) -> bool:
    """Comprueba si hay signos de token CSRF presente."""
    for h in CSRF_HEADER_NAMES:
        if request.META.get(h):
            return True

    cookie_val = request.COOKIES.get(CSRF_COOKIE_NAME)
    if cookie_val:
        return True

    try:
        if request.method == "POST" and hasattr(request, "POST"):
            if request.POST.get(POST_FIELD_NAME):
                return True
    except Exception:
        pass

    return False


def extract_payload_text(request) -> str:
    """Extrae contenido útil de la solicitud para análisis."""
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


# ======================================================
# === MIDDLEWARE DE DEFENSA CSRF ===
# ======================================================
class CSRFDefenseMiddleware(MiddlewareMixin):
    """
    Middleware para DETECTAR intentos de CSRF:
    - Marca request.sql_attack_info con 'tipos': ['CSRF'] y 'descripcion' con razones.
    - No bloquea la petición directamente, permite que AuditoriaMiddleware lo maneje.
    """

    def process_request(self, request):
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

        # 1) Falta token CSRF
        if not has_csrf_token(request):
            descripcion.append("Falta token CSRF en cookie/header/form")

        # 2) Origin/Referer no coinciden
        if not origin_matches_host(request):
            descripcion.append(
                "Origin/Referer no coinciden con Host (posible cross-site)"
            )

        # 3) Content-Type sospechoso
        content_type = request.META.get("CONTENT_TYPE", "") or ""
        for patt in SUSPICIOUS_CT_PATTERNS:
            if patt.search(content_type):
                descripcion.append(f"Content-Type sospechoso: {content_type}")
                break

        # 4) Referer ausente
        referer = request.META.get("HTTP_REFERER", "")
        if not referer and not any(request.META.get(h) for h in CSRF_HEADER_NAMES):
            descripcion.append("Referer ausente y sin X-CSRFToken")

        # Si hay señales, calculamos puntaje y registramos
        if descripcion:
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            intentos_csrf = len(descripcion)
            s_csrf = w_csrf * intentos_csrf

            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                "payload": payload,
                "score": s_csrf,
            }

            logger.warning(
                "CSRF detectado desde IP %s: %s ; payload: %.200s ; score: %.2f",
                client_ip,
                descripcion,
                payload,
                s_csrf,
            )

        return None


""" 
Algoritmos relacionados:
    *Uso de secreto aleatorio criptográfico.
    *Opcionalmente derivación con PBKDF2 / Argon2 para reforzar token.
Contribución a fórmula de amenaza S:
S_csrf = w_csrf * intentos_csrf
S_csrf = 0.2 * 1
donde w_csrf es peso asignado a CSRF y intentos_csrf es la cantidad de intentos detectados.
"""
