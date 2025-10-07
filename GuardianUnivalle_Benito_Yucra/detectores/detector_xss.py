# xss_defense.py
from __future__ import annotations
import json
import logging
import re
from typing import List, Tuple
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# =====================================================
# ===               CONFIGURACIÓN LOGGER             ===
# =====================================================
logger = logging.getLogger("xssdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =====================================================
# ===              INTENTAR CARGAR BLEACH            ===
# =====================================================
try:
    import bleach

    _BLEACH_AVAILABLE = True
except Exception:
    _BLEACH_AVAILABLE = False

# =====================================================
# ===           PATRONES DE DETECCIÓN XSS            ===
# =====================================================
XSS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"<\s*script\b", re.I), "Etiqueta <script>"),
    (re.compile(r"on\w+\s*=", re.I), "Atributo de evento (on*)"),
    (re.compile(r"javascript:\s*", re.I), "URI javascript:"),
    (re.compile(r"<\s*iframe\b", re.I), "Etiqueta <iframe>"),
    (re.compile(r"<\s*embed\b", re.I), "Etiqueta <embed>"),
    (re.compile(r"<\s*object\b", re.I), "Etiqueta <object>"),
    (re.compile(r"document\.cookie", re.I), "Acceso a document.cookie"),
    (re.compile(r"alert\s*\(", re.I), "Uso de alert() potencial"),
]


# =====================================================
# ===         FUNCIONES AUXILIARES XSS              ===
# =====================================================
def detect_xss_text(text: str) -> Tuple[bool, List[str]]:
    """
    Busca patrones de XSS conocidos dentro de un texto.
    Devuelve (True, lista_de_coincidencias) si hay indicios.
    """
    matches: List[str] = []
    if not text:
        return False, matches

    for patt, message in XSS_PATTERNS:
        if patt.search(text):
            matches.append(message)

    return len(matches) > 0, matches


def sanitize_input_basic(text: str) -> str:
    """
    Sanitiza una cadena eliminando etiquetas o caracteres peligrosos.
    Usa bleach si está disponible, de lo contrario hace escape manual.
    """
    if text is None:
        return text

    if _BLEACH_AVAILABLE:
        return bleach.clean(text, tags=[], attributes={}, protocols=[], strip=True)

    replacements = [
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ('"', "&quot;"),
        ("'", "&#x27;"),
        ("/", "&#x2F;"),
    ]
    result = text
    for old, new in replacements:
        result = result.replace(old, new)
    return result


def extract_payload_text(request) -> str:
    """
    Extrae un texto combinado con información del cuerpo, querystring,
    agente de usuario y referer para análisis XSS.
    """
    parts: List[str] = []

    try:
        content_type = request.META.get("CONTENT_TYPE", "")

        if "application/json" in content_type:
            body_data = json.loads(request.body.decode("utf-8") or "{}")
            parts.append(json.dumps(body_data, ensure_ascii=False))
        else:
            body_text = request.body.decode("utf-8", errors="ignore")
            if body_text:
                parts.append(body_text)
    except Exception:
        pass

    qs = request.META.get("QUERY_STRING", "")
    if qs:
        parts.append(qs)

    parts.append(request.META.get("HTTP_USER_AGENT", ""))
    parts.append(request.META.get("HTTP_REFERER", ""))

    return " ".join([p for p in parts if p])


# =====================================================
# ===            MIDDLEWARE DE DEFENSA XSS           ===
# =====================================================
class XSSDefenseMiddleware(MiddlewareMixin):
    """
    Middleware profesional de detección XSS.
    - Detecta patrones maliciosos en solicitudes sospechosas.
    - No bloquea directamente, solo marca el ataque para auditoría.
    - Se integra con AuditoriaMiddleware (request.sql_attack_info).
    """

    def process_request(self, request):
        # ---------------------------------------------
        # 1. Filtrar IPs de confianza
        # ---------------------------------------------
        trusted_ips: List[str] = getattr(settings, "XSS_DEFENSE_TRUSTED_IPS", [])
        client_ip = request.META.get("REMOTE_ADDR", "")
        if client_ip in trusted_ips:
            return None

        # ---------------------------------------------
        # 2. Excluir rutas seguras
        # ---------------------------------------------
        excluded_paths: List[str] = getattr(settings, "XSS_DEFENSE_EXCLUDED_PATHS", [])
        if any(request.path.startswith(p) for p in excluded_paths):
            return None

        # ---------------------------------------------
        # 3. Extraer y analizar payload
        # ---------------------------------------------
        payload = extract_payload_text(request)
        if not payload:
            return None

        flagged, matches = detect_xss_text(payload)
        if not flagged:
            return None

        # ---------------------------------------------
        # 4. Calcular puntaje de amenaza S_xss
        # ---------------------------------------------
        w_xss = getattr(settings, "XSS_DEFENSE_WEIGHT", 0.3)
        detecciones_xss = len(matches)
        s_xss = w_xss * detecciones_xss

        # ---------------------------------------------
        # 5. Loggear y marcar en el request
        # ---------------------------------------------
        logger.warning(
            "XSS detectado desde IP %s: %s ; payload: %.200s ; score: %.2f",
            client_ip,
            matches,
            payload,
            s_xss,
        )

        request.xss_attack_info = {
            "ip": client_ip,
            "tipos": ["XSS"],
            "descripcion": matches,
            "payload": payload,
            "score": s_xss,
        }

        return None


# =====================================================
# ===              INFORMACIÓN EXTRA                ===
# =====================================================
"""
Algoritmos relacionados:
    - Se recomienda almacenar los payloads XSS cifrados con AES-GCM
      para confidencialidad e integridad.

Contribución a fórmula de amenaza S:
    S_xss = w_xss * detecciones_xss
    Ejemplo: S_xss = 0.3 * 2 = 0.6
"""
