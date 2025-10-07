# sql_defense.py
from __future__ import annotations
import json
import logging
import re
from typing import List, Tuple
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# =====================================================
# ===             CONFIGURACIÓN DEL LOGGER           ===
# =====================================================
logger = logging.getLogger("sqlidefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


# =====================================================
# ===        PATRONES DE DETECCIÓN DE SQLi           ===
# =====================================================
SQLI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Inyección clásica con UNION SELECT
    (re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.I), "Uso de UNION SELECT"),
    # Combinaciones OR/AND en consultas WHERE
    (
        re.compile(r"\bselect\b.*\bfrom\b.*\bwhere\b.*\b(or|and)\b.*=", re.I),
        "SELECT con OR/AND",
    ),
    # Comparaciones tautológicas (1=1)
    (
        re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.I),
        "Expresión tautológica OR/AND 1=1",
    ),
    # Manipulación de tablas
    (
        re.compile(r"\b(drop|truncate|delete|insert|update)\b", re.I),
        "Comando de manipulación de tabla",
    ),
    # Comentarios sospechosos o terminadores
    (re.compile(r"(--|#|;)", re.I), "Comentario o terminador sospechoso"),
    # Ejecución directa de procedimientos
    (re.compile(r"exec\s*\(", re.I), "Ejecución de procedimiento almacenado"),
    # Subconsultas y SELECT anidados sospechosos
    (re.compile(r"\(\s*select\b.*\)", re.I), "Subconsulta sospechosa"),
]


# =====================================================
# ===          FUNCIONES AUXILIARES SQLi             ===
# =====================================================
def extract_payload_text(request) -> str:
    """
    Extrae texto de interés desde el cuerpo, querystring,
    encabezados y referencias para analizar posible SQLi.
    """
    parts: List[str] = []

    try:
        content_type = request.META.get("CONTENT_TYPE", "")
        if "application/json" in content_type:
            data = json.loads(request.body.decode("utf-8") or "{}")
            parts.append(json.dumps(data))
        else:
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


def detect_sql_attack(text: str) -> Tuple[bool, List[str]]:
    """
    Recorre el texto buscando patrones típicos de inyección SQL.
    Retorna (True, lista_de_descripciones) si se detecta algún patrón.
    """
    descripcion: List[str] = []

    for patt, msg in SQLI_PATTERNS:
        if patt.search(text):
            descripcion.append(msg)

    return (len(descripcion) > 0, descripcion)


def get_client_ip(request) -> str:
    """
    Obtiene la IP real del cliente considerando X-Forwarded-For.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


# =====================================================
# ===          MIDDLEWARE DE DEFENSA SQLi            ===
# =====================================================
class SQLIDefenseMiddleware(MiddlewareMixin):
    """
    Middleware profesional de detección de inyección SQL.
    - Detecta patrones en parámetros, cuerpo y cabeceras.
    - No bloquea directamente; marca el intento para auditoría.
    """

    def process_request(self, request):
        # ---------------------------------------------
        # 1. Filtrar IPs confiables
        # ---------------------------------------------
        client_ip = get_client_ip(request)
        trusted_ips: List[str] = getattr(settings, "SQLI_DEFENSE_TRUSTED_IPS", [])
        if client_ip in trusted_ips:
            return None

        # ---------------------------------------------
        # 2. Extraer payload de la solicitud
        # ---------------------------------------------
        payload = extract_payload_text(request)
        if not payload:
            return None

        # ---------------------------------------------
        # 3. Analizar contenido en busca de patrones SQLi
        # ---------------------------------------------
        flagged, descripcion = detect_sql_attack(payload)
        if not flagged:
            return None

        # ---------------------------------------------
        # 4. Calcular puntaje de amenaza S_sqli
        # ---------------------------------------------
        w_sqli = getattr(settings, "SQLI_DEFENSE_WEIGHT", 0.4)
        detecciones_sqli = len(descripcion)
        s_sqli = w_sqli * detecciones_sqli

        # ---------------------------------------------
        # 5. Registrar e informar el intento
        # ---------------------------------------------
        logger.warning(
            "Inyección SQL detectada desde IP %s: %s ; payload: %.200s ; score: %.2f",
            client_ip,
            descripcion,
            payload,
            s_sqli,
        )

        # Marcar información del ataque para el sistema de auditoría
        request.sql_attack_info = {
            "ip": client_ip,
            "tipos": ["SQLi"],
            "descripcion": descripcion,
            "payload": payload,
            "score": s_sqli,
        }

        return None


# =====================================================
# ===              INFORMACIÓN EXTRA                ===
# =====================================================
"""
Algoritmos relacionados:
    - Se recomienda almacenar logs SQLi cifrados (AES-GCM) 
      para proteger evidencia de intentos maliciosos.

Cálculo de puntaje de amenaza:
    S_sqli = w_sqli * detecciones_sqli
    Ejemplo: S_sqli = 0.4 * 3 = 1.2

Integración:
    Este middleware puede combinarse con:
        - CSRFDefenseMiddleware
        - XSSDefenseMiddleware
    para calcular un score total de amenaza y decidir bloqueo.
"""
