from __future__ import annotations
import time
import logging
import json
from typing import Dict, List
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from ..mitigacion.limitador_peticion import limitar_peticion
from ..auditoria.registro_auditoria import registrar_evento

# =====================================================
# ===            CONFIGURACIÓN DEL LOGGER            ===
# =====================================================
logger = logging.getLogger("dosdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =====================================================
# ===       PARÁMETROS DE CONFIGURACIÓN BASE         ===
# =====================================================
LIMITE_PETICIONES = getattr(settings, "DOS_LIMITE_PETICIONES", 100)  # por minuto
VENTANA_SEGUNDOS = getattr(settings, "DOS_VENTANA_SEGUNDOS", 60)
PESO_DOS = getattr(settings, "DOS_PESO", 0.6)

# =====================================================
# ===  REGISTRO TEMPORAL DE SOLICITUDES POR IP      ===
# =====================================================
# En producción se recomienda Redis o Memcached
REGISTRO_SOLICITUDES: Dict[str, List[float]] = {}


# =====================================================
# ===  FUNCIONES AUXILIARES                         ===
# =====================================================
def get_client_ip(request) -> str:
    """Obtiene la IP real del cliente (considera proxies)."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def limpiar_registro(ip: str):
    """Limpia peticiones antiguas fuera de la ventana de tiempo."""
    ahora = time.time()
    REGISTRO_SOLICITUDES[ip] = [
        t for t in REGISTRO_SOLICITUDES.get(ip, []) if ahora - t < VENTANA_SEGUNDOS
    ]


def calcular_nivel_amenaza_dos(
    tasa_peticion: int, limite: int = LIMITE_PETICIONES
) -> float:
    """
    Calcula la puntuación de amenaza DoS basada en el peso configurado.
    Fórmula: S_dos = w_dos * (tasa_peticion / limite)
    """
    proporcion = tasa_peticion / limite
    s_dos = PESO_DOS * proporcion
    return round(min(s_dos, 1.0), 3)


def detectar_dos(ip: str, tasa_peticion: int, limite: int = LIMITE_PETICIONES) -> bool:
    """Evalúa si la tasa de peticiones excede el umbral permitido."""
    if tasa_peticion > limite:
        # Registrar evento en auditoría
        registrar_evento(
            tipo="DoS",
            descripcion=f"Alta tasa de peticiones desde {ip}: {tasa_peticion} req/min (límite {limite})",
            severidad="ALTA",
        )
        # Mitigación: pasar un usuario genérico
        limitar_peticion(usuario_id="anonimo")
        return True
    return False


# =====================================================
# ===      MIDDLEWARE DE DETECCIÓN DE DoS           ===
# =====================================================
class DOSDefenseMiddleware(MiddlewareMixin):
    """
    Middleware para detección y registro de ataques DoS.
    - Captura IP, agente y cabeceras sospechosas.
    - Evalúa la frecuencia de peticiones por IP.
    - Marca request.dos_attack_info con información del intento.
    """

    def process_request(self, request):
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "Desconocido")
        referer = request.META.get("HTTP_REFERER", "")
        path = request.path

        # Limpieza de registro anterior
        limpiar_registro(client_ip)

        # Registrar nueva petición
        REGISTRO_SOLICITUDES.setdefault(client_ip, []).append(time.time())
        tasa = len(REGISTRO_SOLICITUDES[client_ip])
        nivel = calcular_nivel_amenaza_dos(tasa)
        es_dos = detectar_dos(client_ip, tasa)

        if es_dos:
            descripcion = [
                f"Tasa de {tasa} req/min excede límite {LIMITE_PETICIONES}",
                f"User-Agent: {user_agent}",
                f"Referer: {referer or 'N/A'}",
                f"Ruta: {path}",
            ]

            # Log profesional
            logger.warning(
                "DoS detectado desde IP %s: %s ; nivel: %.2f",
                client_ip,
                descripcion,
                nivel,
            )

            # Enviar a sistema de auditoría
            request.dos_attack_info = {
                "ip": client_ip,
                "tipos": ["DoS"],
                "descripcion": descripcion,
                "payload": json.dumps(
                    {"user_agent": user_agent, "referer": referer, "path": path}
                ),
                "score": nivel,
            }

        return None


"""
Detector de ataques de tipo DoS (Denial of Service)
====================================================

Este módulo forma parte del sistema de detección de amenazas.
Detecta tasas de petición anómalas en base a límites configurables,
captura datos del atacante (IP, agente, cabeceras)
y registra los incidentes para su auditoría.

Componentes:
- DOSDefenseMiddleware: Middleware principal de detección.
- detectar_dos(): Evalúa si la tasa supera el umbral permitido.
- calcular_nivel_amenaza_dos(): Calcula la severidad proporcional.
- registrar_evento(): Registra los incidentes en auditoría.

Algoritmos relacionados:
    * Rate Limiting basado en ventana deslizante.
    * Cálculo de score: S_dos = w_dos * (tasa_peticion / limite)
"""


""" 
Algoritmos relacionados:
    *Rate Limiting, listas de bloqueo.
    *Opcional: cifrado de logs con ChaCha20-Poly1305.
Contribución a fórmula de amenaza S:
S_dos = w_dos * (tasa_peticion / limite)
S_dos = 0.6 * (150 / 100)
donde w_dos es peso asignado a DoS y tasa_peticion / limite es la proporción de la tasa actual sobre el límite.
"""
"""
Detector de ataques de tipo DoS (Denial of Service)
====================================================

Este módulo forma parte del sistema de detección de amenazas.
Detecta tasas de petición anómalas en base a límites configurables,
captura datos del atacante (IP, agente, cabeceras)
y registra los incidentes para su auditoría.

Componentes:
- DOSDefenseMiddleware: Middleware principal de detección.
- detectar_dos(): Evalúa si la tasa supera el umbral permitido.
- calcular_nivel_amenaza_dos(): Calcula la severidad proporcional.
- registrar_evento(): Registra los incidentes en auditoría.

Algoritmos relacionados:
    * Rate Limiting basado en ventana deslizante.
    * Cálculo de score: S_dos = w_dos * (tasa_peticion / limite)
"""
