# Middleware y utilidades para detección, registro y mitigación de ataques DoS / scraping.
# - Carga listas negras externas (IPs/CIDR) para inteligencia de amenazas.
# - Mantiene registros en memoria por IP (ventana deslizante) y calcula scores.
# - Aplica bloqueos temporales y genera eventos de auditoría.
# - Se integra como middleware Django (DOSDefenseMiddleware).
from __future__ import annotations  # Habilita anotaciones post‑ponibles para tipado.
import time  # Funciones relacionadas con tiempo (timestamps).
import logging  # Registro de eventos.
import json  # Serialización JSON para logs/payloads.
from collections import deque  # Estructura FIFO para ventanas de tiempo.
from typing import Dict, List, Set  # Tipos para anotaciones.
from django.conf import settings  # Acceso a settings de Django.
from django.utils.deprecation import MiddlewareMixin  # Base para middlewares compatibles.
from django.http import HttpResponseForbidden  # Respuesta usada para bloquear peticiones.
import requests  # Usado para obtener listas negras externas (scraping).
import re  # Expresiones regulares (extraer IPs/CIDR).
from ipaddress import ip_address, IPv4Address, IPv4Network  # Operaciones sobre IPs/CIDR.

# =====================================================
# === CONFIGURACIÓN GLOBAL Y LOGGER ===
# =====================================================
logger = logging.getLogger("dosdefense")  # Logger específico para este módulo.
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =====================================================
# === CONFIGURACIÓN DE INTELIGENCIA DE AMENAZAS (THREAT INTEL) ===
# =====================================================
# Fuentes conceptuales públicas para recopilar IPs/CIDR.
IP_BLACKLIST_SOURCES = [
    "https://iplists.firehol.org/files/firehol_level1.netset",  # FireHOL level1
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",  # Feodo Tracker
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1"  # Tor exit nodes 
]

# Cabeceras para simular un navegador en peticiones HTTP a las fuentes.
SCRAPING_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# =====================================================
# === FUNCIONES DE INTELIGENCIA DE AMENAZAS ===
# =====================================================
def fetch_and_parse_blacklists() -> Set[str]:
    """
    descarga y parseo de listas negras externas.
    Devuelve un conjunto de IPs y entradas CIDR como strings.
    """
    global_blacklist: Set[str] = set()
    # Regex que captura IPv4 y opcionalmente el sufijo /NN para CIDR.
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')

    for url in IP_BLACKLIST_SOURCES:
        try:
            # Solicita la fuente externa con timeout.
            response = requests.get(url, headers=SCRAPING_HEADERS, timeout=15)
            response.raise_for_status()
            # Extrae todas las coincidencias de IP/CIDR del texto retornado.
            found_ips = ip_pattern.findall(response.text)
            # Limpieza: eliminar direcciones no válidas obvias.
            cleaned_ips = {ip for ip in found_ips if ip not in ('0.0.0.0', '255.255.255.255')}
            # Actualizar la lista global
            global_blacklist.update(cleaned_ips)
        except requests.exceptions.RequestException as e:
            logger.error(f"[Threat Intel] Error de conexión con {url}: {e}")
        except Exception as e:
            logger.error(f"[Threat Intel] Error inesperado al parsear {url}: {e}")

    # Evitar incluir loopback por error.
    if '127.0.0.1' in global_blacklist:
        global_blacklist.remove('127.0.0.1')

    return global_blacklist

def check_ip_in_advanced_blacklist(client_ip: str, global_blacklist_cidrs: Set[str]) -> bool:
    """
    Comprueba si una IP cliente está en la blacklist, soportando entradas individuales y CIDR.
    - Primero compara entradas exactas.
    - Luego iterar sobre entradas CIDR y comprobar pertenencia.
    """
    if not global_blacklist_cidrs:
        return False

    try:
        ip_a_chequear = IPv4Address(client_ip)  # Validar/convertir la IP cliente.
        # Chequeo rápido: coincidencia exacta en la lista.
        if client_ip in global_blacklist_cidrs:
            return True
        # Chequeo de cada entrada CIDR (si contiene '/').
        for cidr_entry in global_blacklist_cidrs:
            if '/' in cidr_entry:
                try:
                    if ip_a_chequear in IPv4Network(cidr_entry, strict=False):
                        return True
                except ValueError:
                    # Entrada no válida como CIDR -> ignorar y continuar.
                    continue
        return False
    except ValueError:
        # IP inválida / no IPv4.
        logger.error(f"IP del cliente inválida o no IPv4: {client_ip}")
        return False

# =====================================================
# === PARÁMETROS DE CONFIGURACIÓN BASE Y SCORE ===
# =====================================================
# Parámetros configurables vía settings de Django (con valores por defecto).
LIMITE_PETICIONES = getattr(settings, "DOS_LIMITE_PETICIONES", 100)  # Req por ventana antes de considerar DoS.
VENTANA_SEGUNDOS = getattr(settings, "DOS_VENTANA_SEGUNDOS", 60)  # Duración de la ventana en segundos.
PESO_DOS = getattr(settings, "DOS_PESO", 0.6)  # Peso del componente tasa en el score.
LIMITE_ENDPOINTS_DISTINTOS = getattr(settings, "DOS_LIMITE_ENDPOINTS", 50)  # Umbral de endpoints distintos.
TRUSTED_IPS = getattr(settings, "DOS_TRUSTED_IPS", [])  # IPs exentas.
TIEMPO_BLOQUEO_SEGUNDOS = getattr(settings, "DOS_TIEMPO_BLOQUEO", 300)  # Duración del bloqueo temporal.

# Parámetros para score avanzado (blacklist + heurística)
PESO_BLACKLIST = getattr(settings, "DOS_PESO_BLACKLIST", 0.3)
PESO_HEURISTICA = getattr(settings, "DOS_PESO_HEURISTICA", 0.1)
UMBRAL_BLOQUEO = getattr(settings, "DOS_UMBRAL_BLOQUEO", 0.8)  # Umbral absoluto para bloquear.

# === CARGA INICIAL DE LA LISTA NEGRA ===
try:
    IP_BLACKLIST: Set[str] = fetch_and_parse_blacklists()
    output_filename = "blacklist_cargada.txt"
    # Persistir snapshot local para inspección/debug.
    with open(output_filename, 'w') as f:
        for ip in sorted(list(IP_BLACKLIST)):
            f.write(f"{ip}\n")
    logger.info(f"Lista Negra Externa cargada y guardada con {len(IP_BLACKLIST)} IPs/CIDR.")
except Exception as e:
    logger.error(f"Error al cargar la IP Blacklist: {e}. Usando lista vacía.")
    IP_BLACKLIST = set()

# =====================================================
# === REGISTRO TEMPORAL EN MEMORIA ===
# =====================================================
# Estructuras en memoria para llevar contadores/ventanas por IP.
REGISTRO_SOLICITUDES: Dict[str, deque] = {}  # mapa IP -> deque(timestamps)
REGISTRO_ENDPOINTS: Dict[str, set] = {}  # mapa IP -> set(paths accedidos)
BLOQUEOS_TEMPORALES: Dict[str, float] = {}  # mapa IP -> timestamp_de_desbloqueo

# =====================================================
# === FUNCIONES AUXILIARES ===
# =====================================================
def get_client_ip(request) -> str:
    """Extrae la IP cliente, respetando X-Forwarded-For si está presente."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # Tomar la primera IP de la lista (cliente original).
        return x_forwarded_for.split(",")[0].strip()
    # Fallback a REMOTE_ADDR o "0.0.0.0" si no existe.
    return request.META.get("REMOTE_ADDR", "") or "0.0.0.0"

def limpiar_registro_global():
    """
    Limpia entradas inactivas del registro global y desbloquea ips cuyo tiempo expiró.
    - Remueve IPs con última actividad mayor que 'expiracion'.
    - Remueve bloqueos temporales expirados.
    """
    ahora = time.time()
    expiracion = VENTANA_SEGUNDOS * 2  # Considerar inactivo si sin actividad por 2*ventana.
    inactivas = []

    # Buscar IPs inactivas
    for ip, tiempos in REGISTRO_SOLICITUDES.items():
        if tiempos and ahora - tiempos[-1] > expiracion:
            inactivas.append(ip)

    # Eliminar IPs inactivas del registro
    for ip in inactivas:
        REGISTRO_SOLICITUDES.pop(ip, None)
        REGISTRO_ENDPOINTS.pop(ip, None)

    # Desbloquear IPs cuyo tiempo de bloqueo expiró
    ips_a_desbloquear = [ip for ip, tiempo_desbloqueo in BLOQUEOS_TEMPORALES.items() if ahora > tiempo_desbloqueo]
    for ip in ips_a_desbloquear:
        BLOQUEOS_TEMPORALES.pop(ip, None)
        logger.info(f"[Desbloqueo] IP {ip} desbloqueada automáticamente.")

def limpiar_registro(ip: str):
    """Eliminar timestamps antiguos fuera de la ventana deslizante para la IP dada."""
    ahora = time.time()
    if ip not in REGISTRO_SOLICITUDES:
        REGISTRO_SOLICITUDES[ip] = deque()
    tiempos = REGISTRO_SOLICITUDES[ip]
    # Pop left mientras el timestamp más antiguo esté fuera de la ventana.
    while tiempos and ahora - tiempos[0] > VENTANA_SEGUNDOS:
        tiempos.popleft()

def calcular_nivel_amenaza_dos(tasa_peticion: int, limite: int = LIMITE_PETICIONES) -> float:
    """
    Calcula componente de score basado en tasa de peticiones.
    - Normaliza respecto al límite y aplica peso PESO_DOS.
    - Clampa el resultado entre 0.0 y 1.0 y lo redondea a 3 decimales.
    """
    proporcion = tasa_peticion / max(limite, 1)
    s_dos = PESO_DOS * min(proporcion, 2.0)
    return round(min(s_dos, 1.0), 3)

# =====================================================
# === FUNCIONES INTERNAS DE SEGURIDAD Y AUDITORÍA ===
# =====================================================
def limitar_peticion(usuario_id: str):
    """Aplica bloqueo temporal a una IP y registra evento en logs."""
    ahora = time.time()
    tiempo_desbloqueo = ahora + TIEMPO_BLOQUEO_SEGUNDOS
    BLOQUEOS_TEMPORALES[usuario_id] = tiempo_desbloqueo
    logger.warning(f"[Bloqueo Activo] IP {usuario_id} bloqueada temporalmente hasta {time.ctime(tiempo_desbloqueo)}")

def registrar_evento(tipo: str, descripcion: str, severidad: str = "MEDIA"):
    """Registra un evento de auditoría (simulado) en logs en formato JSON."""
    evento = {
        "tipo": tipo,
        "descripcion": descripcion,
        "severidad": severidad,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    logger.info(f"[AUDITORÍA] {json.dumps(evento, ensure_ascii=False)}")

def detectar_dos(ip: str, tasa_peticion: int, limite: int = LIMITE_PETICIONES) -> bool:
    """
    Evaluación simple de DoS por tasa:
    - Si supera el límite -> registrar evento ALTA y bloquear.
    - Si supera 75% del límite -> registrar advertencia MEDIA.
    """
    if tasa_peticion > limite:
        registrar_evento(tipo="DoS", descripcion=f"Alta tasa de peticiones desde {ip}: {tasa_peticion} req/min (límite {limite})", severidad="ALTA")
        limitar_peticion(usuario_id=ip)
        return True
    elif tasa_peticion > limite * 0.75:
        registrar_evento(tipo="DoS", descripcion=f"Posible saturación desde {ip}: {tasa_peticion} req/min", severidad="MEDIA")
    return False

def analizar_headers_avanzado(user_agent: str, referer: str) -> List[str]:
    """
    Heurística para detectar user-agents automatizados o referers sospechosos.
    Devuelve lista de issues detectados (vacía si no hay).
    """
    sospechas = []
    # User-Agent vacio o muy corto o el user-agent por defecto de requests -> sospechoso.
    if not user_agent or len(user_agent) < 10 or user_agent.lower() == "python-requests/2.25.1":
        sospechas.append("User-Agent vacío/Defecto")

    # Palabras clave usadas por herramientas de automatización.
    automation_keywords = ["curl", "python", "wget", "bot", "spider", "scraper", "headless", "phantom"]
    if any(patron in user_agent.lower() for patron in automation_keywords):
        sospechas.append("Herramienta de automatización detectada")

    # Referer que explícitamente sugiere escaneo/ataque.
    if referer and any(palabra in referer.lower() for palabra in ["attack", "scan"]):
        sospechas.append("Referer indicando abuso")

    return sospechas

# =====================================================
# === MIDDLEWARE PRINCIPAL DE DEFENSA DoS ===
# =====================================================
class DOSDefenseMiddleware(MiddlewareMixin):
    """
    Middleware encargado de:
    - Mantener ventana deslizante por IP.
    - Calcular score compuesto (tasa + blacklist + heurística).
    - Aplicar bloqueos temporales y registrar eventos de auditoría.
    """

    def process_request(self, request):
        # Limpieza periódica de estructuras en memoria.
        limpiar_registro_global()

        client_ip = get_client_ip(request)  # Obtener IP del cliente.

        # 1. BLOQUEOS Y EXCEPCIONES PREVIAS
        # Si la IP está en la lista de confianza, no procesar.
        if client_ip in TRUSTED_IPS:
            return None

        # Si la IP está bloqueada temporalmente, registrar y devolver 403.
        if client_ip in BLOQUEOS_TEMPORALES and time.time() < BLOQUEOS_TEMPORALES[client_ip]:
            registrar_evento(tipo="Temporary Block", descripcion=f"Bloqueo temporal por abuso previo: IP {client_ip}.", severidad="ALTA")
            return HttpResponseForbidden("Acceso denegado temporalmente por comportamiento sospechoso.")

        # Evitar duplicar análisis DoS si XSS/CSRF ya marcaron la request.
        if (hasattr(request, 'xss_attack_info') or hasattr(request, 'xss_block') or hasattr(request, 'xss_challenge') or
            hasattr(request, 'csrf_attack_info') or hasattr(request, 'csrf_block') or hasattr(request, 'csrf_challenge')):
            logger.info(f"[DOSDefense] Solicitud desde IP {client_ip} ya detectada por XSS o CSRF. Saltando análisis DoS para evitar superposición.")
            return None

        # 2. ANÁLISIS DE LA PETICIÓN Y CÁLCULO DE MÉTRICAS BASE
        user_agent = request.META.get("HTTP_USER_AGENT", "Desconocido")
        referer = request.META.get("HTTP_REFERER", "")
        path = request.path

        # Actualizar conjunto de endpoints accedidos por la IP y la ventana temporal.
        REGISTRO_ENDPOINTS.setdefault(client_ip, set()).add(path)
        limpiar_registro(client_ip)
        REGISTRO_SOLICITUDES[client_ip].append(time.time())

        tasa = len(REGISTRO_SOLICITUDES[client_ip])  # Conteo de requests en la ventana actual.

        # 3. CÁLCULO DE LOS COMPONENTES DEL SCORE DE AMENAZA
        nivel_dos = calcular_nivel_amenaza_dos(tasa)  # Componente por tasa.
        nivel_blacklist = PESO_BLACKLIST if check_ip_in_advanced_blacklist(client_ip, IP_BLACKLIST) else 0  # Componente blacklist.
        sospechas_headers = analizar_headers_avanzado(user_agent, referer)  # Heurística headers.

        # Puntuaciones simplificadas para headers y endpoints.
        score_headers = 0.5 if sospechas_headers else 0
        score_endpoints = 0.5 if len(REGISTRO_ENDPOINTS[client_ip]) > LIMITE_ENDPOINTS_DISTINTOS else 0
        nivel_heuristica = PESO_HEURISTICA * (score_headers + score_endpoints)

        # 4. CÁLCULO DEL SCORE TOTAL Y DECISIÓN DE MITIGACIÓN
        S_total = nivel_dos + nivel_blacklist + nivel_heuristica

        # Si el score total supera el umbral, bloquear y registrar evento crítico.
        if S_total >= UMBRAL_BLOQUEO:
            descripcion_log = [
                f"Score Total: {S_total:.3f} > Umbral {UMBRAL_BLOQUEO}",
                f"DoS: {nivel_dos:.3f}, Blacklist: {nivel_blacklist:.3f}, Heurística: {nivel_heuristica:.3f}"
            ]
            registrar_evento(tipo="Bloqueo por Score Total", descripcion=" ; ".join(descripcion_log), severidad="CRÍTICA")
            limitar_peticion(usuario_id=client_ip)
            return HttpResponseForbidden("Acceso denegado por alto Score de Amenaza.")

        # 5. REGISTRO DE ADVERTENCIA (Si no se bloquea, pero hay sospecha)
        if S_total > UMBRAL_BLOQUEO * 0.75 or (nivel_dos > 0) or len(sospechas_headers) > 0:
            descripcion = sospechas_headers.copy()
            if score_endpoints > 0:
                descripcion.append("Número anormal de endpoints distintos accedidos (posible escaneo/scraping)")

            descripcion.insert(0, f"Score Total: {S_total:.3f} (Tasa: {tasa} req/min)")
            descripcion.append(f"Ruta: {path}")

            logger.warning("Tráfico Sospechoso desde IP %s: %s", client_ip, " ; ".join(descripcion))
            # Anexar info al request para que otros middlewares / views puedan actuar.
            request.dos_attack_info = {
                "ip": client_ip,
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": descripcion,
                "payload": json.dumps({"user_agent": user_agent, "referer": referer, "path": path}),
                "score": S_total,
            }
        # No interrumpir el flujo normal si no se bloquea.
        return None
