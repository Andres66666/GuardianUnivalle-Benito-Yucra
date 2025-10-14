from __future__ import annotations
import time
import logging
import json
from collections import deque
from typing import Dict, List, Set
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden 
import requests # ⬅️ Necesario para la función de scraping
import re      # ⬅️ Necesario para el parseo de IPs/CIDR
from ipaddress import ip_address, IPv4Address, IPv4Network # Necesario para el Escaneo Avanzado (CIDR)

# =====================================================
# === CONFIGURACIÓN GLOBAL Y LOGGER ===
# =====================================================
logger = logging.getLogger("dosdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =====================================================
# === CONFIGURACIÓN DE INTELIGENCIA DE AMENAZAS (THREAT INTEL) ===
# =====================================================
# URLs CONCEPTUALES de donde EXTRAERÍAS IPs/CIDR
IP_BLACKLIST_SOURCES = [
    # 1. FireHOL (Agregador General de Nivel 1)
    # Resultado: Éxito al obtener 4438 IPs/CIDR
    "https://iplists.firehol.org/files/firehol_level1.netset",

    # 2. Abuse.ch Feodo Tracker (Botnets C&C)
    # Resultado: Éxito al obtener 2 IPs/CIDR (puede ser bajo, pero es funcional)
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",

    # 3. Tor Project (Nodos de Salida)
    # Resultado: Éxito al obtener 1166 IPs/CIDR
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1" 
]

# Cabeceras para simular un navegador
SCRAPING_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# =====================================================
# === FUNCIONES DE INTELIGENCIA DE AMENAZAS ===
# =====================================================

def fetch_and_parse_blacklists() -> Set[str]:
    """
    Intenta obtener y parsear IPs/CIDR de varias fuentes externas.
    """
    global_blacklist: Set[str] = set()
    # Patrón Regex para IPs (admite también rangos CIDR)

    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b') 

    for url in IP_BLACKLIST_SOURCES:
        try:
            response = requests.get(url, headers=SCRAPING_HEADERS, timeout=15)
            response.raise_for_status()
            
            found_ips = ip_pattern.findall(response.text)
            
            # Limpieza
            #cleaned_ips = {ip[0] for ip in found_ips if ip[0] not in ('0.0.0.0', '255.255.255.255')}
            cleaned_ips = {ip for ip in found_ips if ip not in ('0.0.0.0', '255.255.255.255')}
            
            
            global_blacklist.update(cleaned_ips)
            logger.info(f"[Threat Intel] Éxito al obtener {len(cleaned_ips)} IPs/CIDR de {url}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[Threat Intel] Error de conexión con {url}: {e}")
        except Exception as e:
            logger.error(f"[Threat Intel] Error inesperado al parsear {url}: {e}")

    if '127.0.0.1' in global_blacklist:
        global_blacklist.remove('127.0.0.1')
        
    return global_blacklist

def check_ip_in_advanced_blacklist(client_ip: str, global_blacklist_cidrs: Set[str]) -> bool:
    """
    Escaneo avanzado: Chequea si una IP está en la lista negra, incluyendo rangos CIDR.
    """
    if not global_blacklist_cidrs:
        return False
        
    try:
        ip_a_chequear = IPv4Address(client_ip)
        
        # 1. Chequeo rápido de IPs individuales
        if client_ip in global_blacklist_cidrs:
             return True
             
        # 2. Chequeo de rangos CIDR (más lento)
        for cidr_entry in global_blacklist_cidrs:
            if '/' in cidr_entry:
                try:
                    if ip_a_chequear in IPv4Network(cidr_entry, strict=False):
                        return True
                except ValueError:
                    continue # No es una red CIDR válida, continuar
        return False
        
    except ValueError:
        logger.error(f"IP del cliente inválida o no IPv4: {client_ip}")
        return False

# =====================================================
# === PARÁMETROS DE CONFIGURACIÓN BASE Y SCORE ===
# =====================================================
LIMITE_PETICIONES = getattr(settings, "DOS_LIMITE_PETICIONES", 100)
VENTANA_SEGUNDOS = getattr(settings, "DOS_VENTANA_SEGUNDOS", 60)
PESO_DOS = getattr(settings, "DOS_PESO", 0.6)
LIMITE_ENDPOINTS_DISTINTOS = getattr(settings, "DOS_LIMITE_ENDPOINTS", 50)
TRUSTED_IPS = getattr(settings, "DOS_TRUSTED_IPS", [])
TIEMPO_BLOQUEO_SEGUNDOS = getattr(settings, "DOS_TIEMPO_BLOQUEO", 300) 

# Parámetros del Score Avanzado
PESO_BLACKLIST = getattr(settings, "DOS_PESO_BLACKLIST", 0.3)
PESO_HEURISTICA = getattr(settings, "DOS_PESO_HEURISTICA", 0.1)
UMBRAL_BLOQUEO = getattr(settings, "DOS_UMBRAL_BLOQUEO", 0.8)

# === CARGA INICIAL DE LA LISTA NEGRA ===
try:
    IP_BLACKLIST: Set[str] = fetch_and_parse_blacklists() 
    output_filename = "blacklist_cargada.txt"
    with open(output_filename, 'w') as f:
        # Escribe cada IP/CIDR en una nueva línea
        for ip in sorted(list(IP_BLACKLIST)): # Usamos sorted() para orden alfabético/numérico
            f.write(f"{ip}\n")
    logger.info(f"Lista Negra Externa GUARDADA en {output_filename} para inspección.")
    logger.info(f"Lista Negra Externa cargada con {len(IP_BLACKLIST)} IPs/CIDR.")
except Exception as e:
    logger.error(f"Error al cargar la IP Blacklist: {e}. Usando lista vacía.")
    IP_BLACKLIST = set()

# =====================================================
# === REGISTRO TEMPORAL EN MEMORIA ===
# =====================================================
REGISTRO_SOLICITUDES: Dict[str, deque] = {}
REGISTRO_ENDPOINTS: Dict[str, set] = {}
BLOQUEOS_TEMPORALES: Dict[str, float] = {} 

# =====================================================
# === FUNCIONES AUXILIARES ===
# =====================================================
def get_client_ip(request) -> str:
    """Obtiene la IP real del cliente (considera proxies)."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "0.0.0.0"

def limpiar_registro_global():
    """Elimina IPs sin actividad reciente y desbloquea IPs temporales."""
    # ... (La implementación de limpiar_registro_global permanece igual)
    ahora = time.time()
    expiracion = VENTANA_SEGUNDOS * 2
    inactivas = []
    
    for ip, tiempos in REGISTRO_SOLICITUDES.items():
        if tiempos and ahora - tiempos[-1] > expiracion:
            inactivas.append(ip)

    for ip in inactivas:
        REGISTRO_SOLICITUDES.pop(ip, None)
        REGISTRO_ENDPOINTS.pop(ip, None)
    
    ips_a_desbloquear = [ip for ip, tiempo_desbloqueo in BLOQUEOS_TEMPORALES.items() if ahora > tiempo_desbloqueo]
    for ip in ips_a_desbloquear:
        BLOQUEOS_TEMPORALES.pop(ip, None)
        logger.info(f"[Desbloqueo] IP {ip} desbloqueada automáticamente.")

def limpiar_registro(ip: str):
    """Limpia peticiones antiguas fuera de la ventana de tiempo."""
    # ... (La implementación de limpiar_registro permanece igual)
    ahora = time.time()
    if ip not in REGISTRO_SOLICITUDES:
        REGISTRO_SOLICITUDES[ip] = deque()
    tiempos = REGISTRO_SOLICITUDES[ip]
    while tiempos and ahora - tiempos[0] > VENTANA_SEGUNDOS:
        tiempos.popleft()

def calcular_nivel_amenaza_dos(tasa_peticion: int, limite: int = LIMITE_PETICIONES) -> float:
    """Calcula la puntuación de amenaza DoS (Rate Limiting)."""
    # ... (La implementación de calcular_nivel_amenaza_dos permanece igual)
    proporcion = tasa_peticion / max(limite, 1)
    s_dos = PESO_DOS * min(proporcion, 2.0)
    return round(min(s_dos, 1.0), 3)


# =====================================================
# === FUNCIONES INTERNAS DE SEGURIDAD Y AUDITORÍA ===
# =====================================================
def limitar_peticion(usuario_id: str):
    """Implementa la mitigación: Bloquea temporalmente la IP."""
    ahora = time.time()
    tiempo_desbloqueo = ahora + TIEMPO_BLOQUEO_SEGUNDOS
    BLOQUEOS_TEMPORALES[usuario_id] = tiempo_desbloqueo
    logger.warning(
        f"[Bloqueo Activo] IP {usuario_id} bloqueada temporalmente hasta {time.ctime(tiempo_desbloqueo)}"
    )

def registrar_evento(tipo: str, descripcion: str, severidad: str = "MEDIA"):
    """Simula el registro de auditoría de un evento de seguridad."""
    evento = {
        "tipo": tipo,
        "descripcion": descripcion,
        "severidad": severidad,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    logger.info(f"[AUDITORÍA] {json.dumps(evento, ensure_ascii=False)}")

def detectar_dos(ip: str, tasa_peticion: int, limite: int = LIMITE_PETICIONES) -> bool:
    """Evalúa si la tasa de peticiones excede el umbral permitido y aplica mitigación."""
    # ... (La implementación de detectar_dos permanece igual)
    if tasa_peticion > limite:
        registrar_evento(
            tipo="DoS",
            descripcion=f"Alta tasa de peticiones desde {ip}: {tasa_peticion} req/min (límite {limite})",
            severidad="ALTA",
        )
        limitar_peticion(usuario_id=ip) 
        return True
    elif tasa_peticion > limite * 0.75:
        registrar_evento(
            tipo="DoS",
            descripcion=f"Posible saturación desde {ip}: {tasa_peticion} req/min",
            severidad="MEDIA",
        )
    return False

def analizar_headers_avanzado(user_agent: str, referer: str) -> List[str]:
    """Detecta patrones sospechosos, penalizando User-Agents automatizados."""
    # ... (La implementación de analizar_headers_avanzado permanece igual)
    sospechas = []
    
    if not user_agent or len(user_agent) < 10 or user_agent.lower() == "python-requests/2.25.1": 
        sospechas.append("User-Agent vacío/Defecto")
        
    automation_keywords = ["curl", "python", "wget", "bot", "spider", "scraper", "headless", "phantom"]
    if any(patron in user_agent.lower() for patron in automation_keywords):
        sospechas.append("Herramienta de automatización detectada")
        
    if referer and any(palabra in referer.lower() for palabra in ["attack", "scan"]):
        sospechas.append("Referer indicando abuso")
        
    return sospechas


# =====================================================
# === MIDDLEWARE PRINCIPAL DE DEFENSA DoS ===
# =====================================================
class DOSDefenseMiddleware(MiddlewareMixin):
    """
    Middleware de detección, registro y mitigación de ataques DoS/Scraping avanzado.
    """

    def process_request(self, request):
        limpiar_registro_global()

        client_ip = get_client_ip(request)
        
        # 1. BLOQUEOS Y EXCEPCIONES PREVIAS
        if client_ip in TRUSTED_IPS:
            return None
            
        # BLOQUEO TEMPORAL: IPs previamente bloqueadas por alto Score o DoS
        if client_ip in BLOQUEOS_TEMPORALES and time.time() < BLOQUEOS_TEMPORALES[client_ip]:
            registrar_evento(
                tipo="Temporary Block",
                descripcion=f"Bloqueo temporal por abuso previo: IP {client_ip}.",
                severidad="ALTA",
            )
            return HttpResponseForbidden("Acceso denegado temporalmente por comportamiento sospechoso.")

        # 2. ANÁLISIS DE LA PETICIÓN Y CÁLCULO DE MÉTRICAS BASE
        user_agent = request.META.get("HTTP_USER_AGENT", "Desconocido")
        referer = request.META.get("HTTP_REFERER", "")
        path = request.path

        # Mantener ventana deslizante y tasa
        REGISTRO_ENDPOINTS.setdefault(client_ip, set()).add(path)
        limpiar_registro(client_ip)
        REGISTRO_SOLICITUDES[client_ip].append(time.time())

        tasa = len(REGISTRO_SOLICITUDES[client_ip])
        
        # 3. CÁLCULO DE LOS COMPONENTES DEL SCORE DE AMENAZA

        # S_dos: Tasa de Petición (Rate Limiting)
        nivel_dos = calcular_nivel_amenaza_dos(tasa) 
        
        # S_blacklist: Escaneo Avanzado (CIDR)
        nivel_blacklist = PESO_BLACKLIST if check_ip_in_advanced_blacklist(client_ip, IP_BLACKLIST) else 0

        # S_heuristica: Análisis de Comportamiento (Scraping/Escaneo)
        sospechas_headers = analizar_headers_avanzado(user_agent, referer)
        
        score_headers = 0.5 if sospechas_headers else 0
        score_endpoints = 0.5 if len(REGISTRO_ENDPOINTS[client_ip]) > LIMITE_ENDPOINTS_DISTINTOS else 0

        nivel_heuristica = PESO_HEURISTICA * (score_headers + score_endpoints) 

        # 4. CÁLCULO DEL SCORE TOTAL Y DECISIÓN DE MITIGACIÓN

        S_total = nivel_dos + nivel_blacklist + nivel_heuristica

        if S_total >= UMBRAL_BLOQUEO:
            descripcion_log = [
                f"Score Total: {S_total:.3f} > Umbral {UMBRAL_BLOQUEO}",
                f"DoS: {nivel_dos:.3f}, Blacklist: {nivel_blacklist:.3f}, Heurística: {nivel_heuristica:.3f}"
            ]
            registrar_evento(
                tipo="Bloqueo por Score Total",
                descripcion=" ; ".join(descripcion_log),
                severidad="CRÍTICA",
            )
            limitar_peticion(usuario_id=client_ip)
            return HttpResponseForbidden("Acceso denegado por alto Score de Amenaza.")

        # 5. REGISTRO DE ADVERTENCIA (Si no se bloquea, pero es sospechoso)
        
        if S_total > UMBRAL_BLOQUEO * 0.75 or (nivel_dos > 0) or len(sospechas_headers) > 0:
            
            descripcion = sospechas_headers
            if score_endpoints > 0:
                 descripcion.append("Número anormal de endpoints distintos accedidos (posible escaneo/scraping)")

            descripcion.insert(0, f"Score Total: {S_total:.3f} (Tasa: {tasa} req/min)")
            descripcion.append(f"Ruta: {path}")

            logger.warning(
                "Tráfico Sospechoso desde IP %s: %s",
                client_ip,
                " ; ".join(descripcion),
            )
            
            request.dos_attack_info = {
                "ip": client_ip,
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": descripcion,
                "payload": json.dumps({"user_agent": user_agent, "referer": referer, "path": path}),
                "score": S_total,
            }

        return None