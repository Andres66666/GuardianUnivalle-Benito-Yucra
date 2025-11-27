"""
SQLI Defense Middleware con criptografía (AES-GCM / ChaCha20-Poly1305, HMAC-SHA256, Argon2id)
- Instala: cryptography, argon2-cffi
- Configuraciones mínimas en settings.py:
    SQLI_DEFENSE_MASTER_KEY = base64.b64encode(os.urandom(32)).decode()  # ejemplo
    SQLI_DEFENSE_AEAD = "AESGCM"  # o "CHACHA20"
    SQLI_DEFENSE_ARGON2 = {...}  # opcional, parámetros de Argon2id
    SQLI_DEFENSE_P_ATTACK_BLOCK = 0.97
    SQLI_DEFENSE_TRUSTED_IPS = []
    SQLI_DEFENSE_TRUSTED_URLS = []
    SQLI_DEFENSE_USE_CHALLENGE = False
"""

import base64        # Permite codificar/decodificar datos en Base64, útil para manejar claves o tokens.
import os            # Proporciona funciones del sistema operativo, como generar bytes aleatorios (os.urandom).
import json          # Permite serializar y deserializar datos en formato JSON.
import time          # Funciones relacionadas al tiempo: timestamps, delays, mediciones, etc.
import math          # Funciones matemáticas avanzadas (ceil, floor, log, etc.).
import hmac          # Implementación de HMAC (Hash-based Message Authentication Code) para firmas de seguridad.
import logging       # Manejo de logs para registrar eventos, errores y actividad del middleware.
import re            # Expresiones regulares para validar, buscar o limpiar patrones en cadenas.
import html          # Utilidades para escapar o des-escapar HTML (ej: prevención de XSS).
import urllib.parse  # Permite parsear URLs, querystrings, codificar/decodificar parámetros.
import ipaddress     # Permite validar y manipular direcciones IP (IPv4 e IPv6).
from typing import List, Tuple, Dict, Any   # Tipado opcional para mejorar claridad y autocompletado.

from django.utils.deprecation import MiddlewareMixin 
# Clase base para definir middlewares compatibles con versiones antiguas y nuevas de Django.

from django.conf import settings  
# Permite acceder a las configuraciones definidas en settings.py (claves, opciones, flags, etc).

from django.http import HttpResponseForbidden, HttpResponse 
# Respuestas HTTP para retornar códigos como 403 (Forbidden) o 200.

from django.core.cache import cache 
# Acceso al sistema de caché configurado en Django (Memcached, Redis, local-memory, etc.)

# ------------------ CRYPTOGRAFÍA Y ARGON2 ------------------

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  
# Implementaciones cifrado autenticado (AEAD):
# - AES-GCM (recomendado si hay aceleración por hardware)
# - ChaCha20-Poly1305 (ideal para hardware sin aceleración AES)

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac  
# "hashes": proporciona SHA256, SHA512, BLAKE2.
# "crypto_hmac": implementación criptográfica robusta de HMAC (más segura que el módulo estándar).

from cryptography.hazmat.primitives.kdf.hkdf import HKDF  
# HKDF: Derivación de claves. Se usa para generar múltiples claves seguras desde una master key.

from cryptography.exceptions import InvalidSignature  
# Excepción lanzada cuando falla la verificación de una firma HMAC o AEAD.

from argon2.low_level import hash_secret_raw, Type as Argon2Type  
# Argon2id: para hashing seguro de claves/derivación.
# "hash_secret_raw": produce hashes binarios crudos.
# "Argon2Type": permite seleccionar Argon2i, Argon2d o Argon2id.


# --- logger
logger = logging.getLogger("sqlidefense_crypto") # Logger específico para este middleware
logger.setLevel(logging.INFO) # Nivel de log: INFO, WARNING, ERROR
# Agregar handler si no tiene (evita duplicados en recargas)
if not logger.handlers: # Evita agregar múltiples handlers en recargas de código
    handler = logging.StreamHandler() # Loggear a consola (puede cambiarse a FileHandler u otro)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")) # Formato de log estándar 
    logger.addHandler(handler) # Agregar handler al logger 

# ---------------------------
# IMPORTANTE: Configuraciones
# ---------------------------
MASTER_KEY_B64 = getattr(settings, "SQLI_DEFENSE_MASTER_KEY", None) #  intenta leer la variable de configuración SQLI_DEFENSE_MASTER_KEY desde el settings de Django
if not MASTER_KEY_B64:  # Si no está definida, genera una clave maestra aleatoria de 32 bytes
    MASTER_KEY = os.urandom(32) # genera 32 bytes aleatorios seguros para usar como clave maestra
else: 
    try:
        MASTER_KEY = base64.b64decode(MASTER_KEY_B64) # decodifica la clave maestra desde base64
    except Exception:
        MASTER_KEY = MASTER_KEY_B64.encode() if isinstance(MASTER_KEY_B64, str) else MASTER_KEY_B64 # si falla, usa la cadena tal cual como bytes

AEAD_CHOICE = getattr(settings, "SQLI_DEFENSE_AEAD", "AESGCM").upper()  # AESGCM o CHACHA20 # Algoritmo AEAD a usar (AES-GCM recomendado si hay soporte hardware)

# Argon2id parámetros (ajustables desde settings)
ARGON2_CONFIG = getattr(settings, "SQLI_DEFENSE_ARGON2", {
    "time_cost": 2, # Número de iteraciones
    "memory_cost": 65536, # Memoria usada en KiB
    "parallelism": 1, # Grado de paralelismo
    "hash_len": 32, # Longitud del hash resultante
    "type": Argon2Type.ID, # Tipo Argon2id
}) # Configuración por defecto para Argon2id

# HMAC key derivation salt label
HMAC_LABEL = b"sqlidefense-hmac" # Etiqueta usada para derivar la clave HMAC desde la master key
AEAD_LABEL = b"sqlidefense-aead" # Etiqueta usada para derivar la clave AEAD desde la master key

# Patrones SQLi con su descripción y peso asociado (0.0 a 1.0)
SQL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.I), "UNION SELECT (exfiltración)", 0.95),
    (re.compile(r"\bselect\b\s+.*\bfrom\b\s+.+\bwhere\b", re.I | re.S), "SELECT ... FROM ... WHERE (consulta completa)", 0.7),
    (re.compile(r"\binto\s+outfile\b|\binto\s+dumpfile\b", re.I), "INTO OUTFILE / INTO DUMPFILE (volcado a fichero)", 0.98),
    (re.compile(r"\bload_file\s*\(", re.I), "LOAD_FILE() (lectura fichero MySQL)", 0.95),
    (re.compile(r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir)\s*\(", re.I), "pg_read_file / funciones lectura Postgres", 0.95),
    (re.compile(r"\bfile_read\b|\bfile_get_contents\b", re.I), "Indicadores de lectura de fichero en código", 0.85),

    (re.compile(r"\b(sleep|benchmark|pg_sleep|dbms_lock\.sleep|waitfor\s+delay)\b\s*\(", re.I),
     "SLEEP/pg_sleep/WAITFOR DELAY (time-based blind)", 0.98),
    (re.compile(r"\bbenchmark\s*\(", re.I), "BENCHMARK() MySQL (time/DoS)", 0.9),

    (re.compile(r"\b(updatexml|extractvalue|xmltype|utl_http\.request|dbms_xmlquery)\b\s*\(", re.I),
     "Funciones que devuelven errores con contenido (error-based)", 0.95),
    (re.compile(r"\bconvert\(\s*.*\s+using\s+.*\)", re.I), "CONVERT ... USING (encoding conversions potenciales)", 0.7),

    (re.compile(r"\b(nslookup|dnslookup|xp_dirtree|xp_dirtree\(|xp_regread|xp\w+)\b", re.I),
     "Funciones/procs que pueden generar exfiltración OOB (DNS/SMB callbacks)", 0.95),
    (re.compile(r"\b(utl_http\.request|utl_tcp\.socket|http_client|apex_web_service\.make_rest_request)\b", re.I),
     "UTL_HTTP/HTTP callbacks (Oracle/PLSQL HTTP OOB)", 0.95),

    (re.compile(r"\bxp_cmdshell\b|\bexec\s+xp\w+|\bsp_oacreate\b", re.I), "xp_cmdshell / sp_oacreate (ejecución OS MSSQL/Oracle)", 0.98),
    (re.compile(r"\b(exec\s+master\..*xp\w+|sp_executesql|execute\s+immediate|EXEC\s+UTE)\b", re.I), "Ejecución dinámica / sp_executesql / EXECUTE IMMEDIATE", 0.95),

    (re.compile(r"\binformation_schema\b", re.I), "INFORMATION_SCHEMA (recon meta-datos)", 0.92),
    (re.compile(r"\b(information_schema\.tables|information_schema\.columns)\b", re.I), "INFORMATION_SCHEMA.tables/columns", 0.92),
    (re.compile(r"\b(sys\.tables|sys\.objects|sys\.databases|pg_catalog|pg_tables|pg_user)\b", re.I), "Catálogos del sistema (MSSQL/Postgres)", 0.9),

    (re.compile(r"\b(drop\s+table|truncate\s+table|drop\s+database|drop\s+schema)\b", re.I), "DROP/TRUNCATE (DDL destructivo)", 0.95),
    (re.compile(r"\b(delete\s+from|update\s+.+\s+set|insert\s+into)\b", re.I), "DML (DELETE/UPDATE/INSERT potencialmente destructivo)", 0.85),

    (re.compile(r";\s*(select|insert|update|delete|drop|create|truncate)\b", re.I), "Stacked queries (uso de ';' para apilar)", 0.88),

    (re.compile(r"\b(or|and)\b\s+(['\"]?\d+['\"]?)\s*=\s*\1", re.I), "Tautología OR/AND 'x'='x' o 1=1", 0.85),
    (re.compile(r"(['\"]).{0,10}\1\s*or\s*['\"][^']*['\"]\s*=\s*['\"][^']*['\"]", re.I), "Tautología clásica en cadenas (OR '1'='1')", 0.8),

    (re.compile(r"\b(substring|substr|mid|left|right)\b\s*\(", re.I), "SUBSTRING/SUBSTR/LEFT/RIGHT (blind extraction)", 0.82),
    (re.compile(r"\b(ascii|char|chr|nchr)\b\s*\(", re.I), "ASCII/CHAR/CHR (byte/char extraction)", 0.8),

    (re.compile(r"\b(updatexml|extractvalue|xmltype|xmlelement)\b\s*\(", re.I), "updatexml/extractvalue/xmltype (error/XPath leaks)", 0.93),

    (re.compile(r"\binto\s+outfile\b|\binto\s+dumpfile\b", re.I), "INTO OUTFILE / DUMPFILE (escritura en servidor)", 0.97),
    (re.compile(r"\bopenrowset\b|\bbulk\s+insert\b|\bcopy\s+to\b", re.I), "OPENROWSET / BULK INSERT / COPY TO (exportación)", 0.92),

    (re.compile(r"0x[0-9a-fA-F]+", re.I), "Hex literal (0x...) (ofuscación)", 0.6),
    (re.compile(r"\\x[0-9a-fA-F]{2}", re.I), "Escapes hex tipo \\xNN (ofuscación)", 0.6),
    (re.compile(r"&#x[0-9a-fA-F]+;|&#\d+;", re.I), "Entidades HTML / entidades numéricas (ofuscación)", 0.6),
    (re.compile(r"\bchar\s*\(\s*\d+\s*\)", re.I), "CHAR(n) usado para construir cadenas (ofuscación)", 0.65),
    (re.compile(r"\bconcat\(", re.I), "CONCAT() (construcción dinámica de strings)", 0.6),

    (re.compile(r"%3[dD]|%27|%22|%3C|%3E|%3B", re.I), "URL encoding típico (%27, %3C, etc.)", 0.4),

    (re.compile(r"(--\s|#\s|/\*[\s\S]*\*/)", re.I), "Comentarios SQL (--) o /* */ o #", 0.45),

    (re.compile(r"\b\$where\b|\b\$ne\b|\b\$regex\b", re.I), "NoSQL / MongoDB indicators ($where/$ne/$regex)", 0.5),

    (re.compile(r"sqlmap", re.I), "Indicador de herramienta sqlmap en payload", 0.5),
    (re.compile(r"hydra|nmap|nikto", re.I), "Indicador de herramientas de auditoría/scan", 0.3),

    (re.compile(r"\bexecute\b\s*\(", re.I), "execute(...) (ejecución dinámica)", 0.7),
    (re.compile(r"\bdeclare\b\s+@?\w+", re.I), "DECLARE variable (MSSQL/PLSQL declarations)", 0.7),

    (re.compile(r"\bselect\b\s+.*\bfrom\b", re.I), "Estructura SELECT FROM (heurístico)", 0.25),
    (re.compile(r"\binsert\b\s+into\b", re.I), "INSERT INTO (heurístico)", 0.3),

    (re.compile(r"(['\"]).*?;\s*(drop|truncate|delete|update|insert)\b", re.I | re.S), "Cadena con terminador y DDL/DML (potencial ataque)", 0.9),
    (re.compile(r"\b(or)\b\s+1\s*=\s*1\b", re.I), "OR 1=1 tautology", 0.85),

    (re.compile(r"\bselect\s+.*\s+from\s+.*\s+where\s+.*\s+in\s*\(.*\)", re.I | re.S), "Subquery anidada (IN subquery)", 0.75),

    (re.compile(r"\bcase\s+when\s+.*\s+then\s+.*\s+else\b", re.I), "CASE WHEN (blind boolean)", 0.78),
    (re.compile(r"/\*!.+\*/", re.I), "Comentarios condicionales MySQL (/*!...*/)", 0.7),
    (re.compile(r"\bif\s*\(\s*.*\s*,\s*.*\s*,\s*.*\s*\)", re.I), "IF() MySQL (conditional)", 0.72),
    (re.compile(r"\bgroup_concat\s*\(", re.I), "GROUP_CONCAT() (exfiltración en error)", 0.8),
]


#  Se suelen cifrar o sanitizar antes de escribir en logging para evitar fugas de credenciales.
SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth", "email", "username"] # Campos considerados sensibles para cifrar en logs

DEFAULT_THRESHOLDS = getattr(settings, "SQLI_DEFENSE_THRESHOLDS", {"HIGH": 1.8, "MEDIUM": 1.0, "LOW": 0.5}) # Umbrales de score para niveles de alerta
BLOCK_TIMEOUT = getattr(settings, "SQLI_DEFENSE_BLOCK_SECONDS", 60 * 60) # Tiempo de bloqueo inicial en segundos (1 hora por defecto)
COUNTER_WINDOW = getattr(settings, "SQLI_DEFENSE_COUNTER_WINDOW", 60 * 5) # Ventana de tiempo para contar intentos (5 minutos por defecto)
COUNTER_THRESHOLD = getattr(settings, "SQLI_DEFENSE_COUNTER_THRESHOLD", 5) # Umbral de intentos para activar bloqueo
CACHE_BLOCK_KEY_PREFIX = "sqli_block:" # Prefijo para claves de bloqueo en caché
CACHE_COUNTER_KEY_PREFIX = "sqli_count:" # Prefijo para claves de contador en caché
SATURATION_C = getattr(settings, "SQLI_DEFENSE_SATURATION_C", 1.5) # Constante C para función de saturación
SATURATION_ALPHA = getattr(settings, "SQLI_DEFENSE_SATURATION_ALPHA", 2.0) # Constante alpha para función de saturación
NORM_THRESHOLDS = {
    "HIGH": getattr(settings, "SQLI_DEFENSE_NORM_HIGH", 0.2), # Umbral normalizado alto
    "MEDIUM": getattr(settings, "SQLI_DEFENSE_NORM_MED", 0.1), # Umbral normalizado medio
    "LOW": getattr(settings, "SQLI_DEFENSE_NORM_LOW", 0.05), # Umbral normalizado bajo
}
PROB_LAMBDA = getattr(settings, "SQLI_DEFENSE_PROB_LAMBDA", 1.0) # Lambda para función de probabilidad exponencial 

# Peso para cálculo de probabilidad de ataque basado en patrones detectados
FIELD_WEIGHTS = getattr(settings, "SQLI_DEFENSE_FIELD_WEIGHTS", {"_query_string": 1.2, "username": 0.6, "password": 1.8, "raw": 1.0}) # Pesos por campo 

# Si un cliente sigue intentando atacar tras ser desbloqueado, se le aplica el siguiente nivel de backoff más severo. 0s → 15 min → 1h → 6h → 24h → 7 días.
DEFAULT_BACKOFF_LEVELS = getattr(settings, "SQLI_DEFENSE_BACKOFF_LEVELS", [0, 60 * 15, 60 * 60, 60 * 60 * 6, 60 * 60 * 24, 60 * 60 * 24 * 7]) 

# -------------------------------------------------------
# Qué hace: genera una clave simétrica de 32 bytes a partir de MASTER_KEY, usando Argon2 raw y luego HKDF. Esto permite rotación si cambias MASTER_KEY.
# -------------------------------------------------------
def derive_key(label: bytes, context: bytes = b"") -> bytes: # Deriva una clave simétrica de 32 bytes a partir de MASTER_KEY usando Argon2id y HKDF
    salt = (label + context)[:16].ljust(16, b"\0") # Salto fijo de 16 bytes basado en label+context (rellenado con ceros si es necesario)
    try: # Intentar derivar con Argon2id
        raw = hash_secret_raw(secret=MASTER_KEY if isinstance(MASTER_KEY, (bytes, bytearray)) else MASTER_KEY.encode(), # Clave maestra como bytes
                              salt=salt,
                              time_cost=ARGON2_CONFIG["time_cost"],
                              memory_cost=ARGON2_CONFIG["memory_cost"],
                              parallelism=ARGON2_CONFIG["parallelism"],
                              hash_len=ARGON2_CONFIG["hash_len"],
                              type=ARGON2_CONFIG["type"])
        # pulir con HKDF para obtener 32 bytes de alta calidad
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context) # HKDF con SHA256
        key = hk.derive(raw) # Derivar clave final
        return key # Retornar clave derivada
    except Exception:
        # fallback seguro simple: HKDF desde MASTER_KEY
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())

# funcion de cifrado AEAD  
def aead_encrypt(plaintext: bytes, aad: bytes = b"", context: bytes = b"") -> Dict[str, bytes]: # Cifra con AEAD configurado (AES-GCM ChaCha20-Poly1305)
    """
    Cifra con AEAD configurado (AES-GCM o ChaCha20-Poly1305).
    Retorna dict con: ciphertext, nonce, tag (si aplica), alg
    """
    key = derive_key(AEAD_LABEL, context)  # llamar a derive_key para obtener una clave derivada segura, usando HKDF + Argon2id (en tu middleware).
    if AEAD_CHOICE == "CHACHA20":  # Verifica si en configuración seleccionaste ChaCha20-Poly1305 como algoritmo AEAD a usar.
        aead = ChaCha20Poly1305(key) # Crear instancia de ChaCha20Poly1305 con la clave derivada.
        nonce = os.urandom(12) # Generar nonce aleatorio de 12 bytes (requisito para ChaCha20-Poly1305).
        ct = aead.encrypt(nonce, plaintext, aad) # Cifrar los datos con el nonce, plaintext y datos adicionales (AAD).
        # ChaCha20Poly1305 devuelve ciphertext+tag juntos
        return {"alg": "CHACHA20-POLY1305", "nonce": nonce, "ciphertext": ct} # Retornar diccionario con algoritmo, nonce y ciphertext.
    else:
        # AES-GCM (recomendado)
        aead = AESGCM(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        # AESGCM devuelve ciphertext||tag (16 bytes tag al final)
        return {"alg": "AES-GCM", "nonce": nonce, "ciphertext": ct}

# funcion de descifrado AEAD descifra lo cifrado por aead_encrypt
def aead_decrypt(payload: Dict[str, bytes], aad: bytes = b"", context: bytes = b"") -> bytes: # Descifra con AEAD configurado (AES-GCM o ChaCha20-Poly1305)
    key = derive_key(AEAD_LABEL, context) # Derivar la clave usando la misma función derive_key
    alg = payload.get("alg", "AES-GCM") # Obtener el algoritmo usado del payload (por defecto AES-GCM)
    nonce = payload.get("nonce") # Obtener el nonce del payload
    ct = payload.get("ciphertext") # Obtener el ciphertext del payload
    if not nonce or not ct: # Validar que nonce y ciphertext estén presentes
        raise ValueError("invalid payload for AEAD decrypt") # Lanzar error si faltan datos
    if alg.startswith("CHACHA20"): # Si el algoritmo es ChaCha20-Poly1305
        aead = ChaCha20Poly1305(key) # Crear instancia de ChaCha20Poly1305 con la clave derivada
        return aead.decrypt(nonce, ct, aad) # Descifrar y retornar el plaintext
    else:
        aead = AESGCM(key) # Si es AES-GCM, crear instancia de AESGCM con la clave derivada
        return aead.decrypt(nonce, ct, aad) # Descifrar y retornar el plaintext

# funciones HMAC  calcula HMAC-SHA256 sobre data usando clave derivada derive_key(HMAC_LABEL, context).
#  firma/autenticidad independiente del AEAD (defensa en profundidad). Aquí se firma específicamente el ciphertext resultante.
def compute_hmac(data: bytes, context: bytes = b"") -> bytes: # Computa HMAC-SHA256 del data usando clave derivada
    key = derive_key(HMAC_LABEL, context) # Derivar clave HMAC usando derive_key
    h = crypto_hmac.HMAC(key, hashes.SHA256()) # Crear instancia HMAC con SHA256
    h.update(data) # Actualizar HMAC con los datos
    return h.finalize() # Retornar el tag HMAC resultante

# Verifica HMAC-SHA256 sobre data usando clave derivada derive_key(HMAC_LABEL, context).
# Retorna True si la verificación es exitosa, False si falla.
def verify_hmac(data: bytes, tag: bytes, context: bytes = b"") -> bool: # Verifica HMAC-SHA256 del data contra el tag usando clave derivada
    key = derive_key(HMAC_LABEL, context) # Derivar clave HMAC usando derive_key
    h = crypto_hmac.HMAC(key, hashes.SHA256()) # Crear instancia HMAC con SHA256
    h.update(data) # Actualizar HMAC con los datos
    try:
        h.verify(tag) # Verificar el tag HMAC contra los datos
        return True
    except InvalidSignature: 
        return False

# -------------------------
# Helpers utilitarios
# -------------------------
def get_client_ip(request) -> str: # Extrae la IP real del cliente considerando proxies y cabeceras X-Forwarded-For
    trusted_proxies = getattr(settings, "SQLI_DEFENSE_TRUSTED_PROXIES", [])

    def ip_in_trusted(ip_str: str) -> bool: # Verifica si una IP está en la lista de proxies confiables
        try:
            ip_obj = ipaddress.ip_address(ip_str) # Convertir cadena IP a objeto ipaddress
        except Exception:
            return False # Si no es válida, retornar False
        for p in trusted_proxies: # Iterar sobre las entradas de proxies confiables
            try:
                if '/' in p: # Si es una red
                    if ip_obj in ipaddress.ip_network(p, strict=False):  # Verificar si la IP está en la red
                        return True 
                else:
                    if ip_obj == ipaddress.ip_address(p): # Si es una IP individual, comparar directamente
                        return True
            except Exception:
                continue
        return False

    xff = request.META.get("HTTP_X_FORWARDED_FOR", "") # Leer cabecera X-Forwarded-For
    if xff: # Si existe XFF, procesar la lista de IPs
        parts = [p.strip() for p in xff.split(",") if p.strip()] # Dividir y limpiar la lista de IPs
        for ip_candidate in parts: # Iterar en orden (cliente primero)
            try:
                ipaddress.ip_address(ip_candidate) # Validar formato de IP
            except Exception:
                continue
            if not ip_in_trusted(ip_candidate): # Si no es proxy confiable, retornar esta IP
                return ip_candidate  # Retornar la primera IP no confiable (cliente real)
        if parts:  # Si todas son proxies confiables, retornar la última (más cercana al servidor)
            return parts[-1]  # Retornar la última IP en la lista

    xr = request.META.get("HTTP_X_REAL_IP", "") # Leer cabecera X-Real-IP
    if xr: # Si existe X-Real-IP, validarla
        try:
            ipaddress.ip_address(xr) # Validar formato de IP
            if not ip_in_trusted(xr):   # Si no es proxy confiable, retornar esta IP
                return xr  # Retornar la IP de X-Real-IP si no es proxy confiable
        except Exception:
            pass

    hcip = request.META.get("HTTP_CLIENT_IP", "") # Leer cabecera HTTP_CLIENT_IP
    if hcip: # Si existe HTTP_CLIENT_IP, validarla
        try:
            ipaddress.ip_address(hcip) # Validar formato de IP
            return hcip  # Retornar la IP de HTTP_CLIENT_IP si es válida
        except Exception: 
            pass

    remote = request.META.get("REMOTE_ADDR", "") # Leer dirección remota
    return remote or "" # Retornar la IP remota (último recurso)

# Normaliza la entrada decodificando URL, HTML entities, limpiando espacios y escapes hex
def normalize_input(s: str) -> str:
    if not s: # Si la cadena está vacía, retornar cadena vacía
        return ""
    try:
        s_dec = urllib.parse.unquote_plus(s) # Decodificar URL-encoded (incluye '+' como espacio)
    except Exception:
        s_dec = s # Si falla, usar la cadena original
    try:
        s_dec = html.unescape(s_dec) # Decodificar entidades HTML
    except Exception:
        pass
    s_dec = re.sub(r"\\x([0-9a-fA-F]{2})", r"\\x\g<1>", s_dec) # Normalizar escapes hex tipo \xNN
    s_dec = re.sub(r"\s+", " ", s_dec) # Reemplazar múltiples espacios por uno solo
    return s_dec.strip() # Retornar cadena limpia y normalizada

# transforma un peso (score) w en probabilidad q usando la fórmula: q = 1 - exp(-w / λ) con λ = PROB_LAMBDA.
def weight_to_prob(w: float) -> float: # Convierte un peso a probabilidad usando función exponencial
    try:
        lam = float(PROB_LAMBDA) # Obtener lambda de configuración
        q = 1.0 - math.exp(-max(float(w), 0.0) / lam) # Calcular probabilidad usando función exponencial
        return min(max(q, 0.0), 0.999999) # Asegurar que esté en rango [0.0, 0.999999]
    except Exception: 
        return min(max(w, 0.0), 0.999999) # Fallback: retornar peso acotado

# Combina múltiples probabilidades independientes en una sola
# Usando la fórmula: Q = 1 - ∏(1 - q_i)
def combine_probs(qs: List[float]) -> float:  # Combina múltiples probabilidades independientes en una sola
    prod = 1.0  # Producto acumulado de (1 - q)
    for q in qs: # Iterar sobre cada probabilidad
        prod *= (1.0 - q) # Multiplicar por (1 - q)
    return 1.0 - prod # Retornar la probabilidad combinada

# Aplica función sigmoide para saturar el score
# aplica función sigmoide/ logística: 1 / (1 + exp(-alpha * (x - c))) con alpha = SATURATION_ALPHA, c = SATURATION_C.
def saturate_score(raw_score: float) -> float: # Aplica función sigmoide para saturar el score
    try:
        x = float(raw_score) # Convertir score a float
        alpha = float(SATURATION_ALPHA) # Obtener alpha de configuración
        c = float(SATURATION_C) # Obtener c de configuración
        return 1.0 / (1.0 + math.exp(-alpha * (x - c))) # Calcular y retornar score saturado
    except Exception:
        return 0.0 # Si falla, retornar 0.0


def detect_sql_injection(text: str) -> Dict: # funcion que Detecta patrones SQLi en el texto y calcula un score basado en pesos
    norm = normalize_input(text or "") # Normalizar la entrada
    score = 0.0 # Score acumulado
    matches = [] # Lista de coincidencias encontradas
    pattern_occurrences = {} # Diccionario para contar ocurrencias de patrones
     # Contar ocurrencias de cada patrón en el texto normalizado
    for pattern, desc, weight in SQL_PATTERNS: # Iterar sobre cada patrón definido
        for _ in pattern.finditer(norm): # Buscar todas las ocurrencias del patrón
            pattern_occurrences[pattern.pattern] = pattern_occurrences.get(pattern.pattern, 0) + 1 # Incrementar contador de ocurrencias
    prob_list = [] # Lista de probabilidades individuales
    for pattern, desc, weight in SQL_PATTERNS: # Iterar nuevamente para calcular score y detalles
        occ = pattern_occurrences.get(pattern.pattern, 0) # Obtener número de ocurrencias del patrón
        if occ > 0: # Si hubo ocurrencias, calcular contribución al score
            added = 0.0 # Score añadido por este patrón
            # Aplicar decaimiento geométrico por ocurrencia
            for i in range(occ): # Iterar sobre cada ocurrencia
                added += weight * (0.5 ** i) # Sumar peso con decaimiento geométrico
            score += added # Acumular al score total
             # Guardar detalles de la coincidencia
            matches.append((desc, pattern.pattern, weight, occ, round(added, 3))) # Agregar detalles a la lista de matches
             # Calcular probabilidad individual y agregar a la lista
            q = weight_to_prob(added)
            prob_list.append(q)
    return {
        "score": round(score, 3), # Score total redondeado
        "matches": matches, # Detalles de coincidencias
        "descriptions": list({m[0] for m in matches}), # Descripciones únicas de patrones encontrados
        "sample": norm[:1200], # Muestra del texto normalizado (hasta 1200 caracteres)
        "prob_list": prob_list, # Lista de probabilidades individuales
    }

# Redactar payload summary (ahora se encripta snippets antes de loggear)
# por cada elemento del resumen (field, snippet, sensitive) cifra (AEAD) el snippet, calcula HMAC del ciphertext y devuelve una representación base64 del paquete cifrado. Si falla, devuelve "<REDACTED>".
def redact_and_encrypt_payload(payload_summary: List[Dict[str, Any]], context: bytes = b"") -> List[Dict[str, Any]]: # Redacta  cifra snippets sensibles en el payload summary antes de loggear
    encrypted_list = [] # Lista para almacenar resultados cifrados redactados
     # Iterar sobre cada entrada en el payload summary
    for p in payload_summary:
        snippet = p.get("snippet", "") # Obtener el snippet
         # Determinar si el campo es sensible
        is_sensitive = p.get("sensitive", False)
        # Decide: si sensible -> cifrar, si no -> truncar + cifrar si score alto
        try:
            enc = aead_encrypt(snippet.encode("utf-8"), aad=b"", context=context) # Cifrar el snippet
            # Calcular HMAC del ciphertext para integridad
            htag = compute_hmac(enc["ciphertext"], context=context) # Calcular HMAC del ciphertext
            # Preparar estructura cifrada en base64 para logging
            enc_b64 = {
                "alg": enc["alg"], # Algoritmo de cifrado utilizado
                "nonce": base64.b64encode(enc["nonce"]).decode(), # Nonce en base64
                "ciphertext": base64.b64encode(enc["ciphertext"]).decode(), # Texto cifrado en base64
                "hmac": base64.b64encode(htag).decode(), # HMAC en base64 para integridad
            }
            encrypted_list.append({"field": p.get("field"), "encrypted": enc_b64, "sensitive": is_sensitive}) # Agregar entrada cifrada a la lista
            
        except Exception:
            # fallback: redact
            encrypted_list.append({"field": p.get("field"), "snippet": "<REDACTED>", "sensitive": is_sensitive}) # Si falla cifrado, agregar entrada redactada
    return encrypted_list # Retornar la lista de entradas cifradas o redactadas

# Cache helpers
# incrementa el level de bloqueo para la IP (guardado en cache) y establece bloqueo por tiempo según DEFAULT_BACKOFF_LEVELS. Retorna el nuevo level y timeout aplicado.
def cache_block_ip_with_backoff(ip: str):
    if not ip: # Si no hay IP, retornar 0, 0
        return 0, 0
    level_key = f"{CACHE_BLOCK_KEY_PREFIX}{ip}:level" # Clave para el nivel de bloqueo
     # Obtener nivel actual de bloqueo desde cache
    level = cache.get(level_key, 0) or 0
    level = int(level) + 1 # Incrementar el nivel de bloqueo
     # Guardar el nuevo nivel de bloqueo en cache (expira en 7 días)
    cache.set(level_key, level, timeout=60 * 60 * 24 * 7)
    durations = DEFAULT_BACKOFF_LEVELS # Obtener niveles de backoff configurados
     # Determinar timeout basado en el nivel (acotar al máximo definido)
    idx = min(level, len(durations) - 1)
    timeout = durations[idx] # Tiempo de bloqueo en segundos
    cache.set(f"{CACHE_BLOCK_KEY_PREFIX}{ip}", True, timeout=timeout) # Establecer bloqueo en cache con timeout
    return level, timeout # Retornar el nuevo nivel y timeout aplicado

#  consulta cache si la IP está actualmente bloqueada (llave sqli_block:<ip>).
def is_ip_blocked(ip: str) -> bool:
    if not ip: # Si no hay IP, retornar False
        return False
    return bool(cache.get(f"{CACHE_BLOCK_KEY_PREFIX}{ip}")) # Retornar estado de bloqueo desde cache

def incr_ip_counter(ip: str) -> int: # Incrementa el contador de intentos para la IP en la ventana definida y retorna el conteo actual
    if not ip: # Si no hay IP, retornar 0
        return 0
    key = f"{CACHE_COUNTER_KEY_PREFIX}{ip}" # Clave para el contador de intentos
     # Obtener el conteo actual desde cache
    current = cache.get(key, 0)
    try:
        current = int(current) # Convertir a entero
    except Exception: # Si falla, reiniciar a 0
        current = 0 
    current += 1  # Incrementar el contador
     # Guardar el nuevo conteo en cache con timeout definido
    cache.set(key, current, timeout=COUNTER_WINDOW)
    return current # Retornar el conteo actual

# registra (en cache) un evento de detección con timestamp y cifrado del payload si existe.
def record_detection_event(event: dict) -> None: # Registra el evento de detección en cache con cifrado AEAD y HMAC
    try:
        ts = int(time.time()) # Timestamp actual en segundos
        # cifrar payload si existe
        if "payload" in event and event["payload"]: # Si hay payload para cifrar
             # Contexto para cifrado/HMAC basado en IP y timestamp
            try:
                ctx = f"{event.get('ip','')}-{ts}".encode() # Contexto para cifrado/HMAC
                 # Cifrar el payload con AEAD
                enc = aead_encrypt(json.dumps(event["payload"], ensure_ascii=False).encode("utf-8"), context=ctx) # Cifrar el payload
                 # Calcular HMAC del ciphertext
                htag = compute_hmac(enc["ciphertext"], context=ctx) # Calcular HMAC del ciphertext
                 # Preparar estructura cifrada en base64 para almacenamiento
                event["_payload_encrypted"] = {
                    "alg": enc["alg"], # Algoritmo de cifrado utilizado
                    "nonce": base64.b64encode(enc["nonce"]).decode(), # Nonce en base64
                    "ciphertext": base64.b64encode(enc["ciphertext"]).decode(), # Texto cifrado en base64
                    "hmac": base64.b64encode(htag).decode(), # HMAC en base64 para integridad
                } 
                del event["payload"] # Eliminar el payload original
            except Exception:
                event.pop("payload", None) # Si falla cifrado, eliminar el payload
         # Guardar el evento en cache con clave basada en timestamp e IP
        key = f"sqli_event:{ts}:{event.get('ip', '')}" # Clave única para el evento
         # Guardar en cache el evento serializado como JSON (expira en 24 horas
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24) # Expira en 24 horas
    except Exception:
        logger.exception("record_detection_event failed") # Loggear excepción si falla el registro

# --------------------------
# Middleware principal
# --------------------------
class SQLIDefenseCryptoMiddleware(MiddlewareMixin):
    def process_request(self, request): # Procesa cada request entrante para detectar y bloquear SQLi
         # Obtener IP del cliente
        client_ip = get_client_ip(request) # Extraer la IP real del cliente desde el request usando cabeceras de get cliente ip 

        # Chequear bloqueo persistente  mediante cache verifica si la IP está bloqueada en cache
        if is_ip_blocked(client_ip):
            warning_message = (
                "Acceso denegado. Su dirección IP y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[SQLiBlock:Persistent] IP={client_ip} - Intento persistente de acceso bloqueado. Mensaje enviado.")
            return HttpResponseForbidden(warning_message) # Retornar 403 Forbidden con mensaje de advertencia


        trusted_ips = getattr(settings, "SQLI_DEFENSE_TRUSTED_IPS", []) # Lista de IPs confiables desde configuración
         # Saltar análisis si la IP del cliente está en la lista de IPs confiables
        if client_ip and client_ip in trusted_ips: # Si la IP está en la lista de IPs confiables, saltar análisis
            return None

        trusted_urls = getattr(settings, "SQLI_DEFENSE_TRUSTED_URLS", []) # Lista de URLs confiables desde configuración
        referer = request.META.get("HTTP_REFERER", "") # Leer cabecera Referencia 
        host = request.get_host() # Obtener host del request
         # Saltar análisis si la URL de referencia o el host están en la lista de URLs confiables
        if any(url in referer for url in trusted_urls) or any(url in host for url in trusted_urls): # Si la URL de referencia o el host están en la lista de URLs confiables, saltar análisis
            return None # Saltar análisis

        # Extraer payload
        data = {} # Diccionario para almacenar datos extraídos
         # Intentar extraer datos del request según el Content-Type
        try:
            ct = request.META.get("CONTENT_TYPE", "") # Leer cabecera Content-Type
            if "application/json" in ct: # Si es JSON, parsear el cuerpo
                raw = request.body.decode("utf-8") or "{}" # Decodificar cuerpo del request
                try:
                    parsed = json.loads(raw) # Parsear JSON
                    if isinstance(parsed, dict): # Si es un dict, usarlo directamente
                        data = parsed # Asignar datos parseados
                    else:
                        data = {"raw": raw} # Si no es dict, guardar como raw
                except Exception:
                    data = {"raw": raw} # Si falla parseo, guardar como raw
            else:
                try:
                    post = request.POST.dict() # Intentar obtener datos de formulario POST
                    if post: # Si hay datos de formulario, usarlos
                        data = post # Asignar datos de formulario
                    else:
                        raw = request.body.decode("utf-8", errors="ignore") # Decodificar cuerpo del request ignorando errores
                        data = {"raw": raw} if raw else {}
                except Exception:
                    raw = request.body.decode("utf-8", errors="ignore") # Decodificar cuerpo del request ignorando errores
                    data = {"raw": raw} if raw else {} # Guardar como raw si hay datos
        except Exception:
            data = {} # Si falla extracción, usar dict vacío

        qs = request.META.get("QUERY_STRING", "") # Extraer query string
        if qs: # Si hay query string, agregarlo a los datos
            if isinstance(data, dict):  # Si data es dict, agregar query string bajo clave especial
                data["_query_string"] = qs # Agregar query string a los datos
            else:
                data = {"_query_string": qs, "raw": str(data)} # Si no es dict, crear nuevo dict con query string y raw

        if not data:  # Si no hay datos, no continuar
            return None

        # Detectar SQLi por campo
        total_score = 0.0 # Score total acumulado
        all_descriptions = [] # Lista de descripciones de patrones encontrados
        payload_summary = [] # Resumen de payloads detectados
        global_prob_list = [] # Lista global de probabilidades

        if isinstance(data, dict): # Si los datos son un dict, analizar cada campo
            for key, value in data.items(): # Iterar sobre cada campo y valor
                 # Convertir el valor a texto para análisis
                if isinstance(value, (dict, list)):
                    try:
                        vtext = json.dumps(value, ensure_ascii=False) # Convertir dict/list a JSON string
                    except Exception:
                        vtext = str(value) # Fallback a str si falla
                else:
                    vtext = str(value or "") # Convertir a str directamente

                result = detect_sql_injection(vtext) # Detectar SQLi en el texto del campo
                field_weight = FIELD_WEIGHTS.get(str(key), 1.0) # Obtener peso del campo (default 1.0)
                added_score = result.get("score", 0.0) * float(field_weight) # Calcular score ajustado por peso del campo
                 # Acumular score total
                total_score += added_score
                for q in result.get("prob_list", []): # Ajustar probabilidades por peso del campo
                    q_field = 1.0 - ((1.0 - q) ** float(field_weight)) # Ajustar probabilidad por peso del campo
                    global_prob_list.append(q_field) # Agregar a la lista global de probabilidades
                 # Acumular descripciones encontradas
                all_descriptions.extend(result.get("descriptions", []))
                if result.get("score", 0) > 0: # Si se detectó SQLi en este campo, agregar al resumen de payloads
                     # Determinar si el campo es sensible
                    is_sensitive = isinstance(key, str) and key.lower() in SENSITIVE_FIELDS # Marcar como sensible si el campo está en la lista de campos sensibles
                     # Agregar resumen del payload detectado
                    payload_summary.append({"field": key, "snippet": vtext[:300], "sensitive": is_sensitive})
        else:
            raw = str(data) # Si los datos no son un dict, convertir todo a str
             # Analizar el texto completo
            result = detect_sql_injection(raw)
            total_score += result.get("score", 0.0) # Acumular score total
             # Acumular descripciones encontradas
            all_descriptions.extend(result.get("descriptions", []))
            for q in result.get("prob_list", []): # Agregar probabilidades a la lista global
                global_prob_list.append(q) # Agregar a la lista global de probabilidades
             # Agregar resumen del payload detectado si hubo score
            if result.get("score", 0) > 0: # Si se detectó SQLi en el texto completo, agregar al resumen de payloads
                payload_summary.append({"field": "raw", "snippet": raw[:500], "sensitive": False}) # Marcar como no sensible

        if total_score == 0 and not global_prob_list: # Si no se detectó SQLi, no continuar
            return None

        # normalización y probabilidad combinada
        p_attack = combine_probs(global_prob_list) if global_prob_list else 0.0 # Combinar probabilidades individuales
         # Calcular score normalizado
        s_norm = saturate_score(total_score)

        # Encriptar / redactar payload summaries antes de loggear/almacenar
        ctx = f"{client_ip}-{int(time.time())}".encode()
        try:
            encrypted_payload = redact_and_encrypt_payload(payload_summary, context=ctx) # Cifrar/resumir el payload antes de loggear
        except Exception:
            encrypted_payload = [{"field": p.get("field"), "snippet": "<REDACTED>", "sensitive": p.get("sensitive", False)} for p in payload_summary] # Fallback: redactar todo si falla cifrado

        logger.warning(
            f"[SQLiDetect] IP={client_ip} Host={host} Score={total_score:.2f} S_norm={s_norm:.3f} P_attack={p_attack:.3f} Desc={all_descriptions} Payload_enc_snippets={json.dumps(encrypted_payload)[:1000]}" # Loggear detección de SQLi con detalles
        )

        request.sql_attack_info = {
            "ip": client_ip, # IP del cliente
            "tipos": ["SQLi"], #  Tipos de ataque detectados
            "descripcion": all_descriptions, # Descripciones de patrones encontrados
            "payload": json.dumps(encrypted_payload, ensure_ascii=False)[:2000], # Payload cifrado/resumido
            "score": round(total_score, 3), # Score total redondeado
            "s_norm": round(s_norm, 3), # Score normalizado redondeado
            "p_attack": round(p_attack, 3), # Probabilidad de ataque redondeada
            "url": request.build_absolute_uri(),    # URL completa del request
        } # Guardar info de ataque en el request para uso posterior

        # registrar evento cifrado
        try:
            record_detection_event({
                "ts": int(time.time()), # Timestamp del evento
                "type": "SQLi", # Tipo de ataque
                "ip": client_ip, # IP del cliente
                "score": total_score, # Score total
                "s_norm": s_norm, # Score normalizado
                "p_attack": p_attack, # Probabilidad de ataque
                "desc": all_descriptions, # Descripciones de patrones encontrados
                "url": request.build_absolute_uri(),    # URL completa del request
                "payload": encrypted_payload,  # ya viene cifrado dentro de redact_and_encrypt_payload
            })
        except Exception:
            logger.exception("failed to record event") # Loggear excepción si falla el registro del evento

        # Políticas de bloqueo: setea flags en lugar de retornar HttpResponseForbidden
        if p_attack >= getattr(settings, "SQLI_DEFENSE_P_ATTACK_BLOCK", 0.97): # Bloqueo basado en probabilidad de ataque
            level, timeout = cache_block_ip_with_backoff(client_ip) # Bloquear IP con backoff
            logger.error(f"[SQLiBlock:P_attack] IP={client_ip} P={p_attack:.3f} -> level={level} timeout={timeout}s") # Loggear bloqueo por probabilidad
            request.sql_attack_info.update({"blocked": True, "action": "block_p_attack", "block_timeout": timeout, "block_level": level}) # Actualizar info de ataque con detalles de bloqueo
            # Nuevo: setea flag para bloqueo en lugar de retornar
            request.sql_block = True
            request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense (probability)")  # Retornar 403 Forbidden
            return None  # No retorna respuesta aquí
        if s_norm >= NORM_THRESHOLDS["HIGH"]: # Bloqueo alto basado en score normalizado
            level, timeout = cache_block_ip_with_backoff(client_ip) # Bloquear IP con backoff
            logger.error(f"[SQLiBlock] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} URL={request.path}") # Loggear bloqueo por score normalizado alto
            request.sql_attack_info.update({"blocked": True, "action": "block", "block_timeout": timeout, "block_level": level}) # Actualizar info de ataque con detalles de bloqueo
            # Nuevo: setea flag para bloqueo
            request.sql_block = True
            request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense") # Retornar 403 Forbidden
            return None
        elif s_norm >= NORM_THRESHOLDS["MEDIUM"]: # Alerta/contador basado en score normalizado medio
            logger.warning(f"[SQLiAlert] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} - applying counter/challenge") # Loggear alerta por score normalizado medio
            count = incr_ip_counter(client_ip) # Incrementar contador de intentos para la IP
             # Actualizar info de ataque con detalles de alerta
            request.sql_attack_info.update({"blocked": False, "action": "alert", "counter": count})
            if count >= COUNTER_THRESHOLD: # Si el contador supera el umbral, aplicar bloqueo
                level, timeout = cache_block_ip_with_backoff(client_ip) # Bloquear IP con backoff
                 # Reiniciar el contador después del bloqueo
                cache.set(f"{CACHE_COUNTER_KEY_PREFIX}{client_ip}", 0, timeout=COUNTER_WINDOW)
                logger.error(f"[SQLiAutoBlock] IP={client_ip} reached counter={count} -> blocking for {timeout}s")
                request.sql_attack_info.update({"blocked": True, "action": "auto_block", "block_timeout": timeout, "block_level": level}) # Actualizar info de ataque con detalles de auto bloqueo
                # Nuevo: setea flag para bloqueo
                request.sql_block = True
                request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense (auto block)") # Retornar 403 Forbidden
                return None
            if getattr(settings, "SQLI_DEFENSE_USE_CHALLENGE", False): # Si está habilitado el desafío CAPTCHA
                # Nuevo: setea flag para challenge
                request.sql_challenge = True
                request.sql_challenge_response = HttpResponse("Challenge required", status=403) # Retornar 403 con desafío
                request.sql_challenge_response["X-SQLI-Challenge"] = "captcha"
                return None
            return None
        elif s_norm >= NORM_THRESHOLDS["LOW"]: # Monitoreo basado en score normalizado bajo
            logger.info(f"[SQLiMonitor] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} - monitored") # Loggear monitoreo por score normalizado bajo
            request.sql_attack_info.update({"blocked": False, "action": "monitor"}) # Actualizar info de ataque con acción de monitoreo
            return None
        return None