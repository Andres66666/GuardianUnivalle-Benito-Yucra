# xss_defense_crypto.py
# GuardianUnivalle_Benito_Yucra/detectores/xss_defense_crypto.py
# Middleware robusto para detección y mitigación de XSS con componentes criptográficos integrados
# - Detección por patrones con pesos y saturación
# - Sanitización con bleach (si disponible)
# - Integración de HMAC-SHA256 para firmar tokens/cookies
# - SHA-256/SHA-3 para hashes de contenido
# - AES-GCM/ChaCha20-Poly1305 para cifrar cookies sensibles
# - HKDF para derivar claves
# - Argon2id para seguridad de claves derivadas
# - Registro cifrado de eventos y payloads
# xss_defense_crypto.py
# GuardianUnivalle_Benito_Yucra/detectores/xss_defense_crypto.py
# Middleware robusto para detección y mitigación de XSS con componentes criptográficos integrados
# - Detección por patrones con pesos y saturación
# - Sanitización con bleach (si disponible)
# - Integración de HMAC-SHA256 para firmar tokens/cookies
# - SHA-256/SHA-3 para hashes de contenido
# - AES-GCM/ChaCha20-Poly1305 para cifrar cookies sensibles
# - HKDF para derivar claves
# - Argon2id para seguridad de claves derivadas
# - Registro cifrado de eventos y payloads
# xss_defense_crypto.py
# GuardianUnivalle_Benito_Yucra/detectores/xss_defense_crypto.py
# Middleware robusto para detección y mitigación de XSS con componentes criptográficos integrados
# - Detección por patrones con pesos y saturación
# - Sanitización con bleach (si disponible)
# - Integración de HMAC-SHA256 para firmar tokens/cookies
# - SHA-256/SHA-3 para hashes de contenido
# - AES-GCM/ChaCha20-Poly1305 para cifrar cookies sensibles
# - HKDF para derivar claves
# - Argon2id para seguridad de claves derivadas
# - Registro cifrado de eventos y payloads

from __future__ import annotations # 
import json # Permite serializar y deserializar datos en formato JSON.
import logging  # Manejo de logs para registrar eventos, errores y actividad del middleware.
import re  # Expresiones regulares para validar, buscar o limpiar patrones en cadenas.
import math # Funciones matemáticas avanzadas (ceil, floor, log, etc.).
import base64 # Permite codificar/decodificar datos en Base64, útil para manejar claves o tokens.
import os   # Proporciona funciones del sistema operativo, como generar bytes aleatorios (os.urandom).
import time  # Funciones relacionadas al tiempo: timestamps, delays, mediciones, etc.
from typing import List, Tuple, Dict, Any   # Tipado opcional para mejorar claridad y autocompletado.
from django.utils.deprecation import MiddlewareMixin # 
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponse
from django.core.cache import cache

try:
    import bleach
    _BLEACH_AVAILABLE = True
except Exception:
    _BLEACH_AVAILABLE = False

# cryptography & argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from argon2.low_level import hash_secret_raw, Type as Argon2Type

# ----------------------------
# Logger
# ----------------------------
logger = logging.getLogger("xssdefense_crypto")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# ----------------------------
# Configuraciones criptográficas
# ----------------------------
MASTER_KEY_B64 = getattr(settings, "XSS_DEFENSE_MASTER_KEY", None)
if not MASTER_KEY_B64:
    MASTER_KEY = os.urandom(32)
else:
    try:
        MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
    except Exception:
        MASTER_KEY = MASTER_KEY_B64.encode() if isinstance(MASTER_KEY_B64, str) else MASTER_KEY_B64

AEAD_CHOICE = getattr(settings, "XSS_DEFENSE_AEAD", "AESGCM").upper()  # AESGCM o CHACHA20
ARGON2_CONFIG = getattr(settings, "XSS_DEFENSE_ARGON2", {
    "time_cost": 2,
    "memory_cost": 65536,
    "parallelism": 1,
    "hash_len": 32,
    "type": Argon2Type.ID,
})
HMAC_LABEL = b"xssdefense-hmac"
AEAD_LABEL = b"xssdefense-aead"
HASH_CHOICE = getattr(settings, "XSS_DEFENSE_HASH", "SHA256").upper()  # SHA256 o SHA3

# ----------------------------
# Configuraciones de bloqueo y cache
# ----------------------------
XSS_BLOCK_TIMEOUT = getattr(settings, "XSS_DEFENSE_BLOCK_SECONDS", 60 * 60)
XSS_COUNTER_WINDOW = getattr(settings, "XSS_DEFENSE_COUNTER_WINDOW", 60 * 5)
XSS_COUNTER_THRESHOLD = getattr(settings, "XSS_DEFENSE_COUNTER_THRESHOLD", 5)
XSS_CACHE_BLOCK_KEY_PREFIX = "xss_block:"
XSS_CACHE_COUNTER_KEY_PREFIX = "xss_count:"
XSS_DEFAULT_BACKOFF_LEVELS = getattr(settings, "XSS_DEFENSE_BACKOFF_LEVELS", [0, 60 * 15, 60 * 60, 60 * 60 * 6, 60 * 60 * 24, 60 * 60 * 24 * 7])
XSS_NORM_THRESHOLDS = {
    "HIGH": getattr(settings, "XSS_DEFENSE_NORM_HIGH", 0.2),
    "MEDIUM": getattr(settings, "XSS_DEFENSE_NORM_MED", 0.1),
    "LOW": getattr(settings, "XSS_DEFENSE_NORM_LOW", 0.05),
}

# ----------------------------
# Patrones XSS robustos 
# ----------------------------
XSS_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"<\s*script\b", re.I), "<script> directo", 0.95),
    (re.compile(r"<\s*s\s*c\s*r\s*i\s*p\s*t\b", re.I), "<script> ofuscado", 0.90),
    (re.compile(r"\b(eval|Function|setTimeout|setInterval|document\.write)\s*\(", re.I),
     "Ejecución JS dinámica", 0.88),
    (re.compile(r"\bjavascript\s*:", re.I), "URI javascript:", 0.85),
    (re.compile(r"\bdata\s*:\s*text\/html\b", re.I), "URI data:text/html", 0.82),
    (re.compile(r"\bvbscript\s*:", re.I), "URI vbscript:", 0.7),
    (re.compile(r"<\s*(iframe|embed|object|svg|math|meta)\b", re.I), "Iframe/Embed/Object/SVG/Meta", 0.88),
    (re.compile(r"<\s*img\b[^>]*\bonerror\b", re.I), "<img onerror>", 0.86),
    (re.compile(r"<\s*svg\b[^>]*\bonload\b", re.I), "SVG onload/on*", 0.84),
    (re.compile(r"\s+on[a-zA-Z]+\s*=", re.I), "Atributo evento on*", 0.80),
    (re.compile(r"<\s*(a|img|body|div|span|form|input|button)\b[^>]*on[a-zA-Z]+\s*=", re.I),
     "Elemento con evento on*", 0.82),
    (re.compile(r"\binnerHTML\s*=\s*.*[<>\"']", re.I), "Asignación innerHTML", 0.85),
    (re.compile(r"\bdocument\.getElementById\s*\(\s*.*\)\.innerHTML", re.I), "Manipulación DOM innerHTML", 0.80),
    (re.compile(r"\bJSON\.parse\(|\beval\(\s*JSON", re.I), "JSON parse/eval inseguro", 0.75),
    (re.compile(r"\bstyle\s*=\s*[\"'][^\"']*(expression\s*\(|url\s*\(\s*javascript:)", re.I), "CSS expression/url()", 0.66),
    (re.compile(r"@import\s+url\s*\(", re.I), "CSS @import vector", 0.45),
    (re.compile(r"<!\[CDATA\[|\/\/\s*<\s*!\s*\[CDATA\[", re.I), "CDATA/comentarios para evasión", 0.48),
    (re.compile(r"&#x[0-9a-fA-F]+;|&#\d+;", re.I), "Entidades HTML/encoding", 0.70),
    (re.compile(r"%3C\s*script|%3Cscript%3E", re.I), "Tags URL-encoded", 0.68),
]

SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth"]
SENSITIVE_DISCOUNT = 0.5

# ----------------------------
# Funciones criptográficas (derivación, AEAD, HMAC, hash)
# ----------------------------
# deriva una clave simétrica de 32 bytes a partir de MASTER_KEY usando Argon2 y HKDF (con fallback a HKDF directo).
def derive_key(label: bytes, context: bytes = b"") -> bytes:   # generacion de claves  
    salt = (label + context)[:16].ljust(16, b"\0") 
    try:
        raw = hash_secret_raw(secret=MASTER_KEY if isinstance(MASTER_KEY, (bytes, bytearray)) else MASTER_KEY.encode(),
                              salt=salt,
                              time_cost=ARGON2_CONFIG["time_cost"],
                              memory_cost=ARGON2_CONFIG["memory_cost"],
                              parallelism=ARGON2_CONFIG["parallelism"],
                              hash_len=ARGON2_CONFIG["hash_len"],
                              type=ARGON2_CONFIG["type"])
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(raw)
    except Exception:
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())

# ciframos la clave secreta
# cifra plaintext con AES-GCM o ChaCha20-Poly1305 y devuelve dict {alg, nonce, ciphertext}.
def aead_encrypt(plaintext: bytes, aad: bytes = b"", context: bytes = b"") -> Dict[str, bytes]: 
    key = derive_key(AEAD_LABEL, context)
    if AEAD_CHOICE == "CHACHA20":
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        return {"alg": "CHACHA20-POLY1305", "nonce": nonce, "ciphertext": ct}
    else:
        aead = AESGCM(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        return {"alg": "AES-GCM", "nonce": nonce, "ciphertext": ct}
    
# funcion para desifrado 
# descifra y verifica un payload AEAD (AES-GCM/ChaCha20) y devuelve los bytes de plaintext.
def aead_decrypt(payload: Dict[str, bytes], aad: bytes = b"", context: bytes = b"") -> bytes: 
    key = derive_key(AEAD_LABEL, context)
    alg = payload.get("alg", "AES-GCM")
    nonce = payload.get("nonce")
    ct = payload.get("ciphertext")
    if not nonce or not ct:
        raise ValueError("invalid payload for AEAD decrypt")
    if alg.startswith("CHACHA20"):
        aead = ChaCha20Poly1305(key)
        return aead.decrypt(nonce, ct, aad)
    else:
        aead = AESGCM(key)
        return aead.decrypt(nonce, ct, aad)
    
# veficacion de la fima con HMAC
# calcula un HMAC-SHA256 sobre unos datos usando una clave derivada.
def compute_hmac(data: bytes, context: bytes = b"") -> bytes:
    key = derive_key(HMAC_LABEL, context)
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

# La función verify_hmac comprueba si un tag HMAC (firma) es válido para unos datos dados usando una clave derivada del 
# sistema. Devuelve True si la verificación pasa y False si la firma no coincide. 
def verify_hmac(data: bytes, tag: bytes, context: bytes = b"") -> bool: 
    key = derive_key(HMAC_LABEL, context)
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except InvalidSignature:
        return False

# La función compute_hash toma bytes como entrada, elige entre SHA3‑256 o SHA‑256 según la constante global HASH_CHOICE, 
# calcula el resumen con la API Hash de cryptography, codifica el resultado en Base64 y lo devuelve como cadena UTF‑8.
def compute_hash(data: bytes) -> str: 
    if HASH_CHOICE == "SHA3":
        h = hashes.Hash(hashes.SHA3_256()) 
    else:
        h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return base64.b64encode(h.finalize()).decode()

# ----------------------------
# Función de saturación
# ----------------------------
SATURATION_C = getattr(settings, "XSS_DEFENSE_SATURATION_C", 1.5)
SATURATION_ALPHA = getattr(settings, "XSS_DEFENSE_SATURATION_ALPHA", 2.0)

# normaliza un puntaje numérico mediante la función sigmoide (logística). Intenta convertir las entradas 
# globales a float y devuelve el valor entre 0.0 y 1.0 calculado por la fórmula sigmoide; si ocurre cualquier excepción retorna 0.0.
def saturate_score(raw_score: float) -> float: 
    try:
        x = float(raw_score)
        alpha = float(SATURATION_ALPHA)
        c = float(SATURATION_C)
        return 1.0 / (1.0 + math.exp(-alpha * (x - c)))
    except Exception:
        return 0.0

# ----------------------------
# IP robusta
# ----------------------------
# validar si la cadena ip es una dirección IPv4 o IPv6 válida usando el módulo estándar ipaddress.
# Si ipaddress.ip_address(ip) no lanza excepción devuelve True; si ocurre cualquier excepción devuelve False.
def _is_valid_ip(ip: str) -> bool: 
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False
# extrae la IP del cliente desde los encabezados de la petición HTTP (preferencia X-Forwarded-For, 
# luego varios encabezados alternativos, y finalmente REMOTE_ADDR). Devuelve la primera IP encontrada o cadena vacía si no hay ninguna.
def get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")  # 
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
    for h in ("HTTP_X_REAL_IP", "HTTP_CF_CONNECTING_IP", "HTTP_CLIENT_IP"):
        v = request.META.get(h)
        if v and _is_valid_ip(v):
            return v
    return request.META.get("REMOTE_ADDR") or ""

# ----------------------------
# Extraer payload
# ---------------------------- 
#extraer del request un mapa (dict) con el cuerpo de la petición siguiendo este orden:
def extract_body_as_map(request) -> Dict[str, Any]:  # Extrae body como dict desde request
    try:
        ct = request.META.get("CONTENT_TYPE", "")  # Obtiene Content-Type del header HTTP
        if "application/json" in ct:  # Si es JSON
            raw = request.body.decode("utf-8") or "{}"  # Decodifica body UTF-8, default "{}" si vacío
            try:
                data = json.loads(raw)  # Parsea JSON
                if isinstance(data, dict):  # Si resultado es dict
                    return data  # Devuelve directamente
                return {"raw": raw}  # Si no es dict (lista), envuelve en clave 'raw'
            except Exception:  # Si JSON parsing falla
                return {"raw": raw}  # Devuelve raw como fallback
        try:
            post = request.POST.dict()  # Intenta extraer datos de formulario POST
            if post:  # Si hay datos POST
                return post  # Devuelve dict de formulario
        except Exception:  # Si POST parse falla
            pass  # Continúa al siguiente intento
        raw = request.body.decode("utf-8", errors="ignore")  # Decodifica body ignorando errores
        if raw:  # Si hay contenido
            return {"raw": raw}  # Devuelve como fallback raw
    except Exception:  # Si falla todo
        pass  # Continúa
    return {}  # Devuelve dict vacío como fallback final

# ----------------------------
# Detect XSS en valor
# ----------------------------
# analiza un valor buscando patrones XSS, calcula un score y devuelve (score, descripciones, patrones).
def detect_xss_in_value(value: str, is_sensitive: bool = False) -> Tuple[float, List[str], List[str]]:  # Detecta XSS en un valor y retorna (score, descripciones, patrones)
    if not value:  # Si el valor está vacío, retorna sin detecciones
        return 0.0, [], []
    score_total = 0.0  # Acumula puntaje de detección
    descripcion = []  # Lista de descripciones de firmas encontradas
    matches = []  # Patrones que coincidieron
    value = value.lower().strip()  # Normaliza a minúsculas y elimina espacios alrededor
    if _BLEACH_AVAILABLE:  # Si bleach está instalado, sanitiza y penaliza cambios
        cleaned = bleach.clean(value, strip=True)  # Limpia el valor con bleach
        if cleaned != value:  # Si bleach modificó el contenido, sumamos puntaje
            score_total += 0.5  # Penalización por alteración de sanitización
            descripcion.append("Contenido alterado por sanitización (bleach)")  # Añade descripción
    for patt, msg, weight in XSS_PATTERNS:  # Itera patrones XSS con su peso
        occ = len(patt.findall(value))  # Cuenta ocurrencias del patrón
        if occ > 0:  # Si hay ocurrencias
            added = sum(weight * (0.5 ** i) for i in range(occ))  # Aplica decaimiento por múltiples ocurrencias
            if is_sensitive:  # Si el campo es sensible, aplica descuento
                added *= SENSITIVE_DISCOUNT  # Multiplica por factor de descuento
            score_total += added  # Acumula puntaje
            descripcion.append(msg)  # Añade mensaje descriptivo del patrón
            matches.append(patt.pattern)  # Guarda el patrón coincidente
    return round(score_total, 3), descripcion, matches  # Retorna puntaje redondeado y listas


# ----------------------------
# Conversión a probabilidad
# ----------------------------
# convierte un peso a probabilidad usando 1 - exp(-w) y aplica clamp.
def weight_to_prob(w: float) -> float: 
    try:
        q = 1.0 - math.exp(-max(w, 0.0))  # Convierte peso a probabilidad (mapa exponencial)
        return min(max(q, 0.0), 0.999999)  # Clamp para evitar 1.0 exacto
    except Exception:  # En caso de error numérico, fallback conservador
        return min(max(w, 0.0), 0.999999)  # Retorna valor clamped
    
# combina probabilidades independientes y retorna la probabilidad de al menos un match.
def combine_probs(qs: List[float]) -> float:
    prod = 1.0  # Producto de (1 - q_i)
    for q in qs: # recorrido de q 
        prod *= (1.0 - q)  # Multiplica probabilidades complementarias
    return 1.0 - prod  # Probabilidad combinada de al menos una detección

# ----------------------------
# Firmar/cifrar cookies (integración cripto)
# ----------------------------
# firma un valor (HMAC-SHA256) y devuelve "valor.tag_base64".
def sign_cookie_value(value: str, context: bytes = b"") -> str:
    """Firma un valor de cookie con HMAC-SHA256 para evitar alteraciones por XSS."""  # Docstring: propósito de la función
    data = value.encode("utf-8")  # Codifica el valor a bytes UTF-8
    tag = compute_hmac(data, context)  # Calcula HMAC sobre los datos
    return f"{value}.{base64.b64encode(tag).decode()}"  # Retorna valor.sello en base64

# verifica la firma de una cookie y retorna el valor original o lanza ValueError.
def verify_cookie_signature(signed_value: str, context: bytes = b"") -> str:
    """Verifica la firma de una cookie y retorna el valor original si es válido."""  # Docstring
    try:
        value, tag_b64 = signed_value.rsplit(".", 1)  # Separa valor y tag (último punto)
        tag = base64.b64decode(tag_b64)  # Decodifica tag base64
        if verify_hmac(value.encode("utf-8"), tag, context):  # Verifica HMAC
            return value  # Retorna valor si firma válida
        else:
            raise ValueError("Invalid signature")  # Lanza error si firma inválida
    except Exception:
        raise ValueError("Invalid signed cookie")  # Normaliza excepción para caller
    
# cifra un valor de cookie con AEAD y devuelve su representación serializada en Base64.
def encrypt_cookie_value(value: str, context: bytes = b"") -> str:
    """Cifra un valor de cookie sensible con AEAD."""  # Docstring
    enc = aead_encrypt(value.encode("utf-8"), context=context)  # Cifra con AEAD
    return base64.b64encode(json.dumps(enc).encode()).decode()  # Serializa y codifica en base64

# decodifica y descifra una cookie cifrada y devuelve el texto plano.
def decrypt_cookie_value(encrypted_value: str, context: bytes = b"") -> str:
    """Descifra un valor de cookie."""  # Docstring
    try:
        enc = json.loads(base64.b64decode(encrypted_value))  # Decodifica y parsea el payload cifrado
        plaintext = aead_decrypt(enc, context=context)  # Descifra con AEAD
        return plaintext.decode("utf-8")  # Retorna texto decodificado
    except Exception:
        raise ValueError("Invalid encrypted cookie")  # Lanza error si falla

# ----------------------------
# Funciones de cache para bloqueo (similar a SQLi, pero con prefijo XSS_)
# ----------------------------
# incrementa el nivel de backoff para una IP y la marca como bloqueada en cache con timeout
def cache_block_ip_with_backoff(ip: str):
    if not ip:  # Si no hay IP, no hace nada
        return 0, 0
    level_key = f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}:level"  # Clave para nivel de backoff
    level = cache.get(level_key, 0) or 0  # Lee nivel actual o 0
    level = int(level) + 1  # Incrementa nivel
    cache.set(level_key, level, timeout=60 * 60 * 24 * 7)  # Guarda nivel con TTL semanal
    durations = XSS_DEFAULT_BACKOFF_LEVELS  # Niveles de backoff configurados
    idx = min(level, len(durations) - 1)  # Índice seguro en la lista de duraciones
    timeout = durations[idx]  # Tiempo de bloqueo elegido
    cache.set(f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}", True, timeout=timeout)  # Marca IP bloqueada en cache
    return level, timeout  # Retorna nivel y timeout aplicados

# comprueba en cache si una IP está bloqueada.
def is_ip_blocked(ip: str) -> bool:
    if not ip:  # Si no hay IP, no está bloqueada
        return False
    return bool(cache.get(f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}"))  # Retorna estado booleano de bloqueo

# incrementa y devuelve el contador de intentos por IP en cache (window TTL)
def incr_ip_counter(ip: str) -> int:
    if not ip:  # Si no hay IP, no incrementa
        return 0
    key = f"{XSS_CACHE_COUNTER_KEY_PREFIX}{ip}"  # Clave contador por IP
    current = cache.get(key, 0)  # Lee contador actual
    try:
        current = int(current)  # Intenta convertir a int
    except Exception:
        current = 0  # Fallback a 0 si lectura inválida
    current += 1  # Incrementa contador
    cache.set(key, current, timeout=XSS_COUNTER_WINDOW)  # Guarda contador con ventana TTL
    return current  # Retorna nuevo valor del contador

# ----------------------------
# Registro cifrado de eventos (similar a SQLi para asegurar registro)
# ----------------------------
# registra un evento XSS cifrando el payload si existe y almacenando el evento en cache.
def record_xss_event(event: dict) -> None: 
    try:
        ts = int(time.time())  # Timestamp del evento
        # cifrar payload si existe
        if "payload" in event and event["payload"]:
            try:
                ctx = f"{event.get('ip','')}-{ts}".encode()  # Contexto único para cifrado/hmac
                enc = aead_encrypt(json.dumps(event["payload"], ensure_ascii=False).encode("utf-8"), context=ctx)  # Cifra payload
                htag = compute_hmac(enc["ciphertext"], context=ctx)  # Calcula HMAC sobre ciphertext
                event["_payload_encrypted"] = {  # Inserta estructura cifrada en evento
                    "alg": enc["alg"],  # Algoritmo AEAD usado
                    "nonce": base64.b64encode(enc["nonce"]).decode(),  # Nonce en base64
                    "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),  # Ciphertext en base64
                    "hmac": base64.b64encode(htag).decode(),  # HMAC en base64
                }
                del event["payload"]  # Elimina plaintext para no almacenarlo
            except Exception:
                # si falla, simplemente no incluimos payload
                event.pop("payload", None)  # Elimina payload si quedó
        key = f"xss_event:{ts}:{event.get('ip', '')}"  # Clave para almacenar evento en cache
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)  # Guarda evento serializado por 1 día
    except Exception:
        logger.exception("record_xss_event failed")  # Log de excepción si falla registro

# ----------------------------
# Middleware XSS con cripto integrado (ajustado para registro similar a SQLi y chequeo de bloqueo inicial)
# ----------------------------
# middleware que detecta XSS en la petición, registra el evento cifrado y aplica políticas de monitor/alert/block al request.
class XSSDefenseCryptoMiddleware(MiddlewareMixin):
    def process_request(self, request):
        client_ip = get_client_ip(request)  # Obtiene IP cliente desde request

        # Chequear bloqueo inicial 
        if is_ip_blocked(client_ip):  # Si IP está bloqueada persistentemente
            warning_message = (  # Mensaje de advertencia para el cliente bloqueado
                "Acceso denegado. Su dirección IP y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[XSSBlock:Persistent] IP={client_ip} - Intento persistente de acceso bloqueado. Mensaje enviado.")  # Log de bloqueo persistente
            return HttpResponseForbidden(warning_message)  # Devuelve 403 con mensaje

        trusted_ips: List[str] = getattr(settings, "XSS_DEFENSE_TRUSTED_IPS", [])  # Lista de IPs confiables
        if client_ip in trusted_ips:  # Si la IP está en trusted, omite comprobaciones
            return None
        excluded_paths: List[str] = getattr(settings, "XSS_DEFENSE_EXCLUDED_PATHS", [])  # Rutas excluidas
        if any(request.path.startswith(p) for p in excluded_paths):  # Si la ruta está excluida, omitir
            return None

        data = extract_body_as_map(request)  # Extrae body como mapa/dict
        qs = request.META.get("QUERY_STRING", "")  # Query string raw
        if qs:
            data["_query_string"] = qs  # Añade query string al mapa de datos
        if not data:  # Si no hay datos, no continúa detección
            return None

        total_score = 0.0  # Puntaje bruto acumulado
        all_descriptions: List[str] = []  # Todas las descripciones encontradas
        global_prob_list: List[float] = []  # Lista de probabilidades por match
        payload_summary = []  # Resumen de campos detectados

        if isinstance(data, dict):  # Si data es dict, iterar campos
            for key, value in data.items():
                is_sensitive = key.lower() in SENSITIVE_FIELDS  # Marca si campo sensible
                vtext = value  # Valor a procesar
                if isinstance(value, (dict, list)):  # Si es estructura anidada, serializar
                    try:
                        vtext = json.dumps(value, ensure_ascii=False)  # Serializa JSON para análisis
                    except Exception:
                        vtext = str(value)  # Fallback a str si falla
                else:
                    vtext = str(value or "")  # Asegura string (no None)
                s, descs, matches = detect_xss_in_value(vtext, is_sensitive)  # Detecta XSS en el valor
                total_score += s  # Acumula puntaje
                all_descriptions.extend(descs)  # Agrega descripciones
                for m in matches:
                    q = weight_to_prob(s)  # Convierte peso a probabilidad
                    global_prob_list.append(q)  # Añade a lista global
                if s > 0:
                    payload_summary.append({"field": key, "snippet": vtext[:300], "sensitive": is_sensitive})  # Resumen del payload si detectado
        else:  # Si data no es dict (raw), tratar como texto
            raw = str(data)  # Forzar a string
            s, descs, matches = detect_xss_in_value(raw)  # Detectar en raw
            total_score += s
            all_descriptions.extend(descs)
            for m in matches:
                q = weight_to_prob(s)
                global_prob_list.append(q)
            if s > 0:
                payload_summary.append({"field": "raw", "snippet": raw[:500], "sensitive": False})  # Resumen para raw

        if total_score == 0:  # Si no hay hallazgos, terminar
            return None

        p_attack = combine_probs(global_prob_list) if global_prob_list else 0.0  # Probabilidad combinada de ataque
        s_norm = saturate_score(total_score)  # Normaliza puntaje con sigmoide
        url = request.build_absolute_uri()  # URL completa de la petición
        payload_for_request = json.dumps(payload_summary, ensure_ascii=False)[:2000]  # Limita tamaño del payload para logs

        logger.warning(
            "[XSSDetect] IP=%s URL=%s ScoreRaw=%.3f ScoreNorm=%.3f Prob=%.3f Desc=%s",
            client_ip, url, total_score, s_norm, p_attack, all_descriptions  # Log de detección con métricas
        )

        # Registrar el evento de manera cifrada para auditoría
        try:
            record_xss_event({
                "ts": int(time.time()),  # Timestamp
                "ip": client_ip,  # IP detectada
                "score_raw": total_score,  # Puntaje bruto
                "score_norm": s_norm,  # Puntaje normalizado
                "prob": p_attack,  # Probabilidad combinada
                "desc": all_descriptions,  # Descripciones
                "url": url,  # URL afectada
                "payload": payload_summary,  # Payload (se cifra dentro de record_xss_event)
            })
        except Exception:
            logger.exception("failed to record XSS event")  # Log si falla el registro

        # Asignar información de ataque al request para uso posterior
        request.xss_attack_info = {
            "ip": client_ip,  # IP del atacante
            "tipos": ["XSS"],  # Tipo de amenaza
            "descripcion": all_descriptions,  # Descripciones encontradas
            "payload": payload_for_request,  # Payload resumido
            "score_raw": total_score,  # Puntaje bruto
            "score_norm": s_norm,  # Puntaje normalizado
            "prob": p_attack,  # Probabilidad
            "url": url,  # URL
        }

        # Políticas de bloqueo (similar a SQLi, pero ajustadas para XSS)
        if s_norm >= XSS_NORM_THRESHOLDS["HIGH"]:  # Umbral alto -> bloqueo inmediato
            level, timeout = cache_block_ip_with_backoff(client_ip)  # Incrementa backoff y bloquea
            logger.error(f"[XSSBlock] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} URL={url}")  # Log de bloqueo
            request.xss_attack_info.update({"blocked": True, "action": "block", "block_timeout": timeout, "block_level": level})  # Actualiza info en request
            # Setear flag para bloqueo
            request.xss_block = True  # Flag de bloqueo
            request.xss_block_response = HttpResponseForbidden("Request blocked by XSS defense")  # Respuesta preparada de bloqueo
            return None
        elif s_norm >= XSS_NORM_THRESHOLDS["MEDIUM"]:  # Umbral medio -> alertas y counters
            logger.warning(f"[XSSAlert] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} - applying counter/challenge")  # Log de alerta
            count = incr_ip_counter(client_ip)  # Incrementa contador por IP
            request.xss_attack_info.update({"blocked": False, "action": "alert", "counter": count})  # Actualiza info del request
            if count >= XSS_COUNTER_THRESHOLD:  # Si contador supera umbral, bloquear
                level, timeout = cache_block_ip_with_backoff(client_ip)  # Bloqueo con backoff
                cache.set(f"{XSS_CACHE_COUNTER_KEY_PREFIX}{client_ip}", 0, timeout=XSS_COUNTER_WINDOW)  # Reset del contador
                logger.error(f"[XSSAutoBlock] IP={client_ip} reached counter={count} -> blocking for {timeout}s")  # Log auto-block
                request.xss_attack_info.update({"blocked": True, "action": "auto_block", "block_timeout": timeout, "block_level": level})  # Actualiza info
                # Setear flag para bloqueo
                request.xss_block = True
                request.xss_block_response = HttpResponseForbidden("Request blocked by XSS defense (auto block)")  # Respuesta de bloqueo automática
                return None
            if getattr(settings, "XSS_DEFENSE_USE_CHALLENGE", False):  # Si está configurado challenge
                # Setear flag para challenge
                request.xss_challenge = True  # Flag challenge
                request.xss_challenge_response = HttpResponse("Challenge required", status=403)  # Respuesta challenge
                request.xss_challenge_response["X-XSS-Challenge"] = "captcha"  # Header indicando challenge
                return None
            return None
        elif s_norm >= XSS_NORM_THRESHOLDS["LOW"]:  # Umbral bajo -> solo monitoreo
            logger.info(f"[XSSMonitor] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} - monitored")  # Log de monitoreo
            request.xss_attack_info.update({"blocked": False, "action": "monitor"})  # Marca como monitoreado
            return None
        return None  # Default: no acción adicional


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

Notas sobre implementación de algoritmos de seguridad:
    - HMAC-SHA256: Usado para firmar tokens/cookies (sign_cookie_value, verify_cookie_signature).
    - SHA-256/SHA-3: Usado para hashes de contenido (compute_hash).
    - AES-GCM/ChaCha20-Poly1305: Usado para cifrar cookies sensibles (encrypt_cookie_value, decrypt_cookie_value).
    - HKDF: Usado para derivar claves seguras (derive_key).
    - Argon2id: Usado para derivar claves con resistencia a ataques de fuerza bruta (derive_key).
    - TLS 1.3: Recomendado para configurar en el servidor web (e.g., Nginx/Apache) para proteger datos en tránsito.
      Ejemplo configuración Nginx:
      server {
          listen 443 ssl http2;
          ssl_protocols TLSv1.3;
          ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
          # ... otras configuraciones SSL
      }
      Esto asegura que las comunicaciones sean seguras y eviten que XSS robe datos en tránsito.

Para usar en producción:
    - Configura XSS_DEFENSE_MASTER_KEY en settings.py como base64 de una clave segura de 32 bytes.
    - Ajusta umbrales y configuraciones según necesidades.
    - Integra con CSP (Content Security Policy) en headers de respuesta para mayor protección.
"""