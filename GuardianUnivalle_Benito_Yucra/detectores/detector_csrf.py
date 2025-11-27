from __future__ import annotations  # Habilita anotaciones de tipos post‑ponibles (PEP 563) para compatibilidad de tipado.
import secrets  # Generación de tokens/valores aleatorios criptográficamente seguros.
import logging  # Registro de eventos, errores y mensajes de depuración.
import re  # Expresiones regulares para buscar/patrones en cadenas.
import json  # Serializar/deserializar JSON.
import base64  # Codificar/decodificar en Base64.
import os  # Operaciones del sistema (e.g., os.urandom para entropía).
import time  # Funciones relacionadas con tiempo (timestamps, sleep, etc.).
from typing import List, Dict, Any  # Tipos para anotaciones estáticas (listas, diccionarios, any).
from urllib.parse import urlparse  # Parseo de URLs (usado para Origin/Referer/Host).
from django.conf import settings  # Acceso a configuraciones de Django (settings.py).
from django.utils.deprecation import MiddlewareMixin  # Clase base para middlewares compatibles con Django.
from django.core.cache import cache  # Caché de Django para almacenar eventos/contadores.

# cryptography & argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # AEAD: AES-GCM y ChaCha20-Poly1305 para cifrado autenticado.
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac  # Hashes (SHA256/SHA3) y HMAC para firmas.
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF para derivación de claves.
from cryptography.exceptions import InvalidSignature  # Excepción lanzada cuando falla verificación HMAC.
from argon2.low_level import hash_secret_raw, Type as Argon2Type  # Argon2id (hash_secret_raw) para derivación resistente a fuerza bruta.


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
    (re.compile(r"eval\s*\$", re.I), "eval() en payload", 1.0),
    (re.compile(r"document\.cookie", re.I), "Acceso a cookie en payload", 0.9),
    (re.compile(r"innerHTML\s*=", re.I), "Manipulación DOM innerHTML", 0.8),
    (re.compile(r"XMLHttpRequest", re.I), "XHR en payload", 0.7),
    (re.compile(r"fetch\s*\$", re.I), "fetch() en payload", 0.7),
    (re.compile(r"&#x[0-9a-fA-F]+;", re.I), "Entidades HTML en payload", 0.6),
    (re.compile(r"%3Cscript", re.I), "Script URL-encoded en payload", 0.8),
    (re.compile(r"on\w+\s*=", re.I), "Eventos on* en payload", 0.7),
    (re.compile(r"alert\s*\$", re.I), "alert() en payload (prueba)", 0.5),
]

# ----------------------------
# Configuraciones criptográficas (similar a XSS/SQLi)
# ----------------------------
MASTER_KEY_B64 = getattr(settings, "CSRF_DEFENSE_MASTER_KEY", None)
if not MASTER_KEY_B64:
    MASTER_KEY = os.urandom(32)
else:
    try:
        MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
    except Exception:
        MASTER_KEY = MASTER_KEY_B64.encode() if isinstance(MASTER_KEY_B64, str) else MASTER_KEY_B64

AEAD_CHOICE = getattr(settings, "CSRF_DEFENSE_AEAD", "AESGCM").upper()  # AESGCM o CHACHA20
ARGON2_CONFIG = getattr(settings, "CSRF_DEFENSE_ARGON2", {
    "time_cost": 2,
    "memory_cost": 65536,
    "parallelism": 1,
    "hash_len": 32,
    "type": Argon2Type.ID,
})
HMAC_LABEL = getattr(settings, "CSRF_HMAC_LABEL", b"csrfdefense-hmac")
AEAD_LABEL = getattr(settings, "CSRF_AEAD_LABEL", b"csrfdefense-aead")
HASH_CHOICE = getattr(settings, "CSRF_DEFENSE_HASH", "SHA256").upper()  # SHA256 o SHA3

# ----------------------------
# Funciones criptográficas (derivación, AEAD, HMAC, hash)
# ----------------------------
def derive_key(label: bytes, context: bytes = b"") -> bytes:
    # deriva una clave simétrica de 32 bytes a partir de MASTER_KEY usando Argon2 (si disponible)
    # y luego HKDF; si falla Argon2, usa HKDF directo sobre MASTER_KEY como fallback.
    salt = (label + context)[:16].ljust(16, b"\0")  # Construye un salt de 16 bytes a partir de label+context (truncando o rellenando con NULs)
    try:
        # Ejecuta Argon2 (hash_secret_raw) sobre MASTER_KEY con el salt y la configuración ARGON2_CONFIG
        raw = hash_secret_raw(
            secret=MASTER_KEY if isinstance(MASTER_KEY, (bytes, bytearray)) else MASTER_KEY.encode(),  # Asegura bytes para la secret
            salt=salt,
            time_cost=ARGON2_CONFIG["time_cost"],  # parámetro de tiempo Argon2
            memory_cost=ARGON2_CONFIG["memory_cost"],  # parámetro de memoria Argon2
            parallelism=ARGON2_CONFIG["parallelism"],  # paralelismo Argon2
            hash_len=ARGON2_CONFIG["hash_len"],  # longitud del hash bruto producido
            type=ARGON2_CONFIG["type"]  # tipo Argon2 (p.ej. Argon2id)
        )
        # Crea un HKDF usando SHA256 para derivar la clave final de 32 bytes a partir del raw
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(raw)  # Deriva y retorna la clave final
    except Exception:
        # Si Argon2 falla por cualquier motivo, usar HKDF directamente sobre MASTER_KEY como fallback
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())

# Función: cifra y autentica 'plaintext' usando AEAD (AES-GCM por defecto o ChaCha20-Poly1305 si está configurado).
def aead_encrypt(plaintext: bytes, aad: bytes = b"", context: bytes = b"") -> Dict[str, bytes]:
    # Deriva una clave simétrica específica para AEAD usando la etiqueta AEAD_LABEL y el contexto opcional.
    key = derive_key(AEAD_LABEL, context)
    # Si la elección de AEAD es CHACHA20, usar ChaCha20-Poly1305
    if AEAD_CHOICE == "CHACHA20":
        # Inicializa el cifrador ChaCha20-Poly1305 con la clave derivada
        aead = ChaCha20Poly1305(key)
        # Genera un nonce/iv de 12 bytes aleatorios
        nonce = os.urandom(12)
        # Cifra y autentica el plaintext, incluyendo AAD si se pasó
        ct = aead.encrypt(nonce, plaintext, aad)
        # Retorna un diccionario con el algoritmo, nonce y ciphertext (bytes)
        return {"alg": "CHACHA20-POLY1305", "nonce": nonce, "ciphertext": ct}
    else:
        # Por defecto usa AES-GCM
        aead = AESGCM(key)  # Inicializa AES-GCM con la clave derivada
        nonce = os.urandom(12)  # Genera nonce de 12 bytes (recomendado para AES-GCM en este código)
        ct = aead.encrypt(nonce, plaintext, aad)  # Cifra y autentica plaintext con AAD opcional
        # Retorna dict con algoritmo, nonce y ciphertext
        return {"alg": "AES-GCM", "nonce": nonce, "ciphertext": ct}

def aead_decrypt(payload: Dict[str, bytes], aad: bytes = b"", context: bytes = b"") -> bytes:
    #  Descifra y verifica un payload AEAD (AES-GCM o ChaCha20-Poly1305) usando una clave derivada.
    #   - payload: diccionario con keys "alg", "nonce", "ciphertext" (bytes).
    #   - aad: Additional Authenticated Data opcional usado en la verificación.
    #   - context: contexto para derivar la clave (se incluye en derive_key).
    key = derive_key(AEAD_LABEL, context)  # Deriva la clave AEAD específica usando la etiqueta AEAD_LABEL y el contexto.
    alg = payload.get("alg", "AES-GCM")  # Obtiene el algoritmo indicado en el payload; por defecto "AES-GCM".
    nonce = payload.get("nonce")  # Extrae el nonce/IV del payload (debe ser bytes).
    ct = payload.get("ciphertext")  # Extrae el ciphertext (bytes) del payload.
    if not nonce or not ct:
        # Si falta nonce o ciphertext, el payload no es válido -> lanza excepción.
        raise ValueError("invalid payload for AEAD decrypt")
    if alg.startswith("CHACHA20"):
        # Si el algoritmo comienza con "CHACHA20", usar ChaCha20-Poly1305 para descifrar/validar.
        aead = ChaCha20Poly1305(key)  # Inicializa el objeto de descifrado con la clave derivada.
        return aead.decrypt(nonce, ct, aad)  # Descifra y devuelve los bytes de plaintext (verifica tag internamente).
    else:
        # Para cualquier otro caso (por defecto AES-GCM), usar AESGCM.
        aead = AESGCM(key)  # Inicializa AES-GCM con la clave derivada.
        return aead.decrypt(nonce, ct, aad)  # Descifra y devuelve los bytes de plaintext (verifica tag internamente).
    
#  funciones HMAC y hash usadas para firmar/verificar datos y obtener un resumen criptográfico (digest).
def compute_hmac(data: bytes, context: bytes = b"") -> bytes:
    # Deriva la clave HMAC específica usando la etiqueta HMAC_LABEL y el contexto 
    key = derive_key(HMAC_LABEL, context)
    # Crea un objeto HMAC configurado con SHA256 y la clave derivada
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    # Añade los datos al HMAC (actualiza el estado interno)
    h.update(data)
    # Finaliza el cálculo y retorna el tag HMAC en bytes
    return h.finalize()

def verify_hmac(data: bytes, tag: bytes, context: bytes = b"") -> bool:
    # Deriva la misma clave HMAC usada para generar el tag
    key = derive_key(HMAC_LABEL, context)
    # Crea un objeto HMAC con la clave derivada para verificar
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    # Añade los datos que deben corresponder al tag
    h.update(data)
    try:
        # Intenta verificar el tag; si no coincide lanzará InvalidSignature
        h.verify(tag)
        # Si no hubo excepción, la verificación pasó -> True
        return True
    except InvalidSignature:
        # Si la verificación falló, captura y retorna False
        return False

def compute_hash(data: bytes) -> str:
    # Selecciona SHA3-256 si HASH_CHOICE == "SHA3", sino SHA-256
    if HASH_CHOICE == "SHA3":
        h = hashes.Hash(hashes.SHA3_256())
    else:
        h = hashes.Hash(hashes.SHA256())
    # Alimenta el objeto hash con los datos
    h.update(data)
    # Finaliza el hash, codifica el digest en Base64 y lo retorna como str UTF-8
    return base64.b64encode(h.finalize()).decode()

# ----------------------------
# Funciones para tokens CSRF firmados/cifrados
# ----------------------------
# Firma un token CSRF con HMAC-SHA256 y devuelve el token concatenado con el tag en Base64.
def sign_csrf_token(token: str, context: bytes = b"") -> str:
    """Firma un token CSRF con HMAC-SHA256 para evitar alteraciones."""
    # Codifica el token de str a bytes UTF-8 para poder calcular HMAC
    data = token.encode("utf-8")
    # Calcula el HMAC sobre los bytes del token usando la clave derivada (compute_hmac devuelve bytes)
    tag = compute_hmac(data, context)
    # Codifica el tag en base64, lo decodifica a str y concatena "token.tag_b64" para retornar
    return f"{token}.{base64.b64encode(tag).decode()}"

# Verifica la firma de un token CSRF firmado con sign_csrf_token y retorna el token original si es válido.
def verify_csrf_token_signature(signed_token: str, context: bytes = b"") -> str:
    """Verifica la firma de un token CSRF y retorna el token original si es válido."""
    try:
        # Separa el token y el tag codificado en Base64 por el último punto
        token, tag_b64 = signed_token.rsplit(".", 1)
        # Decodifica el tag desde Base64 a bytes
        tag = base64.b64decode(tag_b64)
        # Verifica el HMAC usando la misma clave/contexto; verify_hmac devuelve True si coincide
        if verify_hmac(token.encode("utf-8"), tag, context):
            # Si la verificación pasa, retorna el token original (sin el tag)
            return token
        else:
            # Si la firma no coincide, lanza una excepción controlada
            raise ValueError("Invalid signature")
    except Exception:
        # Normaliza cualquier error como token firmado inválido
        raise ValueError("Invalid signed CSRF token")

#  Cifra un token CSRF usando AEAD (aead_encrypt) y devuelve una representación serializada en Base64.
def encrypt_csrf_token(token: str, context: bytes = b"") -> str:
    """Cifra un token CSRF sensible con AEAD."""
    # Cifra el token (bytes) con AEAD; enc es un dict con keys alg, nonce, ciphertext (bytes)
    enc = aead_encrypt(token.encode("utf-8"), context=context)
    # Serializa el dict a JSON, lo codifica a bytes y lo convierte a Base64 para retorno seguro como str
    return base64.b64encode(json.dumps(enc).encode()).decode()

#  Descifra un token CSRF previamente cifrado por encrypt_csrf_token y retorna el texto plano.
def decrypt_csrf_token(encrypted_token: str, context: bytes = b"") -> str:
    """Descifra un token CSRF."""
    try:
        # Decodifica Base64 a bytes y parsea el JSON para obtener el dict con alg/nonce/ciphertext
        enc = json.loads(base64.b64decode(encrypted_token))
        # Descifra usando aead_decrypt con el mismo contexto para obtener bytes plaintext
        plaintext = aead_decrypt(enc, context=context)
        # Decodifica bytes a str UTF-8 y retorna
        return plaintext.decode("utf-8")
    except Exception:
        # Normaliza cualquier fallo de descifrado como token cifrado inválido
        raise ValueError("Invalid encrypted CSRF token")


# ----------------------------
# Registro cifrado de eventos (similar a XSS/SQLi) - CON LOGS PARA CIFRADO Y DESCIFRADO
# ----------------------------
def record_csrf_event(event: dict) -> None:
    # Registra un evento CSRF en la caché. Si el evento contiene un payload lo cifra con AEAD
    # (derivando contexto a partir de la IP y timestamp), guarda la versión cifrada en la
    # estructura del evento y elimina el plaintext antes de persistir. También realiza pruebas
    # opcionales de cifrado/descifrado cuando no hay payload real y registra mensajes en el logger.
    try:
        ts = int(time.time())  # timestamp actual (segundos desde epoch)
        # Asegurar que URL siempre se registre (fallback si build_absolute_uri falla)
        if "url" not in event or not event["url"]:
            event["url"] = "unknown"  # establecer valor por defecto si no hay URL
            logger.warning(f"[CSRFDefense:Crypto] URL faltante en evento, usando fallback 'unknown' (IP={event.get('ip')})")
        
        # cifrar payload si existe y no está vacío
        if "payload" in event and event["payload"] and event["payload"] != "[]":
            try:
                # construir contexto único para derivación de claves: "IP-timestamp"
                ctx = f"{event.get('ip','')}-{ts}".encode()
                # serializar payload a bytes (JSON) y cifrar con AEAD usando el contexto
                enc = aead_encrypt(json.dumps(event["payload"], ensure_ascii=False).encode("utf-8"), context=ctx)
                # calcular HMAC sobre el ciphertext para integridad adicional usando el mismo contexto
                htag = compute_hmac(enc["ciphertext"], context=ctx)
                # almacenar la representación cifrada y codificada en Base64 en el evento
                event["_payload_encrypted"] = {
                    "alg": enc["alg"],  # algoritmo usado (AES-GCM o CHACHA20-POLY1305)
                    "nonce": base64.b64encode(enc["nonce"]).decode(),  # nonce codificado en Base64
                    "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),  # ciphertext en Base64
                    "hmac": base64.b64encode(htag).decode(),  # tag HMAC en Base64
                }
                del event["payload"]  # eliminar payload en claro para no almacenarlo
                logger.info(f"[CSRFDefense:Crypto] CIFRADO EXITOSO: Payload cifrado para IP {event.get('ip')} (alg={enc['alg']}, len_cipher={len(enc['ciphertext'])})")
            except Exception as e:
                # en caso de error durante el cifrado, registrar el fallo
                logger.error(f"[CSRFDefense:Crypto] CIFRADO FALLÓ: Error cifrando payload para IP {event.get('ip')}: {e}")
                # Mantener payload sin cifrar para registro (solo en desarrollo; en producción podría eliminarse)
                logger.warning(f"[CSRFDefense:Crypto] Manteniendo payload sin cifrar para registro (desarrollo)")
        else:
            # No hay payload real para cifrar
            logger.debug(f"[CSRFDefense:Crypto] No hay payload para cifrar en evento (IP={event.get('ip')}) - CIFRADO NO EJECUTADO")
            # Para pruebas: cifrar y descifrar un payload de prueba para validar la configuración de cifrado
            try:
                test_payload = {"test": "prueba_csrf"}  # payload de prueba
                ctx = f"{event.get('ip','')}-{ts}".encode()  # mismo esquema de contexto
                enc = aead_encrypt(json.dumps(test_payload, ensure_ascii=False).encode("utf-8"), context=ctx)  # cifrar prueba
                logger.info(f"[CSRFDefense:Crypto] CIFRADO DE PRUEBA EXITOSO: Payload de prueba cifrado (alg={enc['alg']}, len_cipher={len(enc['ciphertext'])})")
                # Probar descifrado inmediato con el mismo contexto
                decrypted = aead_decrypt(enc, context=ctx)
                decrypted_data = json.loads(decrypted.decode("utf-8"))  # parsear JSON descifrado
                if decrypted_data == test_payload:
                    # si la prueba coincide, registrar éxito
                    logger.info(f"[CSRFDefense:Crypto] DESCIFRADO DE PRUEBA EXITOSO: Payload descifrado correctamente")
                else:
                    # si los datos no coinciden, registrar error
                    logger.error(f"[CSRFDefense:Crypto] DESCIFRADO DE PRUEBA FALLÓ: Datos no coinciden")
            except Exception as e:
                # registrar cualquier fallo en la prueba de cifrado/descifrado
                logger.error(f"[CSRFDefense:Crypto] CIFRADO/DESCIFRADO DE PRUEBA FALLÓ: {e}")
        
        # construir clave única para cache usando timestamp e IP
        key = f"csrf_event:{ts}:{event.get('ip', '')}"
        # almacenar evento (JSON) en la caché por 24 horas
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)
        # log de depuración con información de almacenamiento
        logger.debug(f"[CSRFDefense:Crypto] Evento registrado en cache exitosamente (key={key}, url={event.get('url')}, payload_present={bool(event.get('_payload_encrypted'))})")
    except Exception as e:
        # captura cualquier excepción inesperada durante el proceso y la registra
        logger.error(f"[CSRFDefense:Crypto] Error registrando evento: {e}")

# ----------------------------
# Funciones auxiliares (igual que antes)
# ----------------------------
# funciones auxiliares para obtener IP cliente, extraer host de headers,
# comprobar si Origin/Referer coinciden con Host, verificar presencia de token CSRF,
# extraer texto del payload y listar parámetros; aquí cada línea tiene comentario explicativo.

def get_client_ip(request):
    # Obtiene la cabecera X-Forwarded-For (lista de IPs si existe)
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    # Si hay X-Forwarded-For, separar por comas y limpiar espacios
    if x_forwarded_for:
        ips = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        # Si la lista no está vacía, retornar la primera IP (cliente original)
        if ips:
            return ips[0]
    # Si no hay X-Forwarded-For, retornar REMOTE_ADDR (IP directa)
    return request.META.get("REMOTE_ADDR", "")

def host_from_header(header_value: str) -> str | None:
    # Si el header está vacío o es None, retornar None
    if not header_value:
        return None
    try:
        # Intentar parsear la URL para extraer netloc (host:puerto)
        parsed = urlparse(header_value)
        # Si parsed.netloc existe, devolver la parte antes de ":" (sin puerto)
        if parsed.netloc:
            return parsed.netloc.split(":")[0]
        # Si urlparse no produjo netloc, intentar dividir directamente por ":" y devolver parte host
        return header_value.split(":")[0]
    except Exception:
        # En caso de cualquier error de parseo, retornar None
        return None

def origin_matches_host(request) -> bool:
    # Obtener Host desde cabecera HTTP_HOST o SERVER_NAME como respaldo
    host_header = request.META.get("HTTP_HOST") or request.META.get("SERVER_NAME")
    # Si no hay host conocido, no podemos comprobar -> considerar como coincidente (no bloquear)
    if not host_header:
        return True
    # Extraer solo la parte del host sin puerto
    host = host_header.split(":")[0]
    # Leer cabeceras Origin y Referer (pueden estar vacías)
    origin = request.META.get("HTTP_ORIGIN", "")
    referer = request.META.get("HTTP_REFERER", "")
    # Bloquear explícitamente referers/ors que sean evidentes javascript: o payloads HTML/data:
    if any(re.search(r"(javascript:|<script|data:text/html)", h or "", re.I) for h in [origin, referer]):
        return False
    # Extraer host desde Origin y comparar con host principal; si coincide, retornar True
    if origin_host := host_from_header(origin):
        if origin_host == host:
            return True
    # Extraer host desde Referer y comparar con host principal; si coincide, retornar True
    if referer_host := host_from_header(referer):
        if referer_host == host:
            return True
    # Si no hay ni Origin ni Referer, tratar como coincidente por defecto (no podemos juzgar)
    if not origin and not referer:
        return True
    # En cualquier otro caso (hay origin/referer y no coinciden) retornar False
    return False

def has_csrf_token(request) -> bool:
    # Comprobar si algún header CSRF conocido está presente en META
    for h in CSRF_HEADER_NAMES:
        if request.META.get(h):
            return True
    # Comprobar si existe la cookie CSRF esperada
    if request.COOKIES.get(CSRF_COOKIE_NAME):
        return True
    try:
        # Si es un POST y el objeto request tiene atributo POST, comprobar campo de formulario CSRF
        if request.method == "POST" and hasattr(request, "POST"):
            if request.POST.get(POST_FIELD_NAME):
                return True
    except Exception:
        # En caso de cualquier excepción al acceder a POST, ignorar y seguir
        pass
    # Si no se encontró ninguna señal de token CSRF, retornar False
    return False

def extract_payload_text(request) -> str:
    # Construir lista de partes relevantes del request para análisis/registro
    parts: List[str] = []
    try:
        # Intentar decodificar el body como UTF-8 (ignorando errores)
        body = request.body.decode("utf-8", errors="ignore")
        # Si hay contenido en el body, añadirlo a las partes
        if body:
            parts.append(body)
    except Exception:
        # Si no se puede leer body, ignorar el error y continuar
        pass
    # Añadir query string si existe
    qs = request.META.get("QUERY_STRING", "")
    if qs:
        parts.append(qs)
    # Añadir User-Agent (puede ser útil para análisis)
    parts.append(request.META.get("HTTP_USER_AGENT", ""))
    # Añadir Referer (útil para correlacionar origen)
    parts.append(request.META.get("HTTP_REFERER", ""))
    # Unir todas las partes no vacías con espacios y retornar la cadena resultante
    return " ".join([p for p in parts if p])

def extract_parameters(request) -> List[str]:
    # Inicializar lista de nombres de parámetros
    params = []
    # Si request tiene POST, añadir las claves de POST
    if hasattr(request, "POST"):
        params.extend(request.POST.keys())
    # Si request tiene GET, añadir las claves de GET
    if hasattr(request, "GET"):
        params.extend(request.GET.keys())
    try:
        # Si el body existe y el Content-Type indica JSON, parsear JSON y añadir sus claves
        if request.body and "application/json" in (request.META.get("CONTENT_TYPE") or ""):
            data = json.loads(request.body)
            params.extend(data.keys())
    except Exception:
        # Si no se puede parsear JSON o ocurre un error, ignorarlo
        pass
    # Retornar la lista de parámetros (posiblemente duplicados entre GET/POST/JSON)
    return params

# Función robusta: analiza una cadena buscando patrones maliciosos definidos en CSRF_PAYLOAD_PATTERNS.
# Devuelve un score (float) sumando los pesos de los patrones que coinciden, redondeado a 3 decimales.
def analyze_payload(value: str) -> float:
    # Inicializa el contador de puntuación
    score = 0.0
    # Itera sobre la lista de patrones predefinidos (regex, descripción, peso)
    for patt, desc, weight in CSRF_PAYLOAD_PATTERNS:
        # Si el patrón coincide con la cadena de entrada, sumar su peso completo (sin descuentos)
        if patt.search(value):
            score += weight  # Sumar el peso del patrón detectado
    # Devolver la puntuación total redondeada a 3 decimales
    return round(score, 3)


# extrae la query string de la petición y la analiza usando analyze_payload.
# Retorna el score de la query string o 0.0 si no existe.
def analyze_query_string(request) -> float:
    # Obtener la query string cruda desde META 
    qs = request.META.get("QUERY_STRING", "")
    # Si hay query string, analizarla y devolver el score calculado por analyze_payload
    if qs:
        return analyze_payload(qs)
    # Si no hay query string, retornar 0.0
    return 0.0


# Función: analiza headers relevantes para detectar comportamientos sospechosos (User-Agent, Accept-Language).
# Devuelve una lista de descripciones de issues encontrados (vacía si no hay problemas).
def analyze_headers(request) -> List[str]:
    # Lista que almacenará problemas detectados
    issues = []
    # Obtener User-Agent (puede ser vacío)
    ua = request.META.get("HTTP_USER_AGENT", "")
    # Si el User-Agent contiene patrones típicos de scripts/automatización o caracteres sospechosos, añadir issue
    if re.search(r"(script|<|eval|bot|crawler)", ua, re.I):
        issues.append("User-Agent sospechoso (posible automatización/bot)")
    
    # Obtener Accept-Language (puede ser vacío o muy corto para bots)
    accept_lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    # Si no hay Accept-Language o su longitud es menor a 2, considerarlo sospechoso
    if not accept_lang or len(accept_lang) < 2:
        issues.append("Accept-Language ausente o muy corto (posible bot)")
    
    # Devolver la lista de issues detectados (vacía si no hay ninguno)
    return issues


class CSRFDefenseMiddleware(MiddlewareMixin):
    # Middleware para detectar señales de ataques CSRF en requests state-changing.
    # - Excluye rutas/IPs configuradas.
    # - Analiza método, headers, content-type, origin/referer, parámetros y payload.
    # - Calcula señales y score; si supera el umbral, marca request.csrf_attack_info
    #   y registra un evento cifrado para auditoría.
    def process_request(self, request):
        # Excluir APIs JSON si se configuró así (prefijos en CSRF_DEFENSE_EXCLUDED_API_PREFIXES)
        for prefix in CSRF_DEFENSE_EXCLUDED_API_PREFIXES:
            if request.path.startswith(prefix):
                logger.debug(f"[CSRFDefense] Skip analysis for API prefix {prefix} path {request.path}")
                return None

        # Obtener IP cliente (get_client_ip) y saltarla si está en lista de IPs confiables
        client_ip = get_client_ip(request)
        trusted_ips = getattr(settings, "CSRF_DEFENSE_TRUSTED_IPS", [])
        if client_ip in trusted_ips:
            return None

        # Saltar paths explicitamente excluidos desde configuración
        excluded_paths = getattr(settings, "CSRF_DEFENSE_EXCLUDED_PATHS", [])
        if any(request.path.startswith(p) for p in excluded_paths):
            return None

        # Solo analizar métodos que cambian estado (POST/PUT/PATCH/DELETE)
        method = (request.method or "").upper()
        if method not in STATE_CHANGING_METHODS:
            return None

        # Inicializar contenedor de descripciones de señales y extraer datos básicos
        descripcion: List[str] = []
        payload = extract_payload_text(request)  # Texto concatenado body/query/user-agent/referer
        params = extract_parameters(request)     # Lista de nombres de parámetros (GET/POST/JSON)

        # 1) Falta token CSRF (cookies/headers/form)
        if not has_csrf_token(request):
            descripcion.append("Falta token CSRF en cookie/header/form")

        # 2) Origin/Referer no coinciden con Host -> posible cross-site
        if not origin_matches_host(request):
            descripcion.append("Origin/Referer no coinciden con Host (posible cross-site)")

        # 3) Content-Type sospechoso según patrones SUSPICIOUS_CT_PATTERNS
        content_type = (request.META.get("CONTENT_TYPE") or "")
        for patt in SUSPICIOUS_CT_PATTERNS:
            if patt.search(content_type):
                descripcion.append(f"Content-Type sospechoso: {content_type}")
                break

        # 4) Referer ausente y sin header X-CSRFToken -> señal adicional
        referer = request.META.get("HTTP_REFERER", "")
        if not referer and not any(request.META.get(h) for h in CSRF_HEADER_NAMES):
            descripcion.append("Referer ausente y sin X-CSRFToken")

        # 5) Parámetros sensibles enviados en GET (posible CSRF por uso indebido de GET)
        for p in params:
            if p.lower() in SENSITIVE_PARAMS and method == "GET":
                descripcion.append(f"Parámetro sensible '{p}' enviado en GET (posible CSRF)")

        # 6) JSON POST desde dominio externo -> sospechoso
        if "application/json" in content_type:
            origin = request.META.get("HTTP_ORIGIN") or ""
            if origin and host_from_header(origin) != (request.META.get("HTTP_HOST") or "").split(":")[0]:
                descripcion.append("JSON POST desde origen externo (posible CSRF)")

        # 7) Análisis robusto del payload en todos los campos (POST y JSON)
        payload_score = 0.0
        payload_summary: List[Dict[str, Any]] = []
        full_payload = extract_payload_text(request)  # Guardar texto completo para registro si hace falta
        try:
            # Analizar campos POST: para cada valor string aplicar analyze_payload
            if hasattr(request, "POST"):
                for key, value in request.POST.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
            # Analizar JSON en el body si corresponde
            if "application/json" in content_type:
                data = json.loads(request.body.decode("utf-8") or "{}")
                for key, value in data.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
        except Exception as e:
            # Fallos al parsear/analizar no deben romper flujo; solo loguear debug
            logger.debug(f"Error analizando payload: {e}")
        # Si se detectó algo en payload, añadir descripción con score total
        if payload_score > 0:
            descripcion.append(f"Payload sospechoso detectado (score total: {payload_score})")


        # 8) Análisis de query string (se añade su score al payload_score si hay detección)
        qs_score = analyze_query_string(request)
        if qs_score > 0:
            descripcion.append(f"Query string sospechosa (score: {qs_score})")
            payload_score += qs_score

        # 9) Análisis de headers adicionales (User-Agent, Accept-Language, etc.)
        header_issues = analyze_headers(request)
        descripcion.extend(header_issues)

        # Si las señales cumplen o exceden el umbral, construir info del ataque y registrar evento cifrado
        total_signals = len(descripcion)
        if descripcion and total_signals >= CSRF_DEFENSE_MIN_SIGNALS:
            # Calcular score final S_csrf = w_csrf * total_signals + payload_score
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            s_csrf = w_csrf * total_signals + payload_score
            # Intentar obtener URL completa; si falla usar fallback con HOST+path
            url = request.build_absolute_uri()  # Puede lanzar/retornar vacío en algunos entornos
            if not url:
                url = f"{request.META.get('HTTP_HOST', 'unknown')}{request.path}"
                logger.warning(f"[CSRFDefense] URL build_absolute_uri falló, usando fallback: {url}")
            
            # Adjuntar información de ataque al objeto request para uso posterior (views/logs)
            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                # Registrar resumen de payload (limitar tamaño). Si no hay summary, incluir parte del full_payload.
                "payload": json.dumps(payload_summary, ensure_ascii=False)[:1000] if payload_summary else json.dumps({"full_payload": full_payload[:500]}, ensure_ascii=False),
                "score": s_csrf,
                "url": url,
            }
            # Loguear advertencia con detalles
            logger.warning(
                "CSRF detectado desde IP %s: %s ; path=%s ; Content-Type=%s ; score=%.2f ; url=%s ; payload_summary=%s",
                client_ip, descripcion, request.path, content_type, s_csrf, url, payload_summary
            )
            # Registrar evento cifrado para auditoría (record_csrf_event maneja cifrado y cache)
            try:
                record_csrf_event({
                    "ts": int(time.time()),
                    "ip": client_ip,
                    "score": s_csrf,
                    "desc": descripcion,
                    "url": url,  # Pasar URL
                    "payload": payload_summary if payload_summary else [],  # Pasar siempre lista
                })
            except Exception:
                # Si falla el registro, loguear excepción sin interrumpir request handling
                logger.exception("failed to record CSRF event")
        else:
            # Si hay descripciones pero no alcanzan el umbral, registrar en debug para análisis
            if descripcion:
                logger.debug(f"[CSRFDefense] low-signals ({total_signals}) not marking: {descripcion}")
        # No alterar el flujo de la request (retornar None para permitir procesamiento normal)
        return None

# =====================================================
# ===              INFORMACIÓN EXTRA                ===
# =====================================================
"""
Algoritmos relacionados para protección contra CSRF:
- HMAC-SHA256: Usado para firmar tokens CSRF (sign_csrf_token, verify_csrf_token_signature).
- SHA-256/SHA-3: Usado para hashes de contenido (compute_hash).
- AES-GCM/ChaCha20-Poly1305: Usado para cifrar tokens sensibles o payloads (encrypt_csrf_token, decrypt_csrf_token).
- HKDF: Usado para derivar claves seguras (derive_key).
- Argon2id: Usado para derivar claves con resistencia a ataques de fuerza bruta (derive_key).
- Registro cifrado de eventos: Para asegurar auditoría sin exponer datos sensibles.

Contribución a fórmula de amenaza S:
    S_csrf = w_csrf * señales_csrf + payload_score
    Ejemplo: S_csrf = 0.2 * 3 + 1.5 = 2.1

Notas sobre implementación de algoritmos de seguridad:
    - Integra con Django's CSRF middleware: Usa este middleware para detección adicional, y genera tokens firmados si es necesario.
    - Para usar en producción: Configura CSRF_DEFENSE_MASTER_KEY en settings.py.
    - Ajusta umbrales y configuraciones según necesidades.
    - Combina con CSP (Content Security Policy) para mayor protección.
"""
