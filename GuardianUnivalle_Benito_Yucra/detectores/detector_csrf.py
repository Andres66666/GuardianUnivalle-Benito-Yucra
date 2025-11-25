from __future__ import annotations
import secrets
import logging
import re
import json
import base64
import os
import time
from typing import List, Dict, Any
from urllib.parse import urlparse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache

# cryptography & argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from argon2.low_level import hash_secret_raw, Type as Argon2Type

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

def compute_hmac(data: bytes, context: bytes = b"") -> bytes:
    key = derive_key(HMAC_LABEL, context)
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(data: bytes, tag: bytes, context: bytes = b"") -> bool:
    key = derive_key(HMAC_LABEL, context)
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except InvalidSignature:
        return False

def compute_hash(data: bytes) -> str:
    if HASH_CHOICE == "SHA3":
        h = hashes.Hash(hashes.SHA3_256())
    else:
        h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return base64.b64encode(h.finalize()).decode()

# ----------------------------
# Funciones para tokens CSRF firmados/cifrados
# ----------------------------
def sign_csrf_token(token: str, context: bytes = b"") -> str:
    """Firma un token CSRF con HMAC-SHA256 para evitar alteraciones."""
    data = token.encode("utf-8")
    tag = compute_hmac(data, context)
    return f"{token}.{base64.b64encode(tag).decode()}"

def verify_csrf_token_signature(signed_token: str, context: bytes = b"") -> str:
    """Verifica la firma de un token CSRF y retorna el token original si es válido."""
    try:
        token, tag_b64 = signed_token.rsplit(".", 1)
        tag = base64.b64decode(tag_b64)
        if verify_hmac(token.encode("utf-8"), tag, context):
            return token
        else:
            raise ValueError("Invalid signature")
    except Exception:
        raise ValueError("Invalid signed CSRF token")

def encrypt_csrf_token(token: str, context: bytes = b"") -> str:
    """Cifra un token CSRF sensible con AEAD."""
    enc = aead_encrypt(token.encode("utf-8"), context=context)
    return base64.b64encode(json.dumps(enc).encode()).decode()

def decrypt_csrf_token(encrypted_token: str, context: bytes = b"") -> str:
    """Descifra un token CSRF."""
    try:
        enc = json.loads(base64.b64decode(encrypted_token))
        plaintext = aead_decrypt(enc, context=context)
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError("Invalid encrypted CSRF token")

# ----------------------------
# Registro cifrado de eventos (similar a XSS/SQLi) - CON LOGS PARA CIFRADO Y DESCIFRADO
# ----------------------------
def record_csrf_event(event: dict) -> None:
    try:
        ts = int(time.time())
        # cifrar payload si existe
        if "payload" in event and event["payload"]:
            try:
                ctx = f"{event.get('ip','')}-{ts}".encode()
                enc = aead_encrypt(json.dumps(event["payload"], ensure_ascii=False).encode("utf-8"), context=ctx)
                htag = compute_hmac(enc["ciphertext"], context=ctx)
                event["_payload_encrypted"] = {
                    "alg": enc["alg"],
                    "nonce": base64.b64encode(enc["nonce"]).decode(),
                    "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),
                    "hmac": base64.b64encode(htag).decode(),
                }
                del event["payload"]  # no almacenar plaintext
                logger.info(f"[CSRFDefense:Crypto] CIFRADO EXITOSO: Payload cifrado para IP {event.get('ip')} (alg={enc['alg']}, len_cipher={len(enc['ciphertext'])})")
            except Exception as e:
                logger.error(f"[CSRFDefense:Crypto] CIFRADO FALLÓ: Error cifrando payload para IP {event.get('ip')}: {e}")
                # si falla, simplemente no incluimos payload
                event.pop("payload", None)
        else:
            logger.debug(f"[CSRFDefense:Crypto] No hay payload para cifrar en evento (IP={event.get('ip')}) - CIFRADO NO EJECUTADO")
            # Para probar cifrado/descifrado, cifrar un payload de prueba
            try:
                test_payload = {"test": "prueba_csrf"}
                ctx = f"{event.get('ip','')}-{ts}".encode()
                enc = aead_encrypt(json.dumps(test_payload, ensure_ascii=False).encode("utf-8"), context=ctx)
                logger.info(f"[CSRFDefense:Crypto] CIFRADO DE PRUEBA EXITOSO: Payload de prueba cifrado (alg={enc['alg']}, len_cipher={len(enc['ciphertext'])})")
                # Probar descifrado
                decrypted = aead_decrypt(enc, context=ctx)
                decrypted_data = json.loads(decrypted.decode("utf-8"))
                if decrypted_data == test_payload:
                    logger.info(f"[CSRFDefense:Crypto] DESCIFRADO DE PRUEBA EXITOSO: Payload descifrado correctamente")
                else:
                    logger.error(f"[CSRFDefense:Crypto] DESCIFRADO DE PRUEBA FALLÓ: Datos no coinciden")
            except Exception as e:
                logger.error(f"[CSRFDefense:Crypto] CIFRADO/DESCIFRADO DE PRUEBA FALLÓ: {e}")
        key = f"csrf_event:{ts}:{event.get('ip', '')}"
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)
        logger.debug(f"[CSRFDefense:Crypto] Evento registrado en cache exitosamente (key={key})")
    except Exception as e:
        logger.error(f"[CSRFDefense:Crypto] Error registrando evento: {e}")

# ----------------------------
# Funciones auxiliares (igual que antes)
# ----------------------------
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
    # Bloquear obvious javascript: referers
    if any(re.search(r"(javascript:|<script|data:text/html)", h or "", re.I) for h in [origin, referer]):
        return False
    if origin_host := host_from_header(origin):
        if origin_host == host:
            return True
    if referer_host := host_from_header(referer):
        if referer_host == host:
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

# FUNCIÓN ROBUSTA: Analizar payload en TODOS los campos (sin descuento)
# FUNCIÓN ROBUSTA: Analizar payload en TODOS los campos (sin descuento)
def analyze_payload(value: str) -> float:
    score = 0.0
    for patt, desc, weight in CSRF_PAYLOAD_PATTERNS:
        if patt.search(value):
            score += weight  # Score full, sin descuento
    return round(score, 3)

# NUEVA FUNCIÓN: Extraer y analizar query string
def analyze_query_string(request) -> float:
    qs = request.META.get("QUERY_STRING", "")
    if qs:
        return analyze_payload(qs)
    return 0.0

# NUEVA FUNCIÓN: Analizar headers adicionales
def analyze_headers(request) -> List[str]:
    issues = []
    ua = request.META.get("HTTP_USER_AGENT", "")
    if re.search(r"(script|<|eval|bot|crawler)", ua, re.I):
        issues.append("User-Agent sospechoso (posible automatización/bot)")
    
    accept_lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    if not accept_lang or len(accept_lang) < 2:
        issues.append("Accept-Language ausente o muy corto (posible bot)")
    
    return issues

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

        # 7) Análisis ROBUSTO de payload en TODOS los campos (sin descuento)
        payload_score = 0.0
        payload_summary: List[Dict[str, Any]] = []
        try:
            # Analizar POST
            if hasattr(request, "POST"):
                for key, value in request.POST.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
            # Analizar JSON
            if "application/json" in content_type:
                data = json.loads(request.body.decode("utf-8") or "{}")
                for key, value in data.items():
                    if isinstance(value, str):
                        score = analyze_payload(value)
                        payload_score += score
                        if score > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": score})
        except Exception as e:
            logger.debug(f"Error analizando payload: {e}")

        if payload_score > 0:
            descripcion.append(f"Payload sospechoso detectado (score total: {payload_score})")

        # 8) Análisis de query string
        qs_score = analyze_query_string(request)
        if qs_score > 0:
            descripcion.append(f"Query string sospechosa (score: {qs_score})")
            payload_score += qs_score

        # 9) Análisis de headers adicionales
        header_issues = analyze_headers(request)
        descripcion.extend(header_issues)

        # Señales >= umbral => marcar y registrar evento cifrado
        total_signals = len(descripcion)
        if descripcion and total_signals >= CSRF_DEFENSE_MIN_SIGNALS:
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            s_csrf = w_csrf * total_signals + payload_score  # Score full sin descuento
            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                "payload": json.dumps(payload_summary, ensure_ascii=False)[:1000],
                "score": s_csrf,
            }
            logger.warning(
                "CSRF detectado desde IP %s: %s ; path=%s ; Content-Type=%s ; score=%.2f (Ultra-Robust: nada ignorado)",
                client_ip, descripcion, request.path, content_type, s_csrf
            )
            # Registrar evento cifrado para auditoría
            try:
                record_csrf_event({
                    "ts": int(time.time()),
                    "ip": client_ip,
                    "score": s_csrf,
                    "desc": descripcion,
                    "url": request.build_absolute_uri(),
                    "payload": payload_summary,  # se cifrará en record_csrf_event
                })
            except Exception:
                logger.exception("failed to record CSRF event")
        else:
            if descripcion:
                logger.debug(f"[CSRFDefense] low-signals ({total_signals}) not marking: {descripcion}")

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
