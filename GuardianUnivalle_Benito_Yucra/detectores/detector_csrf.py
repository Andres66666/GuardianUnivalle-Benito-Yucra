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
from django.http import HttpResponseForbidden, HttpResponse

# cryptography & argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from argon2.low_level import hash_secret_raw, Type as Argon2Type


# ----------------------------
# Logger
# ----------------------------
logger = logging.getLogger("csrfdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)


# ----------------------------
# Constantes / configuración
# ----------------------------
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER_NAMES = ("HTTP_X_CSRFTOKEN", "HTTP_X_CSRF_TOKEN")
CSRF_COOKIE_NAME = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
POST_FIELD_NAME = "csrfmiddlewaretoken"

SUSPICIOUS_CT_PATTERNS = [
    re.compile(r"text/plain", re.I),
    re.compile(r"application/x-www-form-urlencoded", re.I),
    re.compile(r"multipart/form-data", re.I),
    re.compile(r"application/json", re.I),
    re.compile(r"text/html", re.I),
]

SENSITIVE_PARAMS = [
    "password", "csrfmiddlewaretoken", "token", "amount", "transfer", "delete", "update",
    "action", "email", "username"
]

SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth", "email", "username"]

CSRF_DEFENSE_MIN_SIGNALS = getattr(settings, "CSRF_DEFENSE_MIN_SIGNALS", 1)
CSRF_DEFENSE_EXCLUDED_API_PREFIXES = getattr(settings, "CSRF_DEFENSE_EXCLUDED_API_PREFIXES", ["/api/"])


#  CORRECCIÓN: regex con "\$" estaban mal. Aquí debe ser "\(" para detectar llamadas.
CSRF_PAYLOAD_PATTERNS = [
    (re.compile(r"<script[^>]*>.*?</script>", re.I | re.S), "Script tag en payload", 0.9),
    (re.compile(r"javascript\s*:", re.I), "URI javascript: en payload", 0.8),
    (re.compile(r"http[s]?://[^\s]+", re.I), "URL externa en payload", 0.7),

    (re.compile(r"\beval\s*\(", re.I), "eval() en payload", 1.0),
    (re.compile(r"\balert\s*\(", re.I), "alert() en payload (prueba)", 0.5),
    (re.compile(r"\bfetch\s*\(", re.I), "fetch() en payload", 0.7),
    (re.compile(r"\bXMLHttpRequest\b", re.I), "XHR en payload", 0.7),

    (re.compile(r"\bdocument\.cookie\b", re.I), "Acceso a cookie en payload", 0.9),
    (re.compile(r"\binnerHTML\s*=", re.I), "Manipulación DOM innerHTML", 0.8),

    (re.compile(r"&#x[0-9a-fA-F]+;", re.I), "Entidades HTML en payload", 0.6),
    (re.compile(r"%3Cscript", re.I), "Script URL-encoded en payload", 0.8),
    (re.compile(r"\bon\w+\s*=", re.I), "Eventos on* en payload", 0.7),
]


# ----------------------------
# Crypto config
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

#  CORRECCIÓN: si settings lo trae como str, lo pasamos a bytes
_HMAC_LABEL = getattr(settings, "CSRF_HMAC_LABEL", b"csrfdefense-hmac")
HMAC_LABEL: bytes = _HMAC_LABEL.encode() if isinstance(_HMAC_LABEL, str) else _HMAC_LABEL

_AEAD_LABEL = getattr(settings, "CSRF_AEAD_LABEL", b"csrfdefense-aead")
AEAD_LABEL: bytes = _AEAD_LABEL.encode() if isinstance(_AEAD_LABEL, str) else _AEAD_LABEL

HASH_CHOICE = getattr(settings, "CSRF_DEFENSE_HASH", "SHA256").upper()

CACHE_BLOCK_KEY_PREFIX = "csrf_block:"
DEFAULT_BACKOFF_LEVELS = getattr(
    settings,
    "CSRF_DEFENSE_BACKOFF_LEVELS",
    [0, 60 * 15, 60 * 60, 60 * 60 * 6, 60 * 60 * 24, 60 * 60 * 24 * 7]
)


# ----------------------------
# Helpers base64 bytes <-> str
# ----------------------------
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ----------------------------
# Crypto: KDF / AEAD / HMAC / Hash
# ----------------------------
def derive_key(label: bytes, context: bytes = b"") -> bytes:
    salt = (label + context)[:16].ljust(16, b"\0")
    try:
        raw = hash_secret_raw(
            secret=MASTER_KEY if isinstance(MASTER_KEY, (bytes, bytearray)) else MASTER_KEY.encode(),
            salt=salt,
            time_cost=ARGON2_CONFIG["time_cost"],
            memory_cost=ARGON2_CONFIG["memory_cost"],
            parallelism=ARGON2_CONFIG["parallelism"],
            hash_len=ARGON2_CONFIG["hash_len"],
            type=ARGON2_CONFIG["type"],
        )
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(raw)
    except Exception:
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())


def aead_encrypt(plaintext: bytes, aad: bytes = b"", context: bytes = b"") -> Dict[str, bytes]:
    key = derive_key(AEAD_LABEL, context)
    nonce = os.urandom(12)
    if AEAD_CHOICE == "CHACHA20":
        aead = ChaCha20Poly1305(key)
        ct = aead.encrypt(nonce, plaintext, aad)
        return {"alg": "CHACHA20-POLY1305", "nonce": nonce, "ciphertext": ct}
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return {"alg": "AES-GCM", "nonce": nonce, "ciphertext": ct}


def aead_decrypt(payload: Dict[str, bytes], aad: bytes = b"", context: bytes = b"") -> bytes:
    key = derive_key(AEAD_LABEL, context)
    alg = payload.get("alg", b"AES-GCM")
    if isinstance(alg, bytes):
        alg = alg.decode(errors="ignore")
    nonce = payload.get("nonce")
    ct = payload.get("ciphertext")
    if not nonce or not ct:
        raise ValueError("invalid payload for AEAD decrypt")
    if str(alg).startswith("CHACHA20"):
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    return AESGCM(key).decrypt(nonce, ct, aad)


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
    return _b64e(h.finalize())


# ----------------------------
# Fingerprint + bloqueo por cache
# ----------------------------
def get_attacker_fingerprint(request, payload_summary=None) -> str:
    ua = request.META.get("HTTP_USER_AGENT", "")
    accept = request.META.get("HTTP_ACCEPT", "")
    lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    path = request.path

    raw = json.dumps({
        "ua": ua[:200],
        "accept": accept[:100],
        "lang": lang[:50],
        "path": path,
        "payload": payload_summary[:3] if payload_summary else [],
    }, ensure_ascii=False)

    return compute_hash(raw.encode("utf-8"))


def is_fingerprint_blocked(fingerprint: str) -> bool:
    if not fingerprint:
        return False
    return bool(cache.get(f"csrf_block_fingerprint:{fingerprint}"))


def is_ip_blocked(ip: str) -> bool:
    if not ip:
        return False
    return bool(cache.get(f"{CACHE_BLOCK_KEY_PREFIX}{ip}"))


def cache_block_ip_with_backoff(ip: str, fingerprint: str = ""):
    if not ip:
        return 0, 0
    level_key = f"{CACHE_BLOCK_KEY_PREFIX}{ip}:level"
    level = cache.get(level_key, 0) or 0
    level = int(level) + 1
    cache.set(level_key, level, timeout=60 * 60 * 24 * 7)

    idx = min(level, len(DEFAULT_BACKOFF_LEVELS) - 1)
    timeout = DEFAULT_BACKOFF_LEVELS[idx]

    cache.set(f"{CACHE_BLOCK_KEY_PREFIX}{ip}", True, timeout=timeout)
    if fingerprint:
        cache.set(f"csrf_block_fingerprint:{fingerprint}", True, timeout=timeout)
    return level, timeout


# ----------------------------
# Tokens CSRF firmados/cifrados ( CORREGIDO: JSON serializable)
# ----------------------------
def sign_csrf_token(token: str, context: bytes = b"") -> str:
    tag = compute_hmac(token.encode("utf-8"), context)
    return f"{token}.{_b64e(tag)}"


def verify_csrf_token_signature(signed_token: str, context: bytes = b"") -> str:
    try:
        token, tag_b64 = signed_token.rsplit(".", 1)
        tag = _b64d(tag_b64)
        if verify_hmac(token.encode("utf-8"), tag, context):
            return token
        raise ValueError("Invalid signature")
    except Exception:
        raise ValueError("Invalid signed CSRF token")


def encrypt_csrf_token(token: str, context: bytes = b"") -> str:

    enc = aead_encrypt(token.encode("utf-8"), context=context)
    enc_json = {
        "alg": enc["alg"],
        "nonce": _b64e(enc["nonce"]),
        "ciphertext": _b64e(enc["ciphertext"]),
    }
    return _b64e(json.dumps(enc_json, ensure_ascii=False).encode("utf-8"))


def decrypt_csrf_token(encrypted_token: str, context: bytes = b"") -> str:
    try:
        enc_json = json.loads(_b64d(encrypted_token).decode("utf-8"))
        payload = {
            "alg": enc_json.get("alg", "AES-GCM"),
            "nonce": _b64d(enc_json["nonce"]),
            "ciphertext": _b64d(enc_json["ciphertext"]),
        }
        plaintext = aead_decrypt(payload, context=context)
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError("Invalid encrypted CSRF token")


# ----------------------------
# Registro cifrado de eventos
# ----------------------------
def record_csrf_event(event: dict) -> None:
    try:
        ts = int(time.time())

        if "url" not in event or not event["url"]:
            event["url"] = "unknown"
            logger.warning(
                f"[CSRFDefense:Crypto] URL faltante en evento, usando fallback 'unknown' (IP={event.get('ip')})"
            )

        if "payload" in event and event["payload"] and event["payload"] != "[]":
            try:
                ctx = f"{event.get('ip','')}-{ts}".encode("utf-8")
                enc = aead_encrypt(json.dumps(event["payload"], ensure_ascii=False).encode("utf-8"), context=ctx)
                htag = compute_hmac(enc["ciphertext"], context=ctx)

                event["_payload_encrypted"] = {
                    "alg": enc["alg"],
                    "nonce": _b64e(enc["nonce"]),
                    "ciphertext": _b64e(enc["ciphertext"]),
                    "hmac": _b64e(htag),
                }
                del event["payload"]

                logger.info(
                    f"[CSRFDefense:Crypto] CIFRADO EXITOSO: Payload cifrado para IP {event.get('ip')} "
                    f"(alg={enc['alg']}, len_cipher={len(enc['ciphertext'])})"
                )
            except Exception as e:
                logger.error(f"[CSRFDefense:Crypto] CIFRADO FALLÓ: Error cifrando payload para IP {event.get('ip')}: {e}")
                logger.warning("[CSRFDefense:Crypto] Manteniendo payload sin cifrar para registro (desarrollo)")
        else:
            logger.debug(f"[CSRFDefense:Crypto] No hay payload para cifrar en evento (IP={event.get('ip')})")

        key = f"csrf_event:{ts}:{event.get('ip', '')}"
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)
    except Exception as e:
        logger.error(f"[CSRFDefense:Crypto] Error registrando evento: {e}")


# ----------------------------
# Auxiliares CSRF
# ----------------------------
def get_client_ip(request) -> str:
    """
    Sencillo y compatible con Render/Reverse proxy.
    Si quieres hacerlo más estricto, mete lista de proxies confiables como en tu SQLi.
    """
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
    params: List[str] = []
    if hasattr(request, "POST"):
        params.extend(list(request.POST.keys()))
    if hasattr(request, "GET"):
        params.extend(list(request.GET.keys()))
    try:
        if request.body and "application/json" in (request.META.get("CONTENT_TYPE") or ""):
            data = json.loads(request.body)
            if isinstance(data, dict):
                params.extend(list(data.keys()))
    except Exception:
        pass
    return params


def analyze_payload(value: str) -> float:
    score = 0.0
    for patt, _desc, weight in CSRF_PAYLOAD_PATTERNS:
        if patt.search(value):
            score += weight
    return round(score, 3)


def analyze_query_string(request) -> float:
    qs = request.META.get("QUERY_STRING", "")
    return analyze_payload(qs) if qs else 0.0


def analyze_headers(request) -> List[str]:
    issues: List[str] = []
    ua = request.META.get("HTTP_USER_AGENT", "")
    if re.search(r"(script|<|eval|bot|crawler)", ua, re.I):
        issues.append("User-Agent sospechoso (posible automatización/bot)")
    accept_lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")
    if not accept_lang or len(accept_lang) < 2:
        issues.append("Accept-Language ausente o muy corto (posible bot)")
    return issues


# ----------------------------
# Middleware CSRF Defense
# ----------------------------
class CSRFDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
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

        fingerprint = get_attacker_fingerprint(request)
        if is_fingerprint_blocked(fingerprint):
            warning_message = (
                "Acceso denegado. Su fingerprint y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[CSRFBlock:Fingerprint] Fingerprint={fingerprint} IP={client_ip} - Intento persistente de acceso bloqueado.")
            return HttpResponseForbidden(warning_message)

        if is_ip_blocked(client_ip):
            warning_message = (
                "Acceso denegado. Su dirección IP y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[CSRFBlock:IP] IP={client_ip} - Intento persistente de acceso bloqueado.")
            return HttpResponseForbidden(warning_message)

        descripcion: List[str] = []
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

        # 4) Referer ausente y sin header X-CSRFToken
        referer = request.META.get("HTTP_REFERER", "")
        if not referer and not any(request.META.get(h) for h in CSRF_HEADER_NAMES):
            descripcion.append("Referer ausente y sin X-CSRFToken")

        # 5) Parámetros sensibles por GET
        if method == "GET":
            for p in params:
                if p.lower() in SENSITIVE_PARAMS:
                    descripcion.append(f"Parámetro sensible '{p}' enviado en GET (posible CSRF)")

        # 6) JSON POST desde dominio externo
        if "application/json" in content_type:
            origin = request.META.get("HTTP_ORIGIN") or ""
            host = (request.META.get("HTTP_HOST") or "").split(":")[0]
            if origin and host_from_header(origin) != host:
                descripcion.append("JSON POST desde origen externo (posible CSRF)")

        # 7) Análisis payload en POST/JSON
        payload_score = 0.0
        payload_summary: List[Dict[str, Any]] = []
        full_payload = extract_payload_text(request)

        try:
            if hasattr(request, "POST"):
                for key, value in request.POST.items():
                    if isinstance(value, str):
                        s = analyze_payload(value)
                        payload_score += s
                        if s > 0:
                            payload_summary.append({"field": key, "snippet": value[:300], "score": s})

            if "application/json" in content_type:
                data = json.loads(request.body.decode("utf-8") or "{}")
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, str):
                            s = analyze_payload(value)
                            payload_score += s
                            if s > 0:
                                payload_summary.append({"field": key, "snippet": value[:300], "score": s})
        except Exception as e:
            logger.debug(f"Error analizando payload: {e}")

        if payload_score > 0:
            descripcion.append(f"Payload sospechoso detectado (score total: {payload_score})")

        # 8) Query string
        qs_score = analyze_query_string(request)
        if qs_score > 0:
            descripcion.append(f"Query string sospechosa (score: {qs_score})")
            payload_score += qs_score

        # 9) Headers
        descripcion.extend(analyze_headers(request))

        total_signals = len(descripcion)
        if descripcion and total_signals >= CSRF_DEFENSE_MIN_SIGNALS:
            w_csrf = getattr(settings, "CSRF_DEFENSE_WEIGHT", 0.2)
            s_csrf = w_csrf * total_signals + payload_score

            url = request.build_absolute_uri()
            if not url:
                url = f"{request.META.get('HTTP_HOST', 'unknown')}{request.path}"
                logger.warning(f"[CSRFDefense] URL build_absolute_uri falló, usando fallback: {url}")

            fingerprint = get_attacker_fingerprint(request, payload_summary)

            request.csrf_attack_info = {
                "ip": client_ip,
                "tipos": ["CSRF"],
                "descripcion": descripcion,
                "payload": (
                    json.dumps(payload_summary, ensure_ascii=False)[:1000]
                    if payload_summary else
                    json.dumps({"full_payload": full_payload[:500]}, ensure_ascii=False)
                ),
                "score": s_csrf,
                "url": url,
                "fingerprint": fingerprint,
            }

            logger.warning(
                "CSRF detectado desde IP %s: %s ; path=%s ; Content-Type=%s ; score=%.2f ; url=%s ; payload_summary=%s",
                client_ip, descripcion, request.path, content_type, s_csrf, url, payload_summary
            )

            try:
                record_csrf_event({
                    "ts": int(time.time()),
                    "ip": client_ip,
                    "score": s_csrf,
                    "desc": descripcion,
                    "url": url,
                    "payload": payload_summary if payload_summary else [],
                })
            except Exception:
                logger.exception("failed to record CSRF event")
        else:
            if descripcion:
                logger.debug(f"[CSRFDefense] low-signals ({total_signals}) not marking: {descripcion}")

        return None