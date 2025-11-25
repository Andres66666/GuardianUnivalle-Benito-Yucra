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
# - TLS 1.3 recomendado en configuración del servidor (no implementado aquí, pero documentado)
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
# - TLS 1.3 recomendado en configuración del servidor (no implementado aquí, pero documentado)
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
# - TLS 1.3 recomendado en configuración del servidor (no implementado aquí, pero documentado)
# - Registro cifrado de eventos y payloads

from __future__ import annotations
import json
import logging
import re
import math
import base64
import os
import time
from typing import List, Tuple, Dict, Any
from django.utils.deprecation import MiddlewareMixin
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
# Configuraciones criptográficas (similar a SQLi)
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
# Configuraciones de bloqueo y cache (similar a SQLi, pero con prefijo XSS_)
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
# Patrones XSS robustos (igual que antes)
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
# Función de saturación
# ----------------------------
SATURATION_C = getattr(settings, "XSS_DEFENSE_SATURATION_C", 1.5)
SATURATION_ALPHA = getattr(settings, "XSS_DEFENSE_SATURATION_ALPHA", 2.0)

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
def _is_valid_ip(ip: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
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
def extract_body_as_map(request) -> Dict[str, Any]:
    try:
        ct = request.META.get("CONTENT_TYPE", "")
        if "application/json" in ct:
            raw = request.body.decode("utf-8") or "{}"
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
                return {"raw": raw}
            except Exception:
                return {"raw": raw}
        try:
            post = request.POST.dict()
            if post:
                return post
        except Exception:
            pass
        raw = request.body.decode("utf-8", errors="ignore")
        if raw:
            return {"raw": raw}
    except Exception:
        pass
    return {}

# ----------------------------
# Detect XSS en valor
# ----------------------------
def detect_xss_in_value(value: str, is_sensitive: bool = False) -> Tuple[float, List[str], List[str]]:
    if not value:
        return 0.0, [], []
    score_total = 0.0
    descripcion = []
    matches = []
    value = value.lower().strip()
    if _BLEACH_AVAILABLE:
        cleaned = bleach.clean(value, strip=True)
        if cleaned != value:
            score_total += 0.5
            descripcion.append("Contenido alterado por sanitización (bleach)")
    for patt, msg, weight in XSS_PATTERNS:
        occ = len(patt.findall(value))
        if occ > 0:
            added = sum(weight * (0.5 ** i) for i in range(occ))
            if is_sensitive:
                added *= SENSITIVE_DISCOUNT
            score_total += added
            descripcion.append(msg)
            matches.append(patt.pattern)
    return round(score_total, 3), descripcion, matches

# ----------------------------
# Conversión a probabilidad
# ----------------------------
def weight_to_prob(w: float) -> float:
    try:
        q = 1.0 - math.exp(-max(w, 0.0))
        return min(max(q, 0.0), 0.999999)
    except Exception:
        return min(max(w, 0.0), 0.999999)

def combine_probs(qs: List[float]) -> float:
    prod = 1.0
    for q in qs:
        prod *= (1.0 - q)
    return 1.0 - prod

# ----------------------------
# Firmar/cifrar cookies (integración cripto)
# ----------------------------
def sign_cookie_value(value: str, context: bytes = b"") -> str:
    """Firma un valor de cookie con HMAC-SHA256 para evitar alteraciones por XSS."""
    data = value.encode("utf-8")
    tag = compute_hmac(data, context)
    return f"{value}.{base64.b64encode(tag).decode()}"

def verify_cookie_signature(signed_value: str, context: bytes = b"") -> str:
    """Verifica la firma de una cookie y retorna el valor original si es válido."""
    try:
        value, tag_b64 = signed_value.rsplit(".", 1)
        tag = base64.b64decode(tag_b64)
        if verify_hmac(value.encode("utf-8"), tag, context):
            return value
        else:
            raise ValueError("Invalid signature")
    except Exception:
        raise ValueError("Invalid signed cookie")

def encrypt_cookie_value(value: str, context: bytes = b"") -> str:
    """Cifra un valor de cookie sensible con AEAD."""
    enc = aead_encrypt(value.encode("utf-8"), context=context)
    return base64.b64encode(json.dumps(enc).encode()).decode()

def decrypt_cookie_value(encrypted_value: str, context: bytes = b"") -> str:
    """Descifra un valor de cookie."""
    try:
        enc = json.loads(base64.b64decode(encrypted_value))
        plaintext = aead_decrypt(enc, context=context)
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError("Invalid encrypted cookie")

# ----------------------------
# Funciones de cache para bloqueo (similar a SQLi, pero con prefijo XSS_)
# ----------------------------
def cache_block_ip_with_backoff(ip: str):
    if not ip:
        return 0, 0
    level_key = f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}:level"
    level = cache.get(level_key, 0) or 0
    level = int(level) + 1
    cache.set(level_key, level, timeout=60 * 60 * 24 * 7)
    durations = XSS_DEFAULT_BACKOFF_LEVELS
    idx = min(level, len(durations) - 1)
    timeout = durations[idx]
    cache.set(f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}", True, timeout=timeout)
    return level, timeout

def is_ip_blocked(ip: str) -> bool:
    if not ip:
        return False
    return bool(cache.get(f"{XSS_CACHE_BLOCK_KEY_PREFIX}{ip}"))

def incr_ip_counter(ip: str) -> int:
    if not ip:
        return 0
    key = f"{XSS_CACHE_COUNTER_KEY_PREFIX}{ip}"
    current = cache.get(key, 0)
    try:
        current = int(current)
    except Exception:
        current = 0
    current += 1
    cache.set(key, current, timeout=XSS_COUNTER_WINDOW)
    return current

# ----------------------------
# Registro cifrado de eventos (similar a SQLi para asegurar registro)
# ----------------------------
def record_xss_event(event: dict) -> None:
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
            except Exception:
                # si falla, simplemente no incluimos payload
                event.pop("payload", None)
        key = f"xss_event:{ts}:{event.get('ip', '')}"
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)
    except Exception:
        logger.exception("record_xss_event failed")

# ----------------------------
# Middleware XSS con cripto integrado (ajustado para registro similar a SQLi y chequeo de bloqueo inicial)
# ----------------------------
class XSSDefenseCryptoMiddleware(MiddlewareMixin):
    def process_request(self, request):
        client_ip = get_client_ip(request)

        # Chequear bloqueo inicial (similar a SQLi)
        if is_ip_blocked(client_ip):
            warning_message = (
                "Acceso denegado. Su dirección IP y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[XSSBlock:Persistent] IP={client_ip} - Intento persistente de acceso bloqueado. Mensaje enviado.")
            return HttpResponseForbidden(warning_message)

        trusted_ips: List[str] = getattr(settings, "XSS_DEFENSE_TRUSTED_IPS", [])
        if client_ip in trusted_ips:
            return None
        excluded_paths: List[str] = getattr(settings, "XSS_DEFENSE_EXCLUDED_PATHS", [])
        if any(request.path.startswith(p) for p in excluded_paths):
            return None

        data = extract_body_as_map(request)
        qs = request.META.get("QUERY_STRING", "")
        if qs:
            data["_query_string"] = qs
        if not data:
            return None

        total_score = 0.0
        all_descriptions: List[str] = []
        global_prob_list: List[float] = []
        payload_summary = []

        if isinstance(data, dict):
            for key, value in data.items():
                is_sensitive = key.lower() in SENSITIVE_FIELDS
                vtext = value
                if isinstance(value, (dict, list)):
                    try:
                        vtext = json.dumps(value, ensure_ascii=False)
                    except Exception:
                        vtext = str(value)
                else:
                    vtext = str(value or "")
                s, descs, matches = detect_xss_in_value(vtext, is_sensitive)
                total_score += s
                all_descriptions.extend(descs)
                for m in matches:
                    q = weight_to_prob(s)
                    global_prob_list.append(q)
                if s > 0:
                    payload_summary.append({"field": key, "snippet": vtext[:300], "sensitive": is_sensitive})
        else:
            raw = str(data)
            s, descs, matches = detect_xss_in_value(raw)
            total_score += s
            all_descriptions.extend(descs)
            for m in matches:
                q = weight_to_prob(s)
                global_prob_list.append(q)
            if s > 0:
                payload_summary.append({"field": "raw", "snippet": raw[:500], "sensitive": False})

        if total_score == 0:
            return None

        p_attack = combine_probs(global_prob_list) if global_prob_list else 0.0
        s_norm = saturate_score(total_score)
        url = request.build_absolute_uri()
        payload_for_request = json.dumps(payload_summary, ensure_ascii=False)[:2000]

        logger.warning(
            "[XSSDetect] IP=%s URL=%s ScoreRaw=%.3f ScoreNorm=%.3f Prob=%.3f Desc=%s",
            client_ip, url, total_score, s_norm, p_attack, all_descriptions
        )

        # Registrar el evento de manera cifrada para auditoría (similar a SQLi)
        try:
            record_xss_event({
                "ts": int(time.time()),
                "ip": client_ip,
                "score_raw": total_score,
                "score_norm": s_norm,
                "prob": p_attack,
                "desc": all_descriptions,
                "url": url,
                "payload": payload_summary,  # se cifrará en record_xss_event
            })
        except Exception:
            logger.exception("failed to record XSS event")

        # Asignar información de ataque al request para uso posterior (e.g., en vistas o middleware de respuesta)
        request.xss_attack_info = {
            "ip": client_ip,
            "tipos": ["XSS"],
            "descripcion": all_descriptions,
            "payload": payload_for_request,
            "score_raw": total_score,
            "score_norm": s_norm,
            "prob": p_attack,
            "url": url,
        }

        # Políticas de bloqueo (similar a SQLi, pero ajustadas para XSS)
        if s_norm >= XSS_NORM_THRESHOLDS["HIGH"]:
            level, timeout = cache_block_ip_with_backoff(client_ip)
            logger.error(f"[XSSBlock] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} URL={url}")
            request.xss_attack_info.update({"blocked": True, "action": "block", "block_timeout": timeout, "block_level": level})
            # Setear flag para bloqueo
            request.xss_block = True
            request.xss_block_response = HttpResponseForbidden("Request blocked by XSS defense")
            return None
        elif s_norm >= XSS_NORM_THRESHOLDS["MEDIUM"]:
            logger.warning(f"[XSSAlert] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} - applying counter/challenge")
            count = incr_ip_counter(client_ip)
            request.xss_attack_info.update({"blocked": False, "action": "alert", "counter": count})
            if count >= XSS_COUNTER_THRESHOLD:
                level, timeout = cache_block_ip_with_backoff(client_ip)
                cache.set(f"{XSS_CACHE_COUNTER_KEY_PREFIX}{client_ip}", 0, timeout=XSS_COUNTER_WINDOW)
                logger.error(f"[XSSAutoBlock] IP={client_ip} reached counter={count} -> blocking for {timeout}s")
                request.xss_attack_info.update({"blocked": True, "action": "auto_block", "block_timeout": timeout, "block_level": level})
                # Setear flag para bloqueo
                request.xss_block = True
                request.xss_block_response = HttpResponseForbidden("Request blocked by XSS defense (auto block)")
                return None
            if getattr(settings, "XSS_DEFENSE_USE_CHALLENGE", False):
                # Setear flag para challenge
                request.xss_challenge = True
                request.xss_challenge_response = HttpResponse("Challenge required", status=403)
                request.xss_challenge_response["X-XSS-Challenge"] = "captcha"
                return None
            return None
        elif s_norm >= XSS_NORM_THRESHOLDS["LOW"]:
            logger.info(f"[XSSMonitor] IP={client_ip} ScoreRaw={total_score:.3f} ScoreNorm={s_norm:.3f} - monitored")
            request.xss_attack_info.update({"blocked": False, "action": "monitor"})
            return None
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
