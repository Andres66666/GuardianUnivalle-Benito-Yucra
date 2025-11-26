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

import base64
import os
import json
import time
import math
import hmac
import logging
import re
import html
import urllib.parse
import ipaddress
from typing import List, Tuple, Dict, Any

from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponse
from django.core.cache import cache

# cryptography & argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from argon2.low_level import hash_secret_raw, Type as Argon2Type

# --- logger
logger = logging.getLogger("sqlidefense_crypto")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# ---------------------------
# IMPORTANTE: Configuraciones
# ---------------------------
MASTER_KEY_B64 = getattr(settings, "SQLI_DEFENSE_MASTER_KEY", None)
if not MASTER_KEY_B64:
    MASTER_KEY = os.urandom(32)
else:
    try:
        MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
    except Exception:
        MASTER_KEY = MASTER_KEY_B64.encode() if isinstance(MASTER_KEY_B64, str) else MASTER_KEY_B64

AEAD_CHOICE = getattr(settings, "SQLI_DEFENSE_AEAD", "AESGCM").upper()  # AESGCM o CHACHA20

# Argon2id parámetros (ajustables desde settings)
ARGON2_CONFIG = getattr(settings, "SQLI_DEFENSE_ARGON2", {
    "time_cost": 2,
    "memory_cost": 65536,
    "parallelism": 1,
    "hash_len": 32,
    "type": Argon2Type.ID,
})

# HMAC key derivation salt label
HMAC_LABEL = b"sqlidefense-hmac"
AEAD_LABEL = b"sqlidefense-aead"

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

SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth", "email", "username"]
DEFAULT_THRESHOLDS = getattr(settings, "SQLI_DEFENSE_THRESHOLDS", {"HIGH": 1.8, "MEDIUM": 1.0, "LOW": 0.5})
BLOCK_TIMEOUT = getattr(settings, "SQLI_DEFENSE_BLOCK_SECONDS", 60 * 60)
COUNTER_WINDOW = getattr(settings, "SQLI_DEFENSE_COUNTER_WINDOW", 60 * 5)
COUNTER_THRESHOLD = getattr(settings, "SQLI_DEFENSE_COUNTER_THRESHOLD", 5)
CACHE_BLOCK_KEY_PREFIX = "sqli_block:"
CACHE_COUNTER_KEY_PREFIX = "sqli_count:"
SATURATION_C = getattr(settings, "SQLI_DEFENSE_SATURATION_C", 1.5)
SATURATION_ALPHA = getattr(settings, "SQLI_DEFENSE_SATURATION_ALPHA", 2.0)
NORM_THRESHOLDS = {
    "HIGH": getattr(settings, "SQLI_DEFENSE_NORM_HIGH", 0.2),
    "MEDIUM": getattr(settings, "SQLI_DEFENSE_NORM_MED", 0.1),
    "LOW": getattr(settings, "SQLI_DEFENSE_NORM_LOW", 0.05),
}
PROB_LAMBDA = getattr(settings, "SQLI_DEFENSE_PROB_LAMBDA", 1.0)
FIELD_WEIGHTS = getattr(settings, "SQLI_DEFENSE_FIELD_WEIGHTS", {"_query_string": 1.2, "username": 0.6, "password": 1.8, "raw": 1.0})
DEFAULT_BACKOFF_LEVELS = getattr(settings, "SQLI_DEFENSE_BACKOFF_LEVELS", [0, 60 * 15, 60 * 60, 60 * 60 * 6, 60 * 60 * 24, 60 * 60 * 24 * 7])

# -------------------------------------------------------
# Funciones criptográficas: derivación, AEAD, HMAC, util
# -------------------------------------------------------
def derive_key(label: bytes, context: bytes = b"") -> bytes:
    """
    Deriva una clave simétrica (32 bytes) a partir de MASTER_KEY usando Argon2 raw hash,
    y luego HKDF para estandarizar. Esto permite rotación si cambias MASTER_KEY.
    """
    # Argon2 raw derivation (sal pseudo-rand: label + timestamp)
    salt = (label + context)[:16].ljust(16, b"\0")  # determinista por label/context
    try:
        raw = hash_secret_raw(secret=MASTER_KEY if isinstance(MASTER_KEY, (bytes, bytearray)) else MASTER_KEY.encode(),
                              salt=salt,
                              time_cost=ARGON2_CONFIG["time_cost"],
                              memory_cost=ARGON2_CONFIG["memory_cost"],
                              parallelism=ARGON2_CONFIG["parallelism"],
                              hash_len=ARGON2_CONFIG["hash_len"],
                              type=ARGON2_CONFIG["type"])
        # pulir con HKDF para obtener 32 bytes de alta calidad
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        key = hk.derive(raw)
        return key
    except Exception:
        # fallback seguro simple: HKDF desde MASTER_KEY
        hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label + context)
        return hk.derive(MASTER_KEY if isinstance(MASTER_KEY, bytes) else MASTER_KEY.encode())


def aead_encrypt(plaintext: bytes, aad: bytes = b"", context: bytes = b"") -> Dict[str, bytes]:
    """
    Cifra con AEAD configurado (AES-GCM o ChaCha20-Poly1305).
    Retorna dict con: ciphertext, nonce, tag (si aplica), alg
    """
    key = derive_key(AEAD_LABEL, context)
    if AEAD_CHOICE == "CHACHA20":
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        # ChaCha20Poly1305 devuelve ciphertext+tag juntos
        return {"alg": "CHACHA20-POLY1305", "nonce": nonce, "ciphertext": ct}
    else:
        # AES-GCM (recomendado)
        aead = AESGCM(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        # AESGCM devuelve ciphertext||tag (16 bytes tag al final)
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

# -------------------------
# Helpers utilitarios
# -------------------------
def get_client_ip(request) -> str:
    trusted_proxies = getattr(settings, "SQLI_DEFENSE_TRUSTED_PROXIES", [])

    def ip_in_trusted(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            return False
        for p in trusted_proxies:
            try:
                if '/' in p:
                    if ip_obj in ipaddress.ip_network(p, strict=False):
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(p):
                        return True
            except Exception:
                continue
        return False

    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for ip_candidate in parts:
            try:
                ipaddress.ip_address(ip_candidate)
            except Exception:
                continue
            if not ip_in_trusted(ip_candidate):
                return ip_candidate
        if parts:
            return parts[-1]

    xr = request.META.get("HTTP_X_REAL_IP", "")
    if xr:
        try:
            ipaddress.ip_address(xr)
            if not ip_in_trusted(xr):
                return xr
        except Exception:
            pass

    hcip = request.META.get("HTTP_CLIENT_IP", "")
    if hcip:
        try:
            ipaddress.ip_address(hcip)
            return hcip
        except Exception:
            pass

    remote = request.META.get("REMOTE_ADDR", "")
    return remote or ""

def normalize_input(s: str) -> str:
    if not s:
        return ""
    try:
        s_dec = urllib.parse.unquote_plus(s)
    except Exception:
        s_dec = s
    try:
        s_dec = html.unescape(s_dec)
    except Exception:
        pass
    s_dec = re.sub(r"\\x([0-9a-fA-F]{2})", r"\\x\g<1>", s_dec)
    s_dec = re.sub(r"\s+", " ", s_dec)
    return s_dec.strip()

def weight_to_prob(w: float) -> float:
    try:
        lam = float(PROB_LAMBDA)
        q = 1.0 - math.exp(-max(float(w), 0.0) / lam)
        return min(max(q, 0.0), 0.999999)
    except Exception:
        return min(max(w, 0.0), 0.999999)

def combine_probs(qs: List[float]) -> float:
    prod = 1.0
    for q in qs:
        prod *= (1.0 - q)
    return 1.0 - prod

def saturate_score(raw_score: float) -> float:
    try:
        x = float(raw_score)
        alpha = float(SATURATION_ALPHA)
        c = float(SATURATION_C)
        return 1.0 / (1.0 + math.exp(-alpha * (x - c)))
    except Exception:
        return 0.0

# Reusaremos el detector
def detect_sql_injection(text: str) -> Dict:
    norm = normalize_input(text or "")
    score = 0.0
    matches = []
    pattern_occurrences = {}
    for pattern, desc, weight in SQL_PATTERNS:
        for _ in pattern.finditer(norm):
            pattern_occurrences[pattern.pattern] = pattern_occurrences.get(pattern.pattern, 0) + 1
    prob_list = []
    for pattern, desc, weight in SQL_PATTERNS:
        occ = pattern_occurrences.get(pattern.pattern, 0)
        if occ > 0:
            added = 0.0
            for i in range(occ):
                added += weight * (0.5 ** i)
            score += added
            matches.append((desc, pattern.pattern, weight, occ, round(added, 3)))
            q = weight_to_prob(added)
            prob_list.append(q)
    return {
        "score": round(score, 3),
        "matches": matches,
        "descriptions": list({m[0] for m in matches}),
        "sample": norm[:1200],
        "prob_list": prob_list,
    }

# Redactar payload summary (ahora se encripta snippets antes de loggear)
def redact_and_encrypt_payload(payload_summary: List[Dict[str, Any]], context: bytes = b"") -> List[Dict[str, Any]]:
    encrypted_list = []
    for p in payload_summary:
        snippet = p.get("snippet", "")
        is_sensitive = p.get("sensitive", False)
        # Decide: si sensible -> cifrar, si no -> truncar + cifrar si score alto
        try:
            enc = aead_encrypt(snippet.encode("utf-8"), aad=b"", context=context)
            htag = compute_hmac(enc["ciphertext"], context=context)
            enc_b64 = {
                "alg": enc["alg"],
                "nonce": base64.b64encode(enc["nonce"]).decode(),
                "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),
                "hmac": base64.b64encode(htag).decode(),
            }
            encrypted_list.append({"field": p.get("field"), "encrypted": enc_b64, "sensitive": is_sensitive})
            
        except Exception:
            # fallback: redact
            encrypted_list.append({"field": p.get("field"), "snippet": "<REDACTED>", "sensitive": is_sensitive})
    return encrypted_list

# Cache helpers
def cache_block_ip_with_backoff(ip: str):
    if not ip:
        return 0, 0
    level_key = f"{CACHE_BLOCK_KEY_PREFIX}{ip}:level"
    level = cache.get(level_key, 0) or 0
    level = int(level) + 1
    cache.set(level_key, level, timeout=60 * 60 * 24 * 7)
    durations = DEFAULT_BACKOFF_LEVELS
    idx = min(level, len(durations) - 1)
    timeout = durations[idx]
    cache.set(f"{CACHE_BLOCK_KEY_PREFIX}{ip}", True, timeout=timeout)
    return level, timeout

def is_ip_blocked(ip: str) -> bool:
    if not ip:
        return False
    return bool(cache.get(f"{CACHE_BLOCK_KEY_PREFIX}{ip}"))

def incr_ip_counter(ip: str) -> int:
    if not ip:
        return 0
    key = f"{CACHE_COUNTER_KEY_PREFIX}{ip}"
    current = cache.get(key, 0)
    try:
        current = int(current)
    except Exception:
        current = 0
    current += 1
    cache.set(key, current, timeout=COUNTER_WINDOW)
    return current

def record_detection_event(event: dict) -> None:
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
                del event["payload"]
            except Exception:
                event.pop("payload", None)
        key = f"sqli_event:{ts}:{event.get('ip', '')}"
        cache.set(key, json.dumps(event, ensure_ascii=False), timeout=60 * 60 * 24)
    except Exception:
        logger.exception("record_detection_event failed")

# --------------------------
# Middleware principal
# --------------------------
class SQLIDefenseCryptoMiddleware(MiddlewareMixin):
    def process_request(self, request):
        client_ip = get_client_ip(request)

        # Chequear bloqueo
        if is_ip_blocked(client_ip):
            warning_message = (
                "Acceso denegado. Su dirección IP y actividades han sido registradas y monitoreadas. "
                "Continuar con estos intentos podría resultar en exposición pública, bloqueos permanentes o acciones legales. "
                "Recomendamos detenerse inmediatamente para evitar riesgos mayores."
            )
            logger.warning(f"[SQLiBlock:Persistent] IP={client_ip} - Intento persistente de acceso bloqueado. Mensaje enviado.")
            return HttpResponseForbidden(warning_message)


        trusted_ips = getattr(settings, "SQLI_DEFENSE_TRUSTED_IPS", [])
        if client_ip and client_ip in trusted_ips:
            return None

        trusted_urls = getattr(settings, "SQLI_DEFENSE_TRUSTED_URLS", [])
        referer = request.META.get("HTTP_REFERER", "")
        host = request.get_host()
        if any(url in referer for url in trusted_urls) or any(url in host for url in trusted_urls):
            return None

        # Extraer payload
        data = {}
        try:
            ct = request.META.get("CONTENT_TYPE", "")
            if "application/json" in ct:
                raw = request.body.decode("utf-8") or "{}"
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        data = parsed
                    else:
                        data = {"raw": raw}
                except Exception:
                    data = {"raw": raw}
            else:
                try:
                    post = request.POST.dict()
                    if post:
                        data = post
                    else:
                        raw = request.body.decode("utf-8", errors="ignore")
                        data = {"raw": raw} if raw else {}
                except Exception:
                    raw = request.body.decode("utf-8", errors="ignore")
                    data = {"raw": raw} if raw else {}
        except Exception:
            data = {}

        qs = request.META.get("QUERY_STRING", "")
        if qs:
            if isinstance(data, dict):
                data["_query_string"] = qs
            else:
                data = {"_query_string": qs, "raw": str(data)}

        if not data:
            return None

        # Detectar SQLi por campo
        total_score = 0.0
        all_descriptions = []
        payload_summary = []
        global_prob_list = []

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    try:
                        vtext = json.dumps(value, ensure_ascii=False)
                    except Exception:
                        vtext = str(value)
                else:
                    vtext = str(value or "")

                result = detect_sql_injection(vtext)
                field_weight = FIELD_WEIGHTS.get(str(key), 1.0)
                added_score = result.get("score", 0.0) * float(field_weight)
                total_score += added_score
                for q in result.get("prob_list", []):
                    q_field = 1.0 - ((1.0 - q) ** float(field_weight))
                    global_prob_list.append(q_field)
                all_descriptions.extend(result.get("descriptions", []))
                if result.get("score", 0) > 0:
                    is_sensitive = isinstance(key, str) and key.lower() in SENSITIVE_FIELDS
                    payload_summary.append({"field": key, "snippet": vtext[:300], "sensitive": is_sensitive})
        else:
            raw = str(data)
            result = detect_sql_injection(raw)
            total_score += result.get("score", 0.0)
            all_descriptions.extend(result.get("descriptions", []))
            for q in result.get("prob_list", []):
                global_prob_list.append(q)
            if result.get("score", 0) > 0:
                payload_summary.append({"field": "raw", "snippet": raw[:500], "sensitive": False})

        if total_score == 0 and not global_prob_list:
            return None

        # normalización y probabilidad combinada
        p_attack = combine_probs(global_prob_list) if global_prob_list else 0.0
        s_norm = saturate_score(total_score)

        # Encriptar / redactar payload summaries antes de loggear/almacenar
        ctx = f"{client_ip}-{int(time.time())}".encode()
        try:
            encrypted_payload = redact_and_encrypt_payload(payload_summary, context=ctx)
        except Exception:
            encrypted_payload = [{"field": p.get("field"), "snippet": "<REDACTED>", "sensitive": p.get("sensitive", False)} for p in payload_summary]

        logger.warning(
            f"[SQLiDetect] IP={client_ip} Host={host} Score={total_score:.2f} S_norm={s_norm:.3f} P_attack={p_attack:.3f} Desc={all_descriptions} Payload_enc_snippets={json.dumps(encrypted_payload)[:1000]}"
        )

        request.sql_attack_info = {
            "ip": client_ip,
            "tipos": ["SQLi"],
            "descripcion": all_descriptions,
            "payload": json.dumps(encrypted_payload, ensure_ascii=False)[:2000],
            "score": round(total_score, 3),
            "s_norm": round(s_norm, 3),
            "p_attack": round(p_attack, 3),
            "url": request.build_absolute_uri(),
        }

        # registrar evento cifrado
        try:
            record_detection_event({
                "ts": int(time.time()),
                "ip": client_ip,
                "score": total_score,
                "s_norm": s_norm,
                "p_attack": p_attack,
                "desc": all_descriptions,
                "url": request.build_absolute_uri(),
                "payload": encrypted_payload,  # ya viene cifrado dentro de redact_and_encrypt_payload
            })
        except Exception:
            logger.exception("failed to record event")

        # Políticas de bloqueo: setea flags en lugar de retornar HttpResponseForbidden
        if p_attack >= getattr(settings, "SQLI_DEFENSE_P_ATTACK_BLOCK", 0.97):
            level, timeout = cache_block_ip_with_backoff(client_ip)
            logger.error(f"[SQLiBlock:P_attack] IP={client_ip} P={p_attack:.3f} -> level={level} timeout={timeout}s")
            request.sql_attack_info.update({"blocked": True, "action": "block_p_attack", "block_timeout": timeout, "block_level": level})
            # Nuevo: setea flag para bloqueo en lugar de retornar
            request.sql_block = True
            request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense (probability)")
            return None  # No retorna respuesta aquí
        if s_norm >= NORM_THRESHOLDS["HIGH"]:
            level, timeout = cache_block_ip_with_backoff(client_ip)
            logger.error(f"[SQLiBlock] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} URL={request.path}")
            request.sql_attack_info.update({"blocked": True, "action": "block", "block_timeout": timeout, "block_level": level})
            # Nuevo: setea flag para bloqueo
            request.sql_block = True
            request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense")
            return None
        elif s_norm >= NORM_THRESHOLDS["MEDIUM"]:
            logger.warning(f"[SQLiAlert] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} - applying counter/challenge")
            count = incr_ip_counter(client_ip)
            request.sql_attack_info.update({"blocked": False, "action": "alert", "counter": count})
            if count >= COUNTER_THRESHOLD:
                level, timeout = cache_block_ip_with_backoff(client_ip)
                cache.set(f"{CACHE_COUNTER_KEY_PREFIX}{client_ip}", 0, timeout=COUNTER_WINDOW)
                logger.error(f"[SQLiAutoBlock] IP={client_ip} reached counter={count} -> blocking for {timeout}s")
                request.sql_attack_info.update({"blocked": True, "action": "auto_block", "block_timeout": timeout, "block_level": level})
                # Nuevo: setea flag para bloqueo
                request.sql_block = True
                request.sql_block_response = HttpResponseForbidden("Request blocked by SQLI defense (auto block)")
                return None
            if getattr(settings, "SQLI_DEFENSE_USE_CHALLENGE", False):
                # Nuevo: setea flag para challenge
                request.sql_challenge = True
                request.sql_challenge_response = HttpResponse("Challenge required", status=403)
                request.sql_challenge_response["X-SQLI-Challenge"] = "captcha"
                return None
            return None
        elif s_norm >= NORM_THRESHOLDS["LOW"]:
            logger.info(f"[SQLiMonitor] IP={client_ip} Score={total_score:.2f} S_norm={s_norm:.3f} - monitored")
            request.sql_attack_info.update({"blocked": False, "action": "monitor"})
            return None
        return None