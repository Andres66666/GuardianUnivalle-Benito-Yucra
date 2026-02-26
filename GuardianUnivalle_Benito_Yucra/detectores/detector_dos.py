import time
import json
import logging
from typing import Dict, List, Tuple, Optional

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.core.cache import cache

logger = logging.getLogger("dosdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =========================
# Settings (con defaults)
# =========================
DOS_LIMITE_PETICIONES = int(getattr(settings, "DOS_LIMITE_PETICIONES", 120))      # req/VENTANA
DOS_VENTANA_SEGUNDOS = int(getattr(settings, "DOS_VENTANA_SEGUNDOS", 60))        # segundos
DOS_TIEMPO_BLOQUEO = int(getattr(settings, "DOS_TIEMPO_BLOQUEO", 300))           # segundos
DOS_TRUSTED_IPS = list(getattr(settings, "DOS_TRUSTED_IPS", []))

DOS_PESO = float(getattr(settings, "DOS_PESO", 0.6))
DOS_PESO_BLACKLIST = float(getattr(settings, "DOS_PESO_BLACKLIST", 0.15))        # 👈 baja para evitar falsos positivos
DOS_PESO_HEURISTICA = float(getattr(settings, "DOS_PESO_HEURISTICA", 0.25))      # heurística solo si hay señales
DOS_UMBRAL_BLOQUEO = float(getattr(settings, "DOS_UMBRAL_BLOQUEO", 0.8))

DOS_LIMITE_ENDPOINTS = int(getattr(settings, "DOS_LIMITE_ENDPOINTS", 80))

# Nuevo: umbral de warning real (para no spamear logs)
DOS_WARN_RATIO = float(getattr(settings, "DOS_WARN_RATIO", 0.75))  # 75% del umbral
DOS_WARN_MIN_SCORE = float(getattr(settings, "DOS_WARN_MIN_SCORE", 0.20))  # no warn si score es minúsculo
DOS_WARN_MIN_REQ = int(getattr(settings, "DOS_WARN_MIN_REQ", max(10, int(DOS_LIMITE_PETICIONES * 0.2))))

# Claves cache
DOS_BLOCK_KEY = getattr(settings, "DOS_BLOCK_KEY_PREFIX", "dos:block:")
DOS_RATE_KEY = getattr(settings, "DOS_RATE_KEY_PREFIX", "dos:rate:")
DOS_EP_KEY = getattr(settings, "DOS_EP_KEY_PREFIX", "dos:endpoints:")

# =========================
# Helpers
# =========================
def get_client_ip(request) -> str:
    """
    OJO: en proxies (Render/Nginx) la IP real suele venir en X-Forwarded-For
    """
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "0.0.0.0"


def compute_actor_id(request) -> Tuple[str, str]:
    """
    Actor = usuario autenticado o fingerprint (para login/anon).
    Esto evita falsos positivos cuando muchos usuarios comparten la misma IP.
    Retorna: (actor_key, actor_type)
    """
    # 1) Usuario autenticado
    try:
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return f"user:{user.pk}", "user"
    except Exception:
        pass

    # 2) Fingerprint (si lo tienes en tu proyecto)
    #    Si ya tienes get_attacker_fingerprint(request) úsalo directamente.
    try:
        from GuardianUnivalle_Benito_Yucra.detectores.detector_dos import get_attacker_fingerprint  # si está en el mismo módulo, quítalo
    except Exception:
        get_attacker_fingerprint = None

    if get_attacker_fingerprint:
        fp = get_attacker_fingerprint(request)
        if fp:
            return f"fp:{fp}", "fingerprint"

    # 3) Fallback: UA + Accept + path (menos robusto)
    ua = request.META.get("HTTP_USER_AGENT", "")[:200]
    acc = request.META.get("HTTP_ACCEPT", "")[:100]
    lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:50]
    path = request.path
    raw = json.dumps({"ua": ua, "acc": acc, "lang": lang, "path": path}, ensure_ascii=False)
    # hash simple (no crypto) — suficiente como fallback
    actor = str(abs(hash(raw)))
    return f"anon:{actor}", "anon"


def is_blocked(actor_key: str, client_ip: str) -> bool:
    # Bloqueo por actor (principal)
    if cache.get(f"{DOS_BLOCK_KEY}{actor_key}"):
        return True
    # Respaldo: bloqueo por IP (opcional)
    if cache.get(f"{DOS_BLOCK_KEY}ip:{client_ip}"):
        return True
    return False


def block_actor(actor_key: str, client_ip: str, seconds: int) -> None:
    cache.set(f"{DOS_BLOCK_KEY}{actor_key}", True, timeout=seconds)
    # Respaldo: bloquea IP por menos tiempo (para frenar bots NAT)
    cache.set(f"{DOS_BLOCK_KEY}ip:{client_ip}", True, timeout=min(seconds, 60))


def analizar_headers_avanzado(user_agent: str, referer: str) -> List[str]:
    sospechas = []
    if not user_agent or len(user_agent) < 10 or user_agent.lower().startswith("python-requests"):
        sospechas.append("User-Agent vacío/automatizado")

    automation_keywords = ["curl", "wget", "bot", "spider", "scraper", "headless", "phantom", "selenium"]
    ua_low = (user_agent or "").lower()
    if any(k in ua_low for k in automation_keywords):
        sospechas.append("Herramienta de automatización detectada")

    ref_low = (referer or "").lower()
    if referer and any(k in ref_low for k in ["attack", "scan", "sqlmap", "nmap"]):
        sospechas.append("Referer indicando abuso")

    return sospechas


def calc_dos_score(rate: int, limit: int) -> float:
    # sube proporcionalmente hasta 2x
    propor = rate / max(limit, 1)
    return round(min(DOS_PESO * min(propor, 2.0), 1.0), 3)


def rate_window_keys(actor_key: str, now: float) -> List[str]:
    """
    Ventana deslizante por buckets de 1s (simple y efectivo).
    Guardamos contadores por segundo en cache, sumamos últimos N segundos.
    """
    t = int(now)
    return [f"{DOS_RATE_KEY}{actor_key}:{sec}" for sec in range(t - (DOS_VENTANA_SEGUNDOS - 1), t + 1)]


def incr_rate(actor_key: str, now: float) -> int:
    """
    Incrementa contador del segundo actual y retorna tasa (suma en ventana).
    """
    sec = int(now)
    key_now = f"{DOS_RATE_KEY}{actor_key}:{sec}"

    try:
        cache.add(key_now, 0, timeout=DOS_VENTANA_SEGUNDOS + 5)
        cache.incr(key_now)
    except Exception:
        # fallback si backend no soporta incr
        current = cache.get(key_now, 0) or 0
        cache.set(key_now, int(current) + 1, timeout=DOS_VENTANA_SEGUNDOS + 5)

    # suma últimos N segundos (barato para N=60)
    total = 0
    for k in rate_window_keys(actor_key, now):
        v = cache.get(k, 0) or 0
        try:
            total += int(v)
        except Exception:
            pass
    return total


def add_endpoint(actor_key: str, path: str) -> int:
    """
    Cuenta endpoints distintos en ventana (simple).
    """
    key = f"{DOS_EP_KEY}{actor_key}"
    endpoints = cache.get(key)
    if not isinstance(endpoints, list):
        endpoints = []

    if path not in endpoints:
        endpoints.append(path)

    # recorta para evitar crecimiento infinito
    if len(endpoints) > max(DOS_LIMITE_ENDPOINTS * 2, 200):
        endpoints = endpoints[-max(DOS_LIMITE_ENDPOINTS, 100):]

    cache.set(key, endpoints, timeout=DOS_VENTANA_SEGUNDOS + 10)
    return len(endpoints)


# Si tú ya tienes threat intel/blacklist, integra aquí:
def get_blacklist_cached():
    return set()

def check_ip_in_advanced_blacklist(client_ip: str, global_blacklist_cidrs) -> bool:
    return False


# =========================
# Middleware
# =========================
class DOSDefenseMiddleware(MiddlewareMixin):
    """
    - Rate limit por actor (user_id o fingerprint) para evitar falsos positivos por NAT/WiFi.
    - Cache/Redis (funciona multi-worker).
    - Warning logs solo cuando realmente hay riesgo.
    """

    def process_request(self, request):
        now = time.time()
        client_ip = get_client_ip(request)

        # Allowlist
        if client_ip in DOS_TRUSTED_IPS:
            return None

        actor_key, actor_type = compute_actor_id(request)

        # Bloqueo activo
        if is_blocked(actor_key, client_ip):
            logger.warning(f"[DOSBlock:Active] actor={actor_key} type={actor_type} ip={client_ip} path={request.path}")
            return HttpResponseForbidden("Acceso denegado temporalmente por comportamiento sospechoso.")

        # Evitar duplicación si otros detectores ya bloquearon/challengeron
        if (
            hasattr(request, "xss_attack_info") or hasattr(request, "xss_block") or hasattr(request, "xss_challenge")
            or hasattr(request, "csrf_attack_info") or hasattr(request, "csrf_block") or hasattr(request, "csrf_challenge")
            or hasattr(request, "sql_attack_info") or hasattr(request, "sql_block") or hasattr(request, "sql_challenge")
        ):
            return None

        # Datos base
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        referer = request.META.get("HTTP_REFERER", "")
        path = request.path

        # 1) tasa por actor (no por IP)
        tasa = incr_rate(actor_key, now)

        # 2) endpoints distintos por actor
        endpoints_distintos = add_endpoint(actor_key, path)

        # 3) score DoS
        nivel_dos = calc_dos_score(tasa, DOS_LIMITE_PETICIONES)

        # 4) blacklist (bajar peso o condicionar a tasa alta)
        ip_blacklist = get_blacklist_cached()
        en_blacklist = check_ip_in_advanced_blacklist(client_ip, ip_blacklist)

        # Solo suma blacklist si ya hay presión (evita falsos positivos por ISP)
        nivel_blacklist = (DOS_PESO_BLACKLIST if en_blacklist and tasa >= DOS_WARN_MIN_REQ else 0.0)

        # 5) heurística (solo si hay señales)
        sospechas_headers = analizar_headers_avanzado(user_agent, referer)
        score_headers = 0.5 if sospechas_headers else 0.0
        score_endpoints = 0.5 if endpoints_distintos > DOS_LIMITE_ENDPOINTS else 0.0
        nivel_heuristica = DOS_PESO_HEURISTICA * (score_headers + score_endpoints)

        S_total = round(nivel_dos + nivel_blacklist + nivel_heuristica, 3)

        # 6) Bloqueo
        if S_total >= DOS_UMBRAL_BLOQUEO:
            block_actor(actor_key, client_ip, DOS_TIEMPO_BLOQUEO)

            logger.error(
                "[DOSBlock] actor=%s type=%s ip=%s score=%s tasa=%s/%s endpoints=%s/%s path=%s susp=%s",
                actor_key, actor_type, client_ip, f"{S_total:.3f}",
                tasa, DOS_LIMITE_PETICIONES, endpoints_distintos, DOS_LIMITE_ENDPOINTS,
                path, sospechas_headers,
            )
            return HttpResponseForbidden("Acceso denegado por alto Score de Amenaza (DoS).")

        # 7) Warning (SIN SPAM): solo si de verdad se acerca al umbral o hay señales fuertes
        warn_condition = (
            (S_total >= max(DOS_WARN_MIN_SCORE, DOS_UMBRAL_BLOQUEO * DOS_WARN_RATIO))
            or (tasa >= max(DOS_WARN_MIN_REQ, int(DOS_LIMITE_PETICIONES * DOS_WARN_RATIO)))
            or bool(sospechas_headers)
            or (endpoints_distintos > DOS_LIMITE_ENDPOINTS)
        )

        if warn_condition:
            descripcion = []
            descripcion.append(f"Score Total: {S_total:.3f} (Tasa: {tasa} en {DOS_VENTANA_SEGUNDOS}s)")
            if en_blacklist and nivel_blacklist > 0:
                descripcion.append("IP en blacklist (ponderada)")
            if sospechas_headers:
                descripcion.extend(sospechas_headers)
            if endpoints_distintos > DOS_LIMITE_ENDPOINTS:
                descripcion.append("Muchos endpoints distintos (posible scraping/escaneo)")
            descripcion.append(f"Ruta: {path}")

            logger.warning(
                "Tráfico Sospechoso actor=%s type=%s ip=%s: %s",
                actor_key, actor_type, client_ip, " ; ".join(descripcion)
            )

            request.dos_attack_info = {
                "actor": actor_key,
                "actor_type": actor_type,
                "ip": client_ip,
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": descripcion,
                "payload": json.dumps({"user_agent": user_agent, "referer": referer, "path": path}),
                "score": S_total,
                "tasa": tasa,
                "endpoints_distintos": endpoints_distintos,
                "blocked": False,
            }

        return None