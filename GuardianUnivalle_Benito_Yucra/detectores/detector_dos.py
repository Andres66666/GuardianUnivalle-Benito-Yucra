import time
import json
import logging
import hashlib
from typing import Dict, List, Tuple

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden

logger = logging.getLogger("dosdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

DOS_LIMITE_PETICIONES = int(getattr(settings, "DOS_LIMITE_PETICIONES", 120))
DOS_VENTANA_SEGUNDOS = int(getattr(settings, "DOS_VENTANA_SEGUNDOS", 60))
DOS_TIEMPO_BLOQUEO = int(getattr(settings, "DOS_TIEMPO_BLOQUEO", 300))
DOS_TRUSTED_IPS = list(getattr(settings, "DOS_TRUSTED_IPS", []))

DOS_PESO = float(getattr(settings, "DOS_PESO", 0.6))
DOS_PESO_BLACKLIST = float(getattr(settings, "DOS_PESO_BLACKLIST", 0.15))
DOS_PESO_HEURISTICA = float(getattr(settings, "DOS_PESO_HEURISTICA", 0.25))
DOS_UMBRAL_BLOQUEO = float(getattr(settings, "DOS_UMBRAL_BLOQUEO", 0.8))
DOS_LIMITE_ENDPOINTS = int(getattr(settings, "DOS_LIMITE_ENDPOINTS", 80))

DOS_WARN_RATIO = float(getattr(settings, "DOS_WARN_RATIO", 0.75))
DOS_WARN_MIN_SCORE = float(getattr(settings, "DOS_WARN_MIN_SCORE", 0.20))
DOS_WARN_MIN_REQ = int(getattr(settings, "DOS_WARN_MIN_REQ", max(10, int(DOS_LIMITE_PETICIONES * 0.2))))

_STATE_RATE: Dict[str, List[float]] = {}
_STATE_ENDPOINTS: Dict[str, Dict[str, float]] = {}
_STATE_BLOCKS: Dict[str, float] = {}

def get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "0.0.0.0"

def stable_fingerprint(request) -> str:
    ua = (request.META.get("HTTP_USER_AGENT", "") or "")[:200]
    acc = (request.META.get("HTTP_ACCEPT", "") or "")[:120]
    lang = (request.META.get("HTTP_ACCEPT_LANGUAGE", "") or "")[:40]
    ip = get_client_ip(request)
    raw = f"{ip}|{ua}|{acc}|{lang}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

def compute_actor_id(request) -> Tuple[str, str]:
    try:
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return f"user:{user.pk}", "user"
    except Exception:
        pass
    fp = stable_fingerprint(request)
    return f"fp:{fp}", "fingerprint"

def purge_old(now_ts: float) -> None:
    for k in list(_STATE_BLOCKS.keys()):
        if _STATE_BLOCKS.get(k, 0) <= now_ts:
            _STATE_BLOCKS.pop(k, None)

    cutoff = now_ts - DOS_VENTANA_SEGUNDOS
    for actor, times in list(_STATE_RATE.items()):
        new_times = [t for t in times if t >= cutoff]
        if new_times:
            _STATE_RATE[actor] = new_times
        else:
            _STATE_RATE.pop(actor, None)

    for actor, eps in list(_STATE_ENDPOINTS.items()):
        new_eps = {p: ts for p, ts in eps.items() if ts >= cutoff}
        if new_eps:
            _STATE_ENDPOINTS[actor] = new_eps
        else:
            _STATE_ENDPOINTS.pop(actor, None)

def incr_rate(actor_key: str, now_ts: float) -> int:
    times = _STATE_RATE.get(actor_key)
    if times is None:
        times = []
        _STATE_RATE[actor_key] = times
    times.append(now_ts)

    cutoff = now_ts - DOS_VENTANA_SEGUNDOS
    i = 0
    while i < len(times) and times[i] < cutoff:
        i += 1
    if i:
        del times[:i]
    return len(times)

def add_endpoint(actor_key: str, path: str, now_ts: float) -> int:
    eps = _STATE_ENDPOINTS.get(actor_key)
    if eps is None:
        eps = {}
        _STATE_ENDPOINTS[actor_key] = eps
    eps[path] = now_ts

    cutoff = now_ts - DOS_VENTANA_SEGUNDOS
    for p, ts in list(eps.items()):
        if ts < cutoff:
            eps.pop(p, None)

    if len(eps) > max(DOS_LIMITE_ENDPOINTS * 2, 200):
        for p, ts in sorted(eps.items(), key=lambda x: x[1])[: max(len(eps) - 150, 1)]:
            eps.pop(p, None)

    return len(eps)

def is_blocked(actor_key: str) -> bool:
    return _STATE_BLOCKS.get(actor_key, 0) > time.time()

def block_actor(actor_key: str, seconds: int) -> None:
    _STATE_BLOCKS[actor_key] = time.time() + max(1, int(seconds))

def analizar_headers_avanzado(user_agent: str, referer: str) -> List[str]:
    sospechas = []
    ua_low = (user_agent or "").lower()
    if not user_agent or len(user_agent) < 8:
        sospechas.append("User-Agent vacío/corto")
    automation_keywords = ["curl", "wget", "bot", "spider", "scraper", "headless", "phantom", "selenium", "python-requests"]
    if any(k in ua_low for k in automation_keywords):
        sospechas.append("Herramienta de automatización detectada")
    ref_low = (referer or "").lower()
    if referer and any(k in ref_low for k in ["attack", "scan", "sqlmap", "nmap"]):
        sospechas.append("Referer indicando abuso")
    return sospechas

def calc_dos_score(rate: int, limit: int) -> float:
    propor = rate / max(limit, 1)
    return round(min(DOS_PESO * min(propor, 2.0), 1.0), 3)

def get_blacklist_cached():
    return set()

def check_ip_in_advanced_blacklist(client_ip: str, global_blacklist_cidrs) -> bool:
    return False

class DOSDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        now_ts = time.time()
        purge_old(now_ts)

        client_ip = get_client_ip(request)
        if client_ip in DOS_TRUSTED_IPS:
            return None

        actor_key, actor_type = compute_actor_id(request)

        if is_blocked(actor_key):
            request.dos_attack_info = {
                "actor": actor_key,
                "actor_type": actor_type,
                "ip": client_ip,
                "fingerprint": actor_key.replace("fp:", ""),
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": ["Bloqueo DoS activo (rate-limit)"],
                "payload": json.dumps({
                    "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                    "referer": request.META.get("HTTP_REFERER", ""),
                    "path": request.path,
                }),
                "score": 1.0,
                "tasa": None,
                "endpoints_distintos": None,
                "blocked": True,
                "url": request.build_absolute_uri(),
            }
            request.dos_block = True
            request.dos_block_response = HttpResponseForbidden(
                "Acceso denegado temporalmente por comportamiento sospechoso."
            )
            logger.warning(f"[DOSBlock:Active] actor={actor_key} type={actor_type} ip={client_ip} path={request.path}")
            return None

        if (
            hasattr(request, "xss_attack_info") or hasattr(request, "xss_block") or hasattr(request, "xss_challenge")
            or hasattr(request, "csrf_attack_info") or hasattr(request, "csrf_block") or hasattr(request, "csrf_challenge")
            or hasattr(request, "sql_attack_info") or hasattr(request, "sql_block") or hasattr(request, "sql_challenge")
        ):
            return None

        user_agent = request.META.get("HTTP_USER_AGENT", "")
        referer = request.META.get("HTTP_REFERER", "")
        path = request.path

        tasa = incr_rate(actor_key, now_ts)
        endpoints_distintos = add_endpoint(actor_key, path, now_ts)

        nivel_dos = calc_dos_score(tasa, DOS_LIMITE_PETICIONES)

        ip_blacklist = get_blacklist_cached()
        en_blacklist = check_ip_in_advanced_blacklist(client_ip, ip_blacklist)
        nivel_blacklist = (DOS_PESO_BLACKLIST if en_blacklist and tasa >= DOS_WARN_MIN_REQ else 0.0)

        sospechas_headers = analizar_headers_avanzado(user_agent, referer)
        score_headers = 0.5 if sospechas_headers else 0.0
        score_endpoints = 0.5 if endpoints_distintos > DOS_LIMITE_ENDPOINTS else 0.0
        nivel_heuristica = DOS_PESO_HEURISTICA * (score_headers + score_endpoints)

        S_total = round(nivel_dos + nivel_blacklist + nivel_heuristica, 3)

        if S_total >= DOS_UMBRAL_BLOQUEO:
            block_actor(actor_key, DOS_TIEMPO_BLOQUEO)

            descripcion = [
                f"Score Total: {S_total:.3f} (Tasa: {tasa} en {DOS_VENTANA_SEGUNDOS}s)",
                f"endpoints_distintos={endpoints_distintos}",
            ]
            if en_blacklist and nivel_blacklist > 0:
                descripcion.append("IP en blacklist (ponderada)")
            if sospechas_headers:
                descripcion.extend(sospechas_headers)
            if endpoints_distintos > DOS_LIMITE_ENDPOINTS:
                descripcion.append("Muchos endpoints distintos (posible scraping/escaneo)")
            descripcion.append(f"Ruta: {path}")

            request.dos_attack_info = {
                "actor": actor_key,
                "actor_type": actor_type,
                "ip": client_ip,
                "fingerprint": actor_key.replace("fp:", ""),
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": descripcion,
                "payload": json.dumps({"user_agent": user_agent, "referer": referer, "path": path}),
                "score": S_total,
                "tasa": tasa,
                "endpoints_distintos": endpoints_distintos,
                "blocked": True,
                "url": request.build_absolute_uri(),
            }
            request.dos_block = True
            request.dos_block_response = HttpResponseForbidden(
                "Acceso denegado por alto Score de Amenaza (DoS)."
            )

            logger.error(
                "[DOSBlock] actor=%s type=%s ip=%s score=%s tasa=%s/%s endpoints=%s/%s path=%s susp=%s",
                actor_key, actor_type, client_ip, f"{S_total:.3f}",
                tasa, DOS_LIMITE_PETICIONES, endpoints_distintos, DOS_LIMITE_ENDPOINTS,
                path, sospechas_headers,
            )
            return None

        warn_condition = (
            (S_total >= max(DOS_WARN_MIN_SCORE, DOS_UMBRAL_BLOQUEO * DOS_WARN_RATIO))
            or (tasa >= max(DOS_WARN_MIN_REQ, int(DOS_LIMITE_PETICIONES * DOS_WARN_RATIO)))
            or bool(sospechas_headers)
            or (endpoints_distintos > DOS_LIMITE_ENDPOINTS)
        )

        if warn_condition:
            descripcion = [f"Score Total: {S_total:.3f} (Tasa: {tasa} en {DOS_VENTANA_SEGUNDOS}s)"]
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
                "fingerprint": actor_key.replace("fp:", ""),
                "tipos": ["DoS", "Scraping/Escaneo"],
                "descripcion": descripcion,
                "payload": json.dumps({"user_agent": user_agent, "referer": referer, "path": path}),
                "score": S_total,
                "tasa": tasa,
                "endpoints_distintos": endpoints_distintos,
                "blocked": False,
                "url": request.build_absolute_uri(),
            }

        return None