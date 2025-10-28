# xss_defense.py
# GuardianUnivalle_Benito_Yucra/detectores/xss_defense.py
from __future__ import annotations
import json
import logging
import re
from typing import List, Tuple, Any, Dict
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

# -------------------------------------------------
# Logger
# -------------------------------------------------
logger = logging.getLogger("xssdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# -------------------------------------------------
# Intentar usar bleach (si está instalado). Si no,
# seguimos con heurísticos de patrones.
# -------------------------------------------------
try:
    import bleach
    _BLEACH_AVAILABLE = True
except Exception:
    _BLEACH_AVAILABLE = False

# -------------------------------------------------
# Patrones XSS con peso (descripcion, peso) - EXPANDIDOS PARA ROBUSTEZ
# - pesos mayores = más severo (por ejemplo <script> o javascript:)
# - Agregados patrones para DOM-based, polyglots y evasiones avanzadas
# -------------------------------------------------
XSS_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # ---------- Máxima severidad / ejecución directa ----------
    (re.compile(r"<\s*script\b", re.I), "Etiqueta <script> (directa)", 0.95),
    (re.compile(r"<\s*s\s*c\s*r\s*i\s*p\s*t\b", re.I), "Etiqueta <script> ofuscada", 0.90),
    (re.compile(r"\b(document\.cookie|document\.write|document\.location|location\.href|window\.location)\b", re.I),
     "Acceso a document / location (cookie/location/write)", 0.90),
    (re.compile(r"\b(eval|setTimeout|setInterval|Function|new Function)\s*\(", re.I),
     "Ejecución dinámica (eval/Function/setTimeout)", 0.88),

    # ---------- URIs peligrosas ----------
    (re.compile(r"\bjavascript\s*:", re.I), "URI javascript:", 0.85),
    (re.compile(r"\bdata\s*:\s*text\/html\b", re.I), "URI data:text/html", 0.82),
    (re.compile(r"\bdata\s*:\s*text\/html;base64\b", re.I), "URI data:text/html;base64", 0.82),
    (re.compile(r"\bvbscript\s*:", re.I), "URI vbscript:", 0.7),

    # ---------- Etiquetas y vectores alternativos ----------
    (re.compile(r"<\s*(iframe|embed|object|svg|math|meta)\b", re.I), "IFrame/Embed/Object/SVG/Meta", 0.88),
    (re.compile(r"<\s*img\b[^>]*\bonerror\b", re.I), "<img ... onerror>", 0.86),
    (re.compile(r"<\s*svg\b[^>]*\bonload\b", re.I), "SVG con onload/on* (SVG vector)", 0.84),

    # ---------- Atributos de evento (on*) ----------
    (re.compile(r"\s+on[a-zA-Z]+\s*=", re.I), "Atributo de evento (on*)", 0.80),
    (re.compile(r"<\s*(a|img|body|div|span|form|input|button)\b[^>]*on[a-zA-Z]+\s*=", re.I),
     "Elemento con evento on* (a,img,body,...)", 0.82),

    # ---------- Inyección en contextos JS / JSON / script ----------
    (re.compile(r"<\s*script[^>]*>.*?</\s*script\s*>", re.I | re.S), "Script inline completo", 0.92),
    (re.compile(r"'\s*;\s*alert\s*\(|\"\s*;\s*alert\s*\(", re.I), "Inyección en cadenas JS (breakout + alert)", 0.78),
    (re.compile(r"\bJSON\.parse\(|\beval\(\s*JSON", re.I), "JSON parse/eval inseguro", 0.75),

    # ---------- Encodings, entidades y mutaciones ----------
    (re.compile(r"&#x[0-9a-fA-F]+;|&#\d+;", re.I), "Entidades HTML / encoding (posible bypass)", 0.70),
    (re.compile(r"%3C\s*script|%3Cscript%3E", re.I), "Tags URL-encoded (%3Cscript)", 0.68),
    (re.compile(r"(?:\\x3C|\\u003C)\s*script", re.I), "Escapes JS/Unicode que forman <script>", 0.68),

    # ---------- DOM clobbering / nombres reservados ----------
    (re.compile(r'\bid\s*=\s*"(?:form|image|submit|action|location|name)"', re.I), "IDs que causan DOM clobbering", 0.65),
    (re.compile(r'\bname\s*=\s*"(?:form|submit|action|location)"', re.I), "Names que pueden clobber", 0.65),

    # ---------- Atributos URI en tags (href/src) ----------
    (re.compile(r'<\s*a\b[^>]*\bhref\s*=\s*[\'"]\s*javascript\s*:', re.I), "<a href=\"javascript:...\">", 0.84),
    (re.compile(r'<\s*(img|script|iframe)\b[^>]*\bsrc\s*=\s*[\'"]\s*javascript\s*:', re.I),
     "src=javascript: en tags", 0.84),

    # ---------- Vectores en CSS / style ----------
    (re.compile(r"\bstyle\s*=\s*[\"'][^\"']*(expression\s*\(|url\s*\(\s*javascript:)", re.I), "Estilo con expression() o url(javascript:)", 0.66),
    (re.compile(r"@import\s+url\s*\(", re.I), "CSS @import posibles vectores", 0.45),

    # ---------- Comentarios y CDATA para evasión ----------
    (re.compile(r"<!\[CDATA\[|\/\/\s*<\s*!\s*\[CDATA\[", re.I), "CDATA o comentarios para evasión", 0.48),
    (re.compile(r"<!--|-->", re.I), "Comentarios HTML (posible ofuscación/evitación)", 0.30),

    # ---------- Polyglot / mutation / browser quirks ----------
    (re.compile(r"(?:<\s*svg[^>]*>.*?<\s*/\s*svg\s*>)|(?:<\s*math[^>]*>)", re.I | re.S),
     "SVG/MathML polyglot (vectores mutables)", 0.75),
    (re.compile(r"(?:\balert\s*\(|\bconsole\.log\s*\()", re.I), "Indicadores de prueba (alert/console.log)", 0.40),

    # ---------- Heurísticos de baja severidad (informativo) ----------
    (re.compile(r"<\s*form\b", re.I), "Form (posible vector de ataque relacionado)", 0.25),
    (re.compile(r"(onmouseover|onfocus|onmouseenter|onmouseleave)\b", re.I), "Eventos UI (mouseover/focus)", 0.45),

    # ---------- NUEVOS PATRONES PARA ROBUSTEZ ----------
    (re.compile(r"\binnerHTML\s*=\s*.*[<>\"']", re.I), "Asignación a innerHTML con tags", 0.85),  # DOM-based
    (re.compile(r"\bdocument\.getElementById\s*\(\s*.*\)\.innerHTML", re.I), "Manipulación DOM innerHTML", 0.80),
    (re.compile(r"<script[^>]*src\s*=\s*['\"][^'\"]*['\"][^>]*>", re.I), "Script externo (posible carga remota)", 0.75),
    (re.compile(r"\bXMLHttpRequest\s*\(\s*\)\.open\s*\(\s*['\"](GET|POST)['\"]", re.I), "XHR manipulado (posible exfiltración)", 0.70),
    (re.compile(r"<\s*link\b[^>]*\bhref\s*=\s*['\"][^'\"]*javascript\s*:", re.I), "Link con href javascript:", 0.78),
    (re.compile(r"\bwindow\.open\s*\(\s*['\"]*javascript\s*:", re.I), "window.open con javascript:", 0.82),
]

# -------------------------------------------------
# Campos sensibles: NO LOS IGNORAMOS COMPLETAMENTE, PERO LES DAMOS DESCUENTO EN SCORE
# Para robustez, los analizamos pero reducimos el peso para evitar falsos positivos.
# -------------------------------------------------
SENSITIVE_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth"]
SENSITIVE_DISCOUNT = 0.5  # Multiplicador para campos sensibles

# Umbral por defecto para considerar "alto riesgo" (Auditoria puede bloquear según su lógica)
XSS_DEFENSE_THRESHOLD = getattr(settings, "XSS_DEFENSE_THRESHOLD", 0.6)

# -------------------------------------------------
# Util: validación / extracción de IP (robusta)
# -------------------------------------------------

def _is_valid_ip(ip: str) -> bool:
    """Verifica que la cadena sea una IP válida (v4 o v6)."""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def get_client_ip(request) -> str:
    """
    Obtiene la mejor estimación de la IP del cliente:
    - Revisa X-Forwarded-For (primera IP no vacía).
    - Luego X-Real-IP, CF-Connecting-IP.
    - Finalmente REMOTE_ADDR como fallback.
    """
    # Preferir X-Forwarded-For
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # "client, proxy1, proxy2" => tomar la primera no vacía
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]

    # Otros encabezados comunes
    for h in ("HTTP_X_REAL_IP", "HTTP_CF_CONNECTING_IP", "HTTP_CLIENT_IP"):
        v = request.META.get(h)
        if v and _is_valid_ip(v):
            return v

    # Fallback
    remote = request.META.get("REMOTE_ADDR")
    return remote or ""

# -------------------------------------------------
# Extraer payload pero evitando cabeceras (para reducir falsos positivos)
# - Devuelve dict si es JSON, o dict con 'raw' para otros cuerpos
# - NO añade User-Agent o Referer al texto a analizar
# -------------------------------------------------
def extract_body_as_map(request) -> Dict[str, Any]:
    """
    Extrae un diccionario con los datos a analizar:
    - Si JSON: devuelve el dict JSON.
    - Si form-data: devuelve request.POST.dict()
    - Si otro: devuelve {'raw': <texto>}
    """
    try:
        ct = request.META.get("CONTENT_TYPE", "")
        if "application/json" in ct:
            raw = request.body.decode("utf-8") or "{}"
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
                else:
                    # si el JSON no es un objeto (ej: lista), lo devolvemos como raw
                    return {"raw": raw}
            except Exception:
                return {"raw": raw}
        else:
            # FORM data (request.POST) u otros
            try:
                post = request.POST.dict()
                if post:
                    return post
            except Exception:
                pass
            # fallback: cuerpo crudo
            raw = request.body.decode("utf-8", errors="ignore")
            if raw:
                return {"raw": raw}
    except Exception:
        pass
    return {}

# -------------------------------------------------
# Analizar un solo valor (string) en busca de XSS usando patrones
# Devuelve (score, descripciones, matches_patterns)
# -------------------------------------------------
def detect_xss_in_value(value: str, is_sensitive: bool = False) -> Tuple[float, List[str], List[str]]:
    """
    Analiza una cadena y devuelve:
      - score acumulado (sum pesos, con descuento si es campo sensible)
      - lista de descripciones activadas
      - lista de patrones (regex.pattern) que matchearon
    """
    if not value:
        return 0.0, [], []

    score_total = 0.0
    descripcion = []
    matches = []

    # Si bleach está disponible, sanitizar y comparar para detección adicional
    if _BLEACH_AVAILABLE:
        cleaned = bleach.clean(value, strip=True)
        if cleaned != value:
            score_total += 0.5  # Penalización por cambios en sanitización
            descripcion.append("Contenido alterado por sanitización (bleach)")

    for patt, msg, weight in XSS_PATTERNS:
        if patt.search(value):
            adjusted_weight = weight * SENSITIVE_DISCOUNT if is_sensitive else weight
            score_total += adjusted_weight
            descripcion.append(msg)
            matches.append(patt.pattern)

    return round(score_total, 3), descripcion, matches

# -------------------------------------------------
# Middleware principal XSS - MEJORADO PARA ROBUSTEZ
# -------------------------------------------------
class XSSDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # 1) IP y exclusiones
        client_ip = get_client_ip(request)
        trusted_ips: List[str] = getattr(settings, "XSS_DEFENSE_TRUSTED_IPS", [])
        if client_ip and client_ip in trusted_ips:
            return None

        excluded_paths: List[str] = getattr(settings, "XSS_DEFENSE_EXCLUDED_PATHS", [])
        if any(request.path.startswith(p) for p in excluded_paths):
            return None

        # 2) Extraer datos para analizar (dict)
        data = extract_body_as_map(request)

        # Incluir querystring (como campo separado) para análisis si existe
        qs = request.META.get("QUERY_STRING", "")
        if qs:
            data["_query_string"] = qs

        if not data:
            return None

        total_score = 0.0
        all_descriptions: List[str] = []
        all_matches: List[str] = []
        payload_summary = []

        # 3) Analizar campo por campo (si es dict) o el raw - AHORA ANALIZA TODO, CON DESCUENTO PARA SENSIBLES
        if isinstance(data, dict):
            for key, value in data.items():
                is_sensitive = isinstance(key, str) and key.lower() in SENSITIVE_FIELDS

                # convertir a string si es otro tipo (list, int...)
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
                all_matches.extend(matches)

                if s > 0:
                    payload_summary.append({"field": key, "snippet": vtext[:300], "sensitive": is_sensitive})

        else:
            # si no es dict, analizar el raw como texto
            raw = str(data)
            s, descs, matches = detect_xss_in_value(raw)
            total_score += s
            all_descriptions.extend(descs)
            all_matches.extend(matches)
            if s > 0:
                payload_summary.append({"field": "raw", "snippet": raw[:500], "sensitive": False})

        # 4) si no detectó nada, continuar
        if total_score == 0:
            return None

        # 5) construir info para auditoría (truncada)
        url = request.build_absolute_uri()
        score_rounded = round(total_score, 3)
        payload_for_request = json.dumps(payload_summary, ensure_ascii=False)[:2000]

        logger.warning(
            "XSS detectado desde IP %s URL=%s Score=%.3f Desc=%s (Robust: incluye sensibles con descuento)",
            client_ip,
            url,
            score_rounded,
            all_descriptions,
        )

        # 6) marcar en el request (AuditoriaMiddleware lo consumirá)
        request.xss_attack_info = {
            "ip": client_ip,
            "tipos": ["XSS"],
            "descripcion": all_descriptions,
            "payload": payload_for_request,
            "score": score_rounded,
            "url": url,
        }    
        # 7) NO bloquear aquí — lo hace AuditoriaMiddleware según su política
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
"""
