# sql_defense.py
# GuardianUnivalle_Benito_Yucra/detectores/detector_sql.py

import json
import logging
import re
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
import urllib.parse
import html
from typing import List, Tuple, Dict

# ----------------------------
# Configuración del logger
# ----------------------------
logger = logging.getLogger("sqlidefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# =====================================================
# ===        PATRONES DE ATAQUE SQL DEFINIDOS       ===
# =====================================================
SQL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    # ------------------ In‑Band / Exfiltration (muy alto) ------------------
    (re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.I), "UNION SELECT (exfiltración)", 0.95),
    (re.compile(r"\bselect\b\s+.*\bfrom\b\s+.+\bwhere\b", re.I | re.S), "SELECT ... FROM ... WHERE (consulta completa)", 0.7),
    (re.compile(r"\binto\s+outfile\b|\binto\s+dumpfile\b", re.I), "INTO OUTFILE / INTO DUMPFILE (volcado a fichero)", 0.98),
    (re.compile(r"\bload_file\s*\(", re.I), "LOAD_FILE() (lectura fichero MySQL)", 0.95),
    (re.compile(r"\b(pg_read_file|pg_read_binary_file|pg_ls_dir)\s*\(", re.I), "pg_read_file / funciones lectura Postgres", 0.95),
    (re.compile(r"\bfile_read\b|\bfile_get_contents\b", re.I), "Indicadores de lectura de fichero en código", 0.85),

    # ------------------ Time‑based / Blind (muy alto) ------------------
    (re.compile(r"\b(sleep|benchmark|pg_sleep|dbms_lock\.sleep|waitfor\s+delay)\b\s*\(", re.I), "SLEEP/pg_sleep/WAITFOR DELAY (time‑based blind)", 0.98),
    (re.compile(r"\bbenchmark\s*\(", re.I), "BENCHMARK() MySQL (time/DoS)", 0.9),

    # ------------------ Error‑based extraction (muy alto) ------------------
    (re.compile(r"\b(updatexml|extractvalue|xmltype|utl_http\.request|dbms_xmlquery)\b\s*\(", re.I), "Funciones que devuelven errores con contenido (error‑based)", 0.95),
    (re.compile(r"\bconvert\(\s*.*\s+using\s+.*\)", re.I), "CONVERT ... USING (encoding conversions potenciales)", 0.7),

    # ------------------ OOB / Callbacks / Exfiltration (muy alto) ------------------
    (re.compile(r"\b(nslookup|dnslookup|xp_dirtree|xp_dirtree\(|xp_regread|xp\w+)\b", re.I),
     "Funciones/procs que pueden generar exfiltración OOB (DNS/SMB/SMB callbacks)", 0.95),
    (re.compile(r"\b(utl_http\.request|utl_tcp\.socket|http_client|apex_web_service\.make_rest_request)\b", re.I),
     "UTL_HTTP/HTTP callbacks (Oracle/PLSQL HTTP OOB)", 0.95),

    # ------------------ Execution / OS commands (muy alto) ------------------
    (re.compile(r"\bxp_cmdshell\b|\bexec\s+xp\w+|\bsp_oacreate\b", re.I), "xp_cmdshell / sp_oacreate (ejecución OS MSSQL/Oracle)", 0.98),
    (re.compile(r"\b(exec\s+master\..*xp\w+|sp_executesql|execute\s+immediate|EXEC\s+UTE)\b", re.I), "Ejecución dinámica / sp_executesql / EXECUTE IMMEDIATE", 0.95),

    # ------------------ Metadata / Recon (alto) ------------------
    (re.compile(r"\binformation_schema\b", re.I), "INFORMATION_SCHEMA (recon meta‑datos)", 0.92),
    (re.compile(r"\b(information_schema\.tables|information_schema\.columns)\b", re.I), "INFORMATION_SCHEMA.tables/columns", 0.92),
    (re.compile(r"\b(sys\.tables|sys\.objects|sys\.databases|pg_catalog|pg_tables|pg_user)\b", re.I), "Catálogos del sistema (MSSQL/Postgres)", 0.9),

    # ------------------ DML/DDL Destructivo (alto) ------------------
    (re.compile(r"\b(drop\s+table|truncate\s+table|drop\s+database|drop\s+schema)\b", re.I), "DROP/TRUNCATE (DDL destructivo)", 0.95),
    (re.compile(r"\b(delete\s+from|update\s+.+\s+set|insert\s+into)\b", re.I), "DML (DELETE/UPDATE/INSERT potencialmente destructivo)", 0.85),

    # ------------------ Stacked queries (medio‑alto) ------------------
    (re.compile(r";\s*(select|insert|update|delete|drop|create|truncate)\b", re.I), "Stacked queries (uso de ';' para apilar)", 0.88),

    # ------------------ Tautologías / Boolean Blind (medio‑alto) ------------------
    (re.compile(r"\b(or|and)\b\s+(['\"]?\d+['\"]?)\s*=\s*\1", re.I), "Tautología OR/AND 'x'='x' o 1=1", 0.85),
    (re.compile(r"(['\"]).{0,10}\1\s*or\s*['\"][^']*['\"]\s*=\s*['\"][^']*['\"]", re.I), "Tautología clásica en cadenas (OR '1'='1')", 0.8),

    # ------------------ Blind‑boolean extraction functions (medio) ------------------
    (re.compile(r"\b(substring|substr|mid|left|right)\b\s*\(", re.I), "SUBSTRING/SUBSTR/LEFT/RIGHT (blind extraction)", 0.82),
    (re.compile(r"\b(ascii|char|chr|nchr)\b\s*\(", re.I), "ASCII/CHAR/CHR (byte/char extraction)", 0.8),

    # ------------------ Error / XPATH / XML (alto) ------------------
    (re.compile(r"\b(updatexml|extractvalue|xmltype|xmlelement)\b\s*\(", re.I), "updatexml/extractvalue/xmltype (error/XPath leaks)", 0.93),

    # ------------------ File system / I/O (alto) ------------------
    (re.compile(r"\binto\s+outfile\b|\binto\s+dumpfile\b", re.I), "INTO OUTFILE / DUMPFILE (escritura en servidor)", 0.97),
    (re.compile(r"\bopenrowset\b|\bbulk\s+insert\b|\bcopy\s+to\b", re.I), "OPENROWSET / BULK INSERT / COPY TO (exportación)", 0.92),

    # ------------------ Encoding / Obfuscation (medio) ------------------
    (re.compile(r"0x[0-9a-fA-F]+", re.I), "Hex literal (0x...) (ofuscación)", 0.6),
    (re.compile(r"\\x[0-9a-fA-F]{2}", re.I), "Escapes hex tipo \\xNN (ofuscación)", 0.6),
    (re.compile(r"&#x[0-9a-fA-F]+;|&#\d+;", re.I), "Entidades HTML / entidades numéricas (ofuscación)", 0.6),
    (re.compile(r"\bchar\s*\(\s*\d+\s*\)", re.I), "CHAR(n) usado para construir cadenas (ofuscación)", 0.65),
    (re.compile(r"\bconcat\(", re.I), "CONCAT() (construcción dinámica de strings)", 0.6),

    # ------------------ SQL in attributes / URL encoded (medio) ------------------
    (re.compile(r"%3[dD]|%27|%22|%3C|%3E|%3B", re.I), "URL encoding típico (%27, %3C, etc.)", 0.4),

    # ------------------ Comments / terminators (informativo) ------------------
    (re.compile(r"(--\s|#\s|/\*[\s\S]*\*/)", re.I), "Comentarios SQL (--) o /* */ o #", 0.45),

    # ------------------ ORM / NonSQL indicators (informativo) ------------------
    (re.compile(r"\b\$where\b|\b\$ne\b|\b\$regex\b", re.I), "NoSQL / MongoDB indicators ($where/$ne/$regex)", 0.5),

    # ------------------ Tool fingerprints (informativo) ------------------
    (re.compile(r"sqlmap", re.I), "Indicador de herramienta sqlmap en payload", 0.5),
    (re.compile(r"hydra|nmap|nikto", re.I), "Indicador de herramientas de auditoría/scan", 0.3),

    # ------------------ Misc risky tokens (informativo) ------------------
    (re.compile(r"\bexecute\b\s*\(", re.I), "execute(...) (ejecución dinámica)", 0.7),
    (re.compile(r"\bdeclare\b\s+@?\w+", re.I), "DECLARE variable (MSSQL/PLSQL declarations)", 0.7),

    # ------------------ Low‑level heuristics (bajo) ------------------
    (re.compile(r"\bselect\b\s+.*\bfrom\b", re.I), "Estructura SELECT FROM (heurístico)", 0.25),
    (re.compile(r"\binsert\b\s+into\b", re.I), "INSERT INTO (heurístico)", 0.3),

    # ------------------ Catch‑all aggressive patterns (usar con cuidado) ------------------
    (re.compile(r"(['\"]).*?;\s*(drop|truncate|delete|update|insert)\b", re.I | re.S), "Cadena con terminador y DDL/DML (potencial ataque)", 0.9),
    (re.compile(r"\b(or)\b\s+1\s*=\s*1\b", re.I), "OR 1=1 tautology", 0.85),
]

IGNORED_FIELDS = ["password", "csrfmiddlewaretoken", "token", "auth"]

# ----------------------------
# Obtener IP real del cliente
# ----------------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ips = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if ips:
            return ips[0]
    return request.META.get("REMOTE_ADDR", "")

# ----------------------------
# Extraer payload de la solicitud
# ----------------------------
def extract_payload(request):
    parts = []
    try:
        if "application/json" in request.META.get("CONTENT_TYPE", ""):
            data = json.loads(request.body.decode("utf-8") or "{}")
            parts.append(json.dumps(data))
        else:
            body = request.body.decode("utf-8", errors="ignore")
            if body:
                parts.append(body)
    except Exception:
        pass

    qs = request.META.get("QUERY_STRING", "")
    if qs:
        parts.append(qs)

    return " ".join(parts)

# ----------------------------
# Normalización / preprocesamiento
# ----------------------------
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
    # Reemplazo seguro de secuencias \xNN
    s_dec = re.sub(r"\\x([0-9a-fA-F]{2})", r"\\x\g<1>", s_dec)
    s_dec = re.sub(r"\s+", " ", s_dec)
    return s_dec.strip()

# ----------------------------
# Detector SQLi
# ----------------------------
def detect_sql_injection(text: str) -> Dict:
    norm = normalize_input(text or "")
    score = 0.0
    matches = []
    descriptions = []
    for pattern, desc, weight in SQL_PATTERNS:
        if pattern.search(norm):
            score += weight
            matches.append((desc, pattern.pattern, weight))
            descriptions.append(desc)

    return {
        "score": round(score, 3),
        "matches": matches,
        "descriptions": list(dict.fromkeys(descriptions)),
        "sample": norm[:1200],
    }

DEFAULT_THRESHOLDS = {
    "HIGH": 1.8,
    "MEDIUM": 1.0,
    "LOW": 0.5,
}

# ----------------------------
# Middleware SQLi
# ----------------------------
class SQLIDefenseMiddleware(MiddlewareMixin):
    def process_request(self, request):
        client_ip = get_client_ip(request)
        trusted_ips = getattr(settings, "SQLI_DEFENSE_TRUSTED_IPS", [])
        trusted_urls = getattr(settings, "SQLI_DEFENSE_TRUSTED_URLS", [])

        if client_ip in trusted_ips:
            return None

        referer = request.META.get("HTTP_REFERER", "")
        host = request.get_host()
        if any(url in referer for url in trusted_urls) or any(url in host for url in trusted_urls):
            return None

        payload = extract_payload(request)
        result = detect_sql_injection(payload)
        score = result["score"]
        descripciones = result["descriptions"]

        if score == 0:
            return None

        # Registrar ataque
        logger.warning(
            f"[SQLiDetect] IP={client_ip} Host={host} Referer={referer} "
            f"Score={score:.2f} Desc={descripciones} Payload={payload[:500]}"
        )

        # Guardar info en request
        request.sql_attack_info = {
            "ip": client_ip,
            "tipos": ["SQLi"],
            "descripcion": descripciones,
            "payload": payload[:1000],
            "score": round(score, 2),
            "url": request.build_absolute_uri(),
        }

        return None

# =====================================================
# ===              INFORMACIÓN EXTRA                ===
# =====================================================
r"""
Algoritmos relacionados:
    - Se recomienda almacenar logs SQLi cifrados (AES-GCM) 
      para proteger evidencia de intentos maliciosos.

Cálculo de puntaje de amenaza:
    S_sqli = w_sqli * detecciones_sqli
    Ejemplo: S_sqli = 0.4 * 3 = 1.2

Integración:
    Este middleware puede combinarse con:
        - CSRFDefenseMiddleware
        - XSSDefenseMiddleware
    para calcular un score total de amenaza y decidir bloqueo.
"""
