<!-- Información de la librería -->

# 🛡️ Guardian Univalle – Benito & Junkrat

Framework de detección y defensa de amenazas web para Django y Flask

Guardian Univalle es un sistema de seguridad modular desarrollado para fortalecer aplicaciones Django frente a ataques web comunes como XSS, CSRF, inyección SQL, ataques DoS y scraping automatizado.
Cada módulo opera mediante middleware independientes que analizan el tráfico HTTP en tiempo real, aplican heurísticas inteligentes y registran eventos sospechosos para auditoría y bloqueo adaptativo.

⚙️ Arquitectura general

Guardian Univalle está diseñado bajo una arquitectura modular y extensible, donde cada tipo de amenaza se gestiona mediante un middleware especializado.
Cada middleware:

- Se ejecuta en la fase inicial del request (process_request).
- Analiza cabeceras, cuerpo y metadatos de la petición.
- Evalúa indicadores de ataque según patrones heurísticos y reglas configurables.
- Calcula una puntuación de riesgo (score) para cada evento.
- Anexa la información al objeto request (por ejemplo, request.xss_attack_info) para que otros módulos (como el de auditoría) la procesen.

🧩 Módulos de defensa incluidos

1. 🔐 CSRFDefenseMiddleware

Defensa contra Cross-Site Request Forgery (CSRF).

Este módulo detecta intentos de falsificación de peticiones mediante:

- Verificación de cabeceras Origin y Referer contra el host real.
- Validación de tokens CSRF en cookies, cabeceras o formularios.
- Análisis del tipo de contenido (Content-Type) y parámetros sensibles.
- Detección de peticiones JSON o formularios enviados desde dominios externos.
- Asignación de un score de riesgo proporcional al número y severidad de señales encontradas.

Algoritmos utilizados:
Heurísticas basadas en cabeceras HTTP, validación semántica de origen, y detección de anomalías en métodos POST, PUT, DELETE y PATCH.

2. 🧬 XSSDefenseMiddleware

Defensa contra Cross-Site Scripting (XSS).

Analiza en profundidad los datos enviados en el cuerpo y querystring, detectando vectores de inyección HTML/JS mediante:

- Patrones de alto riesgo (<script>, javascript:, onload=, eval()).
- Ofuscaciones con entidades (&#x3C;, %3Cscript).
- Detección de atributos de eventos (onmouseover, onfocus, etc.).
- Análisis de URIs maliciosas (data:text/html, vbscript:).
- Scoring ponderado por severidad (de 0.3 a 0.95).

Algoritmos utilizados:
Detección basada en expresiones regulares avanzadas con pesos heurísticos y uso opcional de la librería Bleach para sanitización comparativa.

Salida:
Agrega request.xss_attack_info con los detalles de detección, la IP de origen, descripción, payload y score total.

3. 💾 SQLIDefenseMiddleware

Defensa contra Inyección SQL (SQLi).

Identifica intentos de inyección SQL en los parámetros enviados a través de:

- Palabras clave peligrosas (UNION, SELECT, DROP, INSERT, UPDATE).
- Uso de comentarios (--, #, /_ ... _/).
- Concatenaciones o subconsultas sospechosas.
- Comportamientos anómalos en parámetros GET, POST o JSON.

Algoritmos utilizados:
Heurísticas sintácticas + patrones combinados con contextos.
Evalúa combinaciones de operadores y palabras reservadas para minimizar falsos positivos.

Resultado:
Registra el intento en request.sql_injection_info con score calculado y parámetros comprometidos.

4. 🌐 DOSDefenseMiddleware

Detección de ataques de Denegación de Servicio (DoS).

Monitorea la frecuencia de peticiones por IP y calcula una métrica adaptativa de comportamiento:

- Detecta exceso de solicitudes en intervalos cortos.
- Analiza User-Agent, patrones repetitivos y tamaño de payloads.
- Aplica límites configurables (MAX_REQUESTS_PER_WINDOW).
- Marca IPs sospechosas para registro y bloqueo temporal.

Algoritmos utilizados:
Sliding Window con conteo adaptativo en memoria, controlado por señales de frecuencia e intensidad.

5. 🕷️ ScrapingDefenseMiddleware (opcional)

Detección de scraping y bots automatizados.

Evalúa características típicas de scraping:

- User-Agent anómalo o ausente.
- Patrón de navegación repetitivo o excesivamente rápido.
- Ausencia de cabeceras humanas (como Accept-Language o Referer).
- Combinación con heurísticas de DoS para detectar scrapers agresivos.

Algoritmos utilizados:
Análisis estadístico de cabeceras + patrones de comportamiento a corto plazo.

🧠 Integración y uso

Instalar la librería:

pip install guardian-univalle

En tu archivo settings.py de Django, añadir los middlewares:
```python
MIDDLEWARE = [
    # Middlewares personalizados  
    "GuardianUnivalle_Benito_Yucra.detectores.detector_dos.DOSDefenseMiddleware", 
    "GuardianUnivalle_Benito_Yucra.detectores.detector_sql.SQLIDefenseMiddleware",
    "GuardianUnivalle_Benito_Yucra.detectores.detector_xss.XSSDefenseMiddleware",
    "GuardianUnivalle_Benito_Yucra.detectores.detector_csrf.CSRFDefenseMiddleware",
    "users.middleware.AuditoriaMiddleware",
    'users.auditoria_servidor.AuditoriaServidorMiddleware',
]
```
(Opcional) Configurar umbrales en settings.py:

XSS_DEFENSE_THRESHOLD = 0.6
CSRF_DEFENSE_MIN_SIGNALS = 1
DOS_DEFENSE_MAX_REQUESTS = 100
SQLI_DEFENSE_THRESHOLD = 0.5

🧾 Auditoría y correlación de eventos

Cada middleware genera un diccionario con detalles de detección:

request.xss_attack_info = {
"ip": "192.168.1.10",
"tipos": ["XSS"],
"descripcion": ["Etiqueta <script> detectada"],
"payload": "{'field': 'comentario', 'snippet': '<script>alert(1)</script>'}",
"score": 0.92,
"url": "/comentarios/enviar/",
}

Estos datos pueden ser almacenados por un AuditoriaMiddleware o enviados a un sistema SIEM para correlación y respuesta automatizada.

🧩 Filosofía del proyecto

Guardian Univalle – Benito & Junkrat busca proporcionar una capa de defensa proactiva para entornos Django universitarios y empresariales, combinando:

Detección heurística,

Análisis semántico de cabeceras y payloads, y

Escalamiento de score basado en señales múltiples.

Su diseño es didáctico y extensible, ideal tanto para proyectos reales como para enseñanza de ciberseguridad aplicada.

🧱 Estructura del paquete
```python
guardian_univalle/
│
├── detectores/
│ ├── csrf_defense.py
│ ├── xss_defense.py
│ ├── sql_defense.py
│ ├── dos_defense.py
│ ├── scraping_defense.py
│
├── auditoria/
│ └── auditoria_middleware.py
│
└── **init**.py
```
🧾 Licencia

Este proyecto se distribuye bajo la licencia MIT, permitiendo libre uso y modificación con atribución.
