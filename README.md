<!-- Información de la librería -->
<table align="center" style="width: 100%; text-align: center; border-collapse: collapse; background-color: #f4f4f9; border-radius: 15px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); padding: 20px;">
  <tr>
    <td style="border: none; padding: 10px 20px;">
      <img src="https://res.cloudinary.com/dsbgmboh1/image/upload/v1761866594/Andres_Benito_Calle_Yucra_nxyqee.png"
           alt="Univalle Logo" width="300" 
           style="transition: transform 0.3s ease-in-out;" 
           onmouseover="this.style.transform='scale(1.1)'" 
           onmouseout="this.style.transform='scale(1)'">
    </td>
    <td style="border: none; padding: 10px 20px; text-align: center;">
      <h1 style="font-size: 50px; margin: 0; color: #c62828; font-family: 'Arial', sans-serif; text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);">
        Guardian Univalle – Benito
      </h1>
      <p style="margin: 5px 0 0 0; font-size: 18px; color: #444; font-family: 'Segoe UI', sans-serif;">
        Framework de detección y defensa de amenazas web para Django.
      </p>
    </td>
    <td style="border: none; padding: 10px 20px;">
      <img src="https://res.cloudinary.com/dsbgmboh1/image/upload/v1761864884/GuardianUnivalle_imeegq.png" 
           alt="Django Logo" width="300" 
           style="transition: transform 0.3s ease-in-out;" 
           onmouseover="this.style.transform='scale(1.1)'" 
           onmouseout="this.style.transform='scale(1)'">
    </td>
  </tr>
</table>


`Guardian Univalle` es un sistema de seguridad modular desarrollado para fortalecer aplicaciones Django frente a ataques web comunes como **XSS**, **CSRF**, **inyección SQL**, **ataques DoS** y **scraping automatizado**.  
Cada módulo opera mediante **middlewares independientes** que analizan el tráfico HTTP en tiempo real, aplican heurísticas inteligentes y registran eventos sospechosos para auditoría y bloqueo adaptativo.

---
## Arquitectura general

Guardian Univalle está diseñado bajo una **arquitectura modular y extensible**, donde cada tipo de amenaza se gestiona mediante un middleware especializado.  
Cada middleware:

- Se ejecuta en la fase inicial del request (`process_request`).
- Analiza cabeceras, cuerpo y metadatos de la petición.
- Evalúa indicadores de ataque según patrones heurísticos y reglas configurables.
- Calcula una puntuación de riesgo (score) para cada evento.
- Anexa la información al objeto `request` (por ejemplo, `request.xss_attack_info`) para que otros módulos (como el de auditoría) la procesen.

---

##  Módulos de defensa incluidos

### 1. CSRFDefenseMiddleware
**Defensa contra Cross-Site Request Forgery (CSRF)**

Este módulo detecta intentos de falsificación de peticiones mediante:

- Verificación de cabeceras **Origin** y **Referer** contra el host real.  
- Validación de **tokens CSRF** en cookies, cabeceras o formularios.  
- Análisis del **tipo de contenido** (`Content-Type`) y parámetros sensibles.  
- Detección de peticiones JSON o formularios enviados desde dominios externos.  
- Asignación de un **score de riesgo** proporcional al número y severidad de señales encontradas.  

**Algoritmos utilizados:** heurísticas basadas en cabeceras HTTP, validación semántica de origen y detección de anomalías en métodos `POST`, `PUT`, `DELETE` y `PATCH`.

---

### 2. XSSDefenseMiddleware
**Defensa contra Cross-Site Scripting (XSS)**

Analiza los datos enviados en el cuerpo y querystring, detectando vectores de inyección HTML/JS mediante:

- Patrones de alto riesgo (`<script>`, `javascript:`, `onload=`, `eval()`).
- Ofuscaciones con entidades (`&#x3C;`, `%3Cscript`).
- Detección de atributos de eventos (`onmouseover`, `onfocus`, etc.).
- Análisis de URIs maliciosas (`data:text/html`, `vbscript:`).
- Scoring ponderado por severidad (de 0.3 a 0.95).

**Algoritmos utilizados:** expresiones regulares avanzadas con pesos heurísticos y uso opcional de la librería **Bleach** para sanitización comparativa.

**Salida:** agrega `request.xss_attack_info` con los detalles de detección, IP de origen, descripción, payload y score total.

---

### 3. SQLIDefenseMiddleware
**Defensa contra Inyección SQL (SQLi)**

Identifica intentos de inyección SQL en parámetros enviados a través de:

- Palabras clave peligrosas (`UNION`, `SELECT`, `DROP`, `INSERT`, `UPDATE`).
- Uso de comentarios (`--`, `#`, `/* ... */`).
- Concatenaciones o subconsultas sospechosas.
- Comportamientos anómalos en parámetros GET, POST o JSON.

**Algoritmos utilizados:** heurísticas sintácticas + patrones combinados con contextos.  
Evalúa combinaciones de operadores y palabras reservadas para minimizar falsos positivos.

**Resultado:** registra el intento en `request.sql_injection_info` con score calculado y parámetros comprometidos.

---

### 4. DOSDefenseMiddleware
**Detección de ataques de Denegación de Servicio (DoS)**

Monitorea la frecuencia de peticiones por IP y calcula una métrica adaptativa:

- Detecta exceso de solicitudes en intervalos cortos.
- Analiza `User-Agent`, patrones repetitivos y tamaño de payloads.
- Aplica límites configurables (`MAX_REQUESTS_PER_WINDOW`).
- Marca IPs sospechosas para registro y bloqueo temporal.

**Algoritmos utilizados:** Sliding Window con conteo adaptativo, controlado por señales de frecuencia e intensidad.

---

### 5. ScrapingDefenseMiddleware (opcional)
**Detección de scraping y bots automatizados**

Evalúa características típicas de scraping:

- User-Agent anómalo o ausente.  
- Patrón de navegación repetitivo o excesivamente rápido.  
- Ausencia de cabeceras humanas como `Accept-Language` o `Referer`.  
- Combinación con heurísticas de DoS para detectar scrapers agresivos.

**Algoritmos utilizados:** análisis estadístico de cabeceras + patrones de comportamiento a corto plazo.

---

## Integración y uso

### Instalación

```bash
pip install guardian-univalle
```
### Configuración en settings.py

```bash
MIDDLEWARE = [
    # Middlewares personalizados  
    "GuardianUnivalle_Benito_Yucra.detectores.detector_dos.DOSDefenseMiddleware", 
    "GuardianUnivalle_Benito_Yucra.detectores.detector_sql.SQLIDefenseMiddleware",
    "GuardianUnivalle_Benito_Yucra.detectores.detector_xss.XSSDefenseMiddleware",
    "GuardianUnivalle_Benito_Yucra.detectores.detector_csrf.CSRFDefenseMiddleware",
    "users.middleware.AuditoriaMiddleware",
    "users.auditoria_servidor.AuditoriaServidorMiddleware",
]

```

```bash
ALLOWED_HOSTS = [
    "192.168.0.3",
    "127.0.0.1",
    "localhost",
]

```
### Parámetros de defensa avanzada

```bash
# --- DoS Defense ---
DOS_LIMITE_PETICIONES = 120 
DOS_VENTANA_SEGUNDOS = 60
DOS_PESO = 0.6
DOS_LIMITE_ENDPOINTS = 80 
DOS_TIEMPO_BLOQUEO = 300 
DOS_TRUSTED_IPS = ["127.0.0.1", "192.168.0.3"]

# Score total de bloqueo
DOS_PESO_BLACKLIST = 0.3
DOS_PESO_HEURISTICA = 0.1
DOS_UMBRAL_BLOQUEO = 0.8

# Configuración general
DOS_DEFENSE_MAX_REQUESTS = 100
DOS_DEFENSE_BLOCK_TIME = 300
DOS_DEFENSE_TRUSTED_IPS = ["127.0.0.1", "192.168.0.3"]

```

```bash
# --- SQL Injection Defense ---
SQLI_DEFENSE_TRUSTED_IPS = ["127.0.0.1", "192.168.0.3"]

# --- XSS Defense ---
XSS_DEFENSE_TRUSTED_IPS = ["127.0.0.1", "192.168.0.3"]
XSS_DEFENSE_SANITIZE_INPUT = False
XSS_DEFENSE_BLOCK = True
XSS_DEFENSE_EXCLUDED_PATHS = ["/health", "/internal"]

# --- CSRF Defense ---
CSRF_DEFENSE_TRUSTED_IPS = ["127.0.0.1", "192.168.0.3"]
CSRF_DEFENSE_BLOCK = True
CSRF_DEFENSE_LOG = True

```
### Auditoría y correlación de eventos
```bash
request.xss_attack_info = {
    "ip": "192.168.1.10",
    "tipos": ["XSS"],
    "descripcion": ["Etiqueta <script> detectada"],
    "payload": {"field": "comentario", "snippet": "<script>alert(1)</script>"},
    "score": 0.92,
    "url": "/comentarios/enviar/",
}

```
### Filosofía del proyecto
Guardian Univalle – Benito & Junkrat busca proporcionar una capa de defensa proactiva para entornos Django universitarios y empresariales, combinando:

#Detección heurística.

#Análisis semántico de cabeceras y payloads.

#Escalamiento de score basado en señales múltiples.

Su diseño es didáctico y extensible, ideal tanto para proyectos reales como para enseñanza de ciberseguridad aplicada.
---
### Estructura del paquete
```bash
guardian_univalle/
│
├── detectores/
│   ├── csrf_defense.py
│   ├── xss_defense.py
│   ├── sql_defense.py
│   ├── dos_defense.py
│   ├── scraping_defense.py
│
├── auditoria/
│   └── auditoria_middleware.py
│
└── __init__.py

```
### Licencia 
Este proyecto se distribuye bajo la licencia MIT, permitiendo libre uso y modificación con atribución.

📘 Universidad Privada del Valle – Sede La Paz

👨‍💻 Desarrollado por: Benito Yucra

📅 Año: 2025
