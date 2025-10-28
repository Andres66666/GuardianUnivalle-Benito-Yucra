<!-- Información de la librería -->

# 🛡️ Guardian Univalle – Benito & Junkrat

**Framework de detección y defensa de amenazas web para Django y Flask**

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

## 🧩 Módulos de defensa incluidos

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
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

