"""
Middleware base para frameworks web (Django/Flask/FastAPI)
"""
from ..detectores.detector_sql import detectar_inyeccion_sql
from ..detectores.detector_xss import detectar_xss

def middleware_proteccion(request):
    # Simulación de protección de entrada
    if detectar_inyeccion_sql(request.get("query", "")):
        return {"error": "SQL Injection detectado"}
    if detectar_xss(request.get("input", "")):
        return {"error": "XSS detectado"}
    return {"ok": True}
