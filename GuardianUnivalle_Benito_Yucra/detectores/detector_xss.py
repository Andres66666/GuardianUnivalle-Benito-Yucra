import html
from ..auditoria.registro_auditoria import registrar_evento

def sanitizar_xss(entrada: str) -> str:
    return html.escape(entrada)

def detectar_xss(entrada: str) -> bool:
    patrones = ["<script", "javascript:", "onerror", "onload"]
    if any(p in entrada.lower() for p in patrones):
        registrar_evento("XSS", f"Ataque detectado: {entrada}")
        return True
    return False
""" 
Algoritmos relacionados:
    *Guardar entradas sospechosas con AES-GCM para confidencialidad y autenticidad.
Contribución a fórmula de amenaza S:
S_xss = w_xss * detecciones_xss
S_xss = 0.3 * 2
donde w_xss es peso asignado a XSS y detecciones_xss es la cantidad de patrones detectados.

"""