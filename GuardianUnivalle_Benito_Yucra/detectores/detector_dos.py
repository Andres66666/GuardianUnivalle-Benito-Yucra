from ..mitigacion.limitador_peticion import limitar_peticion
from ..auditoria.registro_auditoria import registrar_evento

def detectar_dos(tasa_peticion: int, limite: int = 100) -> bool:
    if tasa_peticion > limite:
        registrar_evento("DoS", f"Tasa de petición elevada: {tasa_peticion}")
        return True
    return False
""" 
Algoritmos relacionados:
    *Rate Limiting, listas de bloqueo.
    *Opcional: cifrado de logs con ChaCha20-Poly1305.
Contribución a fórmula de amenaza S:
S_dos = w_dos * (tasa_peticion / limite)
S_dos = 0.6 * (150 / 100)
donde w_dos es peso asignado a DoS y tasa_peticion / limite es la proporción de la tasa actual sobre el límite.
"""