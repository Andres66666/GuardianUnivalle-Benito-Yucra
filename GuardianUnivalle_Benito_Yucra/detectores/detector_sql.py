import re
from ..auditoria.registro_auditoria import registrar_evento

def detectar_inyeccion_sql(consulta: str) -> bool:
    """Detecta patrones típicos de SQL Injection"""
    patrones = [
        r"(\bor\b|\band\b).*(=|like)",
        r"(--|#|;)",
        r"(union(\s)+select)",
        r"(drop|delete|insert|update).*",
    ]
    for p in patrones:
        if re.search(p, consulta, re.IGNORECASE):
            registrar_evento("SQL Injection", f"Ataque detectado: {consulta}")
            return True
    return False
""" 
Algoritmos relacionados:
    *Se puede aplicar cifrado AES-256 para guardar las consultas auditadas.
    *Hash SHA-256 para integridad de registros.
*Contribución a fórmula de amenaza S:
        S_sql = w_sql * detecciones_sql
        S_sql = 0.5 * 3
donde w_sql es peso asignado a SQL Injection y detecciones_sql es la cantidad de patrones detectados.
 """