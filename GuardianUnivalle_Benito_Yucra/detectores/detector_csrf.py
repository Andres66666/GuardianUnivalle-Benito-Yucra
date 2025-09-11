import secrets
from ..auditoria.registro_auditoria import registrar_evento

def generar_token_csrf() -> str:
    return secrets.token_hex(32)

def validar_token_csrf(token: str, token_sesion: str) -> bool:
    valido = token == token_sesion
    if not valido:
        registrar_evento("CSRF", "Intento de CSRF detectado")
    return valido

""" 
Algoritmos relacionados:
    *Uso de secreto aleatorio criptográfico.
    *Opcionalmente derivación con PBKDF2 / Argon2 para reforzar token.
Contribución a fórmula de amenaza S:
S_csrf = w_csrf * intentos_csrf
S_csrf = 0.2 * 1
donde w_csrf es peso asignado a CSRF y intentos_csrf es la cantidad de intentos detectados.
"""