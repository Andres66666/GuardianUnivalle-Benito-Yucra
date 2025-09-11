"""
Manejo de lista de bloqueo
"""
lista_bloqueo = set()

def agregar_bloqueo(ip: str):
    lista_bloqueo.add(ip)

def esta_bloqueado(ip: str) -> bool:
    return ip in lista_bloqueo
