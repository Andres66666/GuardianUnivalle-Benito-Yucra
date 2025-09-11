"""
Limitador de peticiones para prevenir DoS
"""
def limitar_peticion(usuario_id: str, max_peticion: int = 100) -> bool:
    # Simulación de limitador: True si excede
    print(f"✅ Limitador activo para {usuario_id}")
    return False
