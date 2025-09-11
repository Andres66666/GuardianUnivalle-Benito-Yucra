"""
Funciones auxiliares generales
"""
import os

def generar_id_unico() -> str:
    return os.urandom(16).hex()
