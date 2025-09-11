""" Funciones de cifrado """
# GuardianUnivalle_Benito_Yucra/encryption.py

def encrypt_data(data: str) -> str:
    """Simulación de cifrado sencillo"""
    return "".join(chr(ord(c)+3) for c in data)

def decrypt_data(data: str) -> str:
    """Simulación de descifrado sencillo"""
    return "".join(chr(ord(c)-3) for c in data)
