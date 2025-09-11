"""
Gestión de intercambio de claves con ECDH y derivación HKDF.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generar_claves_ecdh():
    """Genera clave privada y pública ECDH"""
    clave_privada = ec.generate_private_key(ec.SECP384R1())
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def derivar_clave_secreta(clave_privada, clave_publica):
    """Deriva una clave compartida usando HKDF"""
    shared_key = clave_privada.exchange(ec.ECDH(), clave_publica)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'guardianclave'
    ).derive(shared_key)
    return derived_key
