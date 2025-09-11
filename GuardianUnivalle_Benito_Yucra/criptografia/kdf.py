"""
Wrappers para derivación de claves segura: PBKDF2 y Argon2
"""
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
import os

def pbkdf2_derivar_clave(password: str, salt: bytes = None) -> bytes:
    """Deriva clave usando PBKDF2"""
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode()), salt

def argon2_derivar_clave(password: str) -> str:
    """Deriva clave usando Argon2"""
    ph = PasswordHasher()
    return ph.hash(password)
