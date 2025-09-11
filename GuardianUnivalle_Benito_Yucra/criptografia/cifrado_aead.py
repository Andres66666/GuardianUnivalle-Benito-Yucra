"""
Cifrado simétrico autenticado: AES-GCM y ChaCha20-Poly1305
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os

def cifrar_aes_gcm(mensaje: bytes, clave: bytes) -> dict:
    aes = AESGCM(clave)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, mensaje, None)
    return {"nonce": nonce, "ciphertext": ciphertext}

def descifrar_aes_gcm(cipher: dict, clave: bytes) -> bytes:
    aes = AESGCM(clave)
    return aes.decrypt(cipher["nonce"], cipher["ciphertext"], None)

def cifrar_chacha20(mensaje: bytes, clave: bytes) -> dict:
    cipher = ChaCha20Poly1305(clave)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, mensaje, None)
    return {"nonce": nonce, "ciphertext": ciphertext}

def descifrar_chacha20(cipher: dict, clave: bytes) -> bytes:
    cipher_obj = ChaCha20Poly1305(clave)
    return cipher_obj.decrypt(cipher["nonce"], cipher["ciphertext"], None)
