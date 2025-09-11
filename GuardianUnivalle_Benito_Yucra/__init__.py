""" Funciones principales """
# GuardianUnivalle_Benito_Yucra/__init__.py

from .encryption import encrypt_data, decrypt_data
from .web_protection import sanitize_input, check_csrf
from .dos_protection import rate_limiter
from .malware_check import scan_malware

def protect_app():
    """
    Activa todas las protecciones de seguridad de forma automática.
    """
    print("🔒 GuardianUnivalle-Benito-Yucra: Seguridad activada")
    # Aquí podríamos llamar funciones automáticamente si queremos
    # scan_malware()
    # rate_limiter()
    # sanitize_input()
    # check_csrf()
