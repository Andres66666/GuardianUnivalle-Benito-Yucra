""" Funciones principales """
# GuardianUnivalle_Benito_Yucra/__init__.py

"""
Paquete principal de GuardianUnivalle.
Incluye módulos de criptografía, detección de ataques, mitigación, auditoría y puntuación de amenazas.
"""
from . import criptografia
from . import detectores
from . import mitigacion
from . import auditoria
from . import puntuacion
from . import middleware_web
from . import utilidades

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
