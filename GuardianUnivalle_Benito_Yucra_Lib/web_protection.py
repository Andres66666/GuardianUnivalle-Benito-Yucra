# GuardianUnivalle_Benito_Yucra/web_protection.py

def sanitize_input(user_input: str) -> str:
    """Elimina caracteres peligrosos (simulación)"""
    return user_input.replace("<", "&lt;").replace(">", "&gt;")

def check_csrf():
    """Simulación de protección CSRF"""
    print("✅ CSRF check passed")
