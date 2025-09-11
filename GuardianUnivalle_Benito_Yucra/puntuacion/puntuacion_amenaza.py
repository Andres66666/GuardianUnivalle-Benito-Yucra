"""
Fórmula compuesta S para puntuar la amenaza global
"""
def calcular_puntuacion(detecciones_sql=0, detecciones_xss=0, intentos_csrf=0,
                        procesos_keylogger=0, tasa_dos=0,
                        w_sql=1.5, w_xss=1.2, w_csrf=1.0, w_keylogger=2.0, w_dos=2.5,
                        limite_dos=100) -> float:
    S = (
        w_sql * detecciones_sql +
        w_xss * detecciones_xss +
        w_csrf * intentos_csrf +
        w_keylogger * procesos_keylogger +
        w_dos * (tasa_dos / limite_dos)
    )
    return S
