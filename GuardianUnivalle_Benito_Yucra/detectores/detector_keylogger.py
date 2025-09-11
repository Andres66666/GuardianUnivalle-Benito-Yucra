import psutil
from ..auditoria.registro_auditoria import registrar_evento

def detectar_keylogger():
    sospechosos = []
    for proc in psutil.process_iter(['pid', 'name']):
        if "keylogger" in proc.info['name'].lower():
            sospechosos.append(proc.info)
            registrar_evento("Keylogger", f"Proceso sospechoso: {proc.info}")
    return sospechosos


""" 
Algoritmos relacionados:
    *Guardar registros con AES-256 + hash SHA-512 para integridad.
Contribución a fórmula de amenaza S:
S_keylogger = w_keylogger * numero_procesos_sospechosos
S_keylogger = 0.4 * 2
donde w_keylogger es peso asignado a keyloggers y numero_procesos_sospechosos es la cantidad de procesos detectados.

"""