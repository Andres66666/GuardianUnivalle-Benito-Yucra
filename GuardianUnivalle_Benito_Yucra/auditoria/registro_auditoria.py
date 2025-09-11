import datetime

def registrar_evento(tipo: str, mensaje: str):
    with open("auditoria_guardian.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now()}] {tipo}: {mensaje}\n")

def generar_reporte() -> str:
    with open("auditoria_guardian.log", "r", encoding="utf-8") as f:
        return f.read()
