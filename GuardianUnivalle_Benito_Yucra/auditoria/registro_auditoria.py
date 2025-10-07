import os
import datetime
import json

LOG_FILE = "auditoria_guardian.log"


def registrar_evento(
    tipo: str,
    descripcion: str = "",
    severidad: str = "MEDIA",
    extra: dict | None = None,
):
    try:
        evento = {
            "fecha": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tipo": tipo,
            "descripcion": descripcion,
            "severidad": severidad,
            "extra": extra or {},
        }

        # ✅ Crear carpeta solo si hay directorio en la ruta
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(evento, ensure_ascii=False) + "\n")

    except Exception as e:
        print(f"[Auditoría] Error al registrar evento: {e}")


def generar_reporte() -> str:
    """Devuelve todo el contenido del archivo de auditoría."""
    if not os.path.exists(LOG_FILE):
        return "No hay registros aún."
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return f.read()
