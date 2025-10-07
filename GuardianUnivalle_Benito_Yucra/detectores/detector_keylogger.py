from __future__ import annotations
import psutil
import os
import logging
import platform
import subprocess
from typing import List, Dict
from django.conf import settings
from ..auditoria.registro_auditoria import registrar_evento

# =====================================================
# === CONFIGURACIÓN DEL LOGGER ===
# =====================================================
logger = logging.getLogger("keyloggerdefense")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
# =========================================
# Middleware de Keylogger para Django
# =========================================
from django.utils.deprecation import MiddlewareMixin


class KEYLOGGERDefenseMiddleware(MiddlewareMixin):
    """
    Middleware que ejecuta el escaneo de keyloggers
    en cada request entrante.
    """

    def __init__(self, get_response=None):
        super().__init__(get_response)
        # Importa tu clase de detección
        from .detector_keylogger import KEYLOGGERDefense

        self.detector = KEYLOGGERDefense()

    def process_request(self, request):
        """
        Ejecuta el escaneo antes de procesar la vista.
        Guarda los resultados en el objeto request para uso posterior.
        """
        try:
            # Detecta en modo interactivo
            resultado = self.detector.ejecutar_escaneo(modo_interactivo=True)
            request.keylogger_attack_info = resultado
        except Exception as e:
            logger.error("Error en KEYLOGGERDefenseMiddleware: %s", e)


# =====================================================
# === CONFIGURACIÓN DE PARÁMETROS ===
# =====================================================
PESO_KEYLOGGER = getattr(settings, "KEYLOGGER_PESO", 0.4)
EXTENSIONES_SOSPECHOSAS = [".exe", ".dll", ".scr", ".bat", ".cmd", ".msi"]
CARPETAS_CRITICAS = [
    "C:\\Users\\Public",
    "C:\\Users\\%USERNAME%\\AppData\\Roaming",
    "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp",
    "C:\\ProgramData",
    "C:\\Windows\\Temp",
]
PATRONES_NOMBRES = ["keylogger", "spy", "hook", "keyboard", "capture", "stealer"]


# =====================================================
# === FUNCIONES AUXILIARES ===
# =====================================================
def calcular_score_keylogger(total_items: int) -> float:
    """Calcula el nivel de amenaza normalizado."""
    return round(min(PESO_KEYLOGGER * total_items, 1.0), 3)


def detectar_procesos_sospechosos() -> List[Dict]:
    """Escanea procesos activos y detecta posibles keyloggers."""
    hallazgos = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            nombre = proc.info.get("name", "").lower()
            if any(pat in nombre for pat in PATRONES_NOMBRES):
                hallazgos.append(proc.info)
                registrar_evento("Keylogger", f"Proceso sospechoso: {proc.info}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return hallazgos


def detectar_archivos_sospechosos() -> List[str]:
    """
    Busca archivos con extensiones peligrosas y nombres relacionados
    a keyloggers en carpetas críticas del sistema.
    """
    hallazgos = []
    for base in CARPETAS_CRITICAS:
        base = os.path.expandvars(base)  # reemplaza %USERNAME%
        if not os.path.exists(base):
            continue
        for root, _, files in os.walk(base):
            for file in files:
                if any(file.lower().endswith(ext) for ext in EXTENSIONES_SOSPECHOSAS):
                    if any(pat in file.lower() for pat in PATRONES_NOMBRES):
                        ruta = os.path.join(root, file)
                        hallazgos.append(ruta)
                        registrar_evento("Keylogger", f"Archivo sospechoso: {ruta}")
    return hallazgos


def detectar_programas_instalados() -> list[str]:
    """
    Detecta software potencialmente malicioso en Windows usando PowerShell.
    """
    hallazgos = []
    if platform.system() != "Windows":
        return hallazgos

    ps_command = (
        "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"
    )

    try:
        salida = subprocess.check_output(
            ["powershell", "-Command", ps_command],
            stderr=subprocess.DEVNULL,
            shell=True,
        ).decode("utf-8", errors="ignore")

        for linea in salida.splitlines():
            nombre = linea.strip().lower()
            if any(pat in nombre for pat in PATRONES_NOMBRES):
                hallazgos.append(nombre)
                registrar_evento("Keylogger", f"Software sospechoso: {nombre}")

    except Exception as e:
        logger.error("Error al listar programas instalados con PowerShell: %s", e)

    return hallazgos


# =====================================================
# === CLASE PRINCIPAL DE DETECCIÓN ===
# =====================================================
class KEYLOGGERDefense:
    """
    Escanea procesos, archivos y programas para detectar keyloggers
    o software espía potencialmente malicioso.
    """

    def ejecutar_escaneo(self, modo_interactivo=False):
        procesos = detectar_procesos_sospechosos()
        archivos = detectar_archivos_sospechosos()
        programas = detectar_programas_instalados()

        total_hallazgos = len(procesos) + len(archivos) + len(programas)
        score = calcular_score_keylogger(total_hallazgos)

        evento = {
            "tipo": "Keylogger",
            "procesos": procesos,
            "archivos": archivos,
            "programas": programas,
            "score": score,
            "descripcion": [],
        }

        if total_hallazgos > 0:
            evento["descripcion"] = [
                f"Procesos sospechosos: {len(procesos)}",
                f"Archivos sospechosos: {len(archivos)}",
                f"Programas sospechosos: {len(programas)}",
            ]
            if modo_interactivo:
                # Retornar hallazgos para mostrar al usuario antes de bloquear
                return evento

            # Si no es interactivo, registra y bloquea automáticamente
            registrar_evento(
                tipo="Keylogger",
                descripcion=f"Detectados {total_hallazgos} elementos sospechosos.",
                severidad="ALTA" if score >= 0.5 else "MEDIA",
            )
            return evento

        # Si no hay hallazgos
        evento["descripcion"] = ["Sin hallazgos"]
        return evento


""" 
Algoritmos relacionados:
    *Guardar registros con AES-256 + hash SHA-512 para integridad.
Contribución a fórmula de amenaza S:
S_keylogger = w_keylogger * numero_procesos_sospechosos
S_keylogger = 0.4 * 2
donde w_keylogger es peso asignado a keyloggers y numero_procesos_sospechosos es la cantidad de procesos detectados.

"""
"""
Detector extendido de Keyloggers
================================

Módulo avanzado de detección de keyloggers y software espía en el sistema.
Incluye revisión de procesos activos, archivos ejecutables sospechosos y
aplicaciones instaladas en el sistema operativo Windows.

Componentes:
- Escaneo de procesos activos.
- Detección de archivos con extensiones críticas (.exe, .dll, .scr, .bat, .cmd, .msi).
- Revisión de aplicaciones instaladas (si se ejecuta en Windows).
- Cálculo de nivel de amenaza y registro de auditoría.

Algoritmos:
    * Revisión de procesos (psutil)
    * Análisis de archivos con extensiones críticas
    * Detección de software instalado
    * Registro cifrado con AES-256 + SHA-512
    * Fórmula: S_keylogger = w_keylogger * (procesos + archivos + instalaciones)
"""
