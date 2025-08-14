# GuardianUnivalle-Benito-Yucra

Paso 1: Activar el entorno virtual
crear un entor no visrtual 
python -m venv GuardianUnivalle-Benito-Yucra 
.\GuardianUnivalle-Benito-Yucra\Scripts\Activate.ps1

instalaciones 
Paso 2: Instalar herramientas necesarias
pip install --upgrade pip
pip install build twine

pedira que sea ctualice 
python.exe -m pip install --upgrade pip

Construir la librería
Paso 3: Construir la librería
python -m build
Paso 5: Subir la librería a PyPI
python -m twine upload dist/*
