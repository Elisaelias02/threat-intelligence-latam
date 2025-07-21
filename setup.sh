#!/bin/bash

echo "=========================================="
echo "AEGIS Threat Intelligence Setup"
echo "=========================================="

# Check Python version
echo "Verificando Python..."
python_version=$(python3 --version 2>&1 | cut -d" " -f2 | cut -d"." -f1,2)
required_version="3.8"

if python3 -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)"; then
    echo "✓ Python $python_version encontrado"
else
    echo "✗ Python 3.8+ requerido. Versión actual: $python_version"
    exit 1
fi

# Install dependencies
echo
echo "Instalando dependencias..."
if pip3 install -r requirements.txt; then
    echo "✓ Dependencias instaladas correctamente"
else
    echo "✗ Error instalando dependencias"
    exit 1
fi

# Create configuration file if it doesn't exist
echo
echo "Configurando entorno..."
if [ ! -f .env ]; then
    cp config_example.env .env
    echo "✓ Archivo .env creado desde config_example.env"
    echo "   Por favor, edita .env con tus API keys"
else
    echo "✓ Archivo .env ya existe"
fi

# Check MongoDB (optional)
echo
echo "Verificando MongoDB (opcional)..."
if command -v mongod &> /dev/null; then
    echo "✓ MongoDB encontrado"
    
    # Try to start MongoDB if not running
    if ! pgrep mongod > /dev/null; then
        echo "  Iniciando MongoDB..."
        if sudo systemctl start mongod 2>/dev/null || sudo service mongodb start 2>/dev/null; then
            echo "  ✓ MongoDB iniciado"
        else
            echo "  ⚠ No se pudo iniciar MongoDB automáticamente"
            echo "    El sistema funcionará con almacenamiento en memoria"
        fi
    else
        echo "  ✓ MongoDB ya está ejecutándose"
    fi
else
    echo "⚠ MongoDB no encontrado - usando almacenamiento en memoria"
    echo "  Para instalar MongoDB:"
    echo "  - Ubuntu/Debian: sudo apt-get install mongodb"
    echo "  - macOS: brew install mongodb-community"
fi

# Create logs directory
mkdir -p logs
echo "✓ Directorio de logs creado"

echo
echo "=========================================="
echo "Setup completado!"
echo "=========================================="
echo
echo "Próximos pasos:"
echo "1. Editar .env con tus API keys:"
echo "   nano .env"
echo
echo "2. Ejecutar la aplicación:"
echo "   python3 app.py"
echo
echo "3. Acceder al dashboard:"
echo "   http://localhost:5000"
echo
echo "Documentación completa en README.md"
echo "=========================================="