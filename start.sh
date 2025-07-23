#!/bin/bash

echo "========================================"
echo "🛡️  AEGIS Threat Intelligence LATAM"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   Run: python3 -m venv venv"
    echo "   Then: source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  Archivo .env no encontrado"
    echo "   Creando archivo .env de ejemplo..."
    cp .env .env 2>/dev/null || echo "# Configura tus API keys aquí" > .env
fi

echo "🚀 Iniciando sistema de Threat Intelligence..."
echo ""
echo "📍 Dashboard disponible en:"
echo "   http://localhost:5000"
echo ""
echo "🔑 Para obtener datos reales, configura las API keys en .env"
echo "   - VirusTotal: https://www.virustotal.com/gui/join-us"
echo "   - OTX: https://otx.alienvault.com/"
echo "   - IBM X-Force: https://exchange.xforce.ibmcloud.com/"
echo ""
echo "⏹️  Presiona Ctrl+C para detener el servidor"
echo ""

# Start the application
python app.py