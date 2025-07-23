#!/bin/bash

echo "========================================"
echo "AEGIS Threat Intelligence LATAM"
echo "Setup para Sistema REAL y Funcional"
echo "========================================"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado. Por favor instálalo primero."
    exit 1
fi

echo "✅ Python 3 encontrado: $(python3 --version)"

# Instalar dependencias
echo "📦 Instalando dependencias..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencias instaladas correctamente"
else
    echo "❌ Error instalando dependencias"
    exit 1
fi

# Crear archivo .env si no existe
if [ ! -f .env ]; then
    echo "🔧 Creando archivo de configuración .env..."
    cp config_example.env .env
    echo "✅ Archivo .env creado"
    echo ""
    echo "🔑 IMPORTANTE: Edita el archivo .env para configurar tus API keys"
    echo "   - Para funcionalidad básica: configura VIRUSTOTAL_API_KEY"
    echo "   - Para funcionalidad completa: configura todas las APIs"
    echo "   - Sin configuración: funcionará con fuentes públicas limitadas"
else
    echo "✅ Archivo .env ya existe"
fi

echo ""
echo "=========================================="
echo "🚀 CONFIGURACIÓN COMPLETADA"
echo "=========================================="
echo ""
echo "📝 PASOS SIGUIENTES:"
echo ""
echo "1. 🔑 CONFIGURAR APIs (Recomendado):"
echo "   nano .env"
echo "   # Agregar tu VIRUSTOTAL_API_KEY para búsquedas de IOCs"
echo "   # Agregar OTX_API_KEY para pulsos de amenazas"
echo ""
echo "2. 🚀 INICIAR EL SISTEMA:"
echo "   python3 app.py"
echo ""
echo "3. 🌐 ABRIR DASHBOARD:"
echo "   http://localhost:5000"
echo ""
echo "=========================================="
echo "🔗 OBTENER API KEYS GRATIS:"
echo "=========================================="
echo ""
echo "🔍 VirusTotal (OBLIGATORIO para búsquedas):"
echo "   https://www.virustotal.com/gui/join-us"
echo ""
echo "📡 AlienVault OTX (Recomendado):"
echo "   https://otx.alienvault.com/"
echo ""
echo "🏢 IBM X-Force (Opcional):"
echo "   https://exchange.xforce.ibmcloud.com/"
echo ""
echo "🐛 NVD CVEs (Opcional):"
echo "   https://nvd.nist.gov/developers/request-an-api-key"
echo ""
echo "=========================================="
echo "📊 FUNCIONALIDADES SIN API KEYS:"
echo "=========================================="
echo ""
echo "✅ MalwareBazaar - Muestras de malware LATAM"
echo "✅ URLhaus - URLs maliciosas activas"
echo "✅ NVD CVEs - Vulnerabilidades (rate limit bajo)"
echo "❌ Búsqueda manual de IOCs"
echo "❌ VirusTotal data"
echo "❌ OTX Pulses"
echo "❌ IBM X-Force intelligence"
echo ""
echo "🎯 Para máxima funcionalidad, configura al menos VIRUSTOTAL_API_KEY"
echo ""

# Verificar si hay API keys configuradas
if [ -f .env ]; then
    if grep -q "tu_api_key" .env; then
        echo "⚠️  RECORDATORIO: Actualiza las API keys en el archivo .env"
    else
        echo "✅ Parece que tienes API keys configuradas"
    fi
fi

echo ""
echo "🚀 ¡Listo para usar! Ejecuta: python3 app.py"