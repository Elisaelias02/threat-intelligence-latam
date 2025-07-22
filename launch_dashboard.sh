#!/bin/bash

echo "🚀 Lanzando AEGIS Threat Intelligence Dashboard"
echo "=============================================="

echo "🔍 Verificando archivos..."
if [ ! -f "app.py" ]; then
    echo "❌ app.py no encontrado"
    exit 1
fi

echo "✅ app.py encontrado"

echo "🧪 Verificando sintaxis..."
python3 -c "
try:
    with open('app.py', 'r') as f:
        content = f.read()
    compile(content, 'app.py', 'exec')
    print('✅ Sintaxis correcta')
except Exception as e:
    print(f'❌ Error: {e}')
    exit(1)
"

echo "🌐 Iniciando servidor Flask..."
echo "📍 Dashboard disponible en: http://localhost:5000"
echo "🔧 Usa Ctrl+C para detener el servidor"
echo ""

python3 app.py
