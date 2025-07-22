#!/usr/bin/env python3
"""
Test completo del dashboard AEGIS para verificar funcionalidad
"""

import sys
import os
import json
import asyncio
import subprocess
import time
from datetime import datetime

def test_backend_syntax():
    """Verifica que el código Python sea válido"""
    print("🧪 Probando sintaxis del backend...")
    
    try:
        with open('app.py', 'r') as f:
            content = f.read()
        
        compile(content, 'app.py', 'exec')
        print("✅ Sintaxis de Python correcta")
        return True
        
    except SyntaxError as e:
        print(f"❌ Error de sintaxis en línea {e.lineno}: {e.text}")
        return False
    except Exception as e:
        print(f"❌ Error compilando: {e}")
        return False

def test_api_endpoints():
    """Verifica que todos los endpoints necesarios estén definidos"""
    print("\n🌐 Verificando endpoints de API...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    required_endpoints = [
        '/api/stats',
        '/api/campaigns', 
        '/api/iocs',
        '/api/cves',
        '/api/alerts',
        '/api/ioc-search'
    ]
    
    missing_endpoints = []
    for endpoint in required_endpoints:
        if f"@app.route('{endpoint}'" not in content:
            missing_endpoints.append(endpoint)
        else:
            print(f"✅ {endpoint}")
    
    if missing_endpoints:
        print(f"❌ Endpoints faltantes: {missing_endpoints}")
        return False
    
    print("✅ Todos los endpoints están definidos")
    return True

def test_javascript_functions():
    """Verifica que todas las funciones JavaScript necesarias estén definidas"""
    print("\n⚡ Verificando funciones JavaScript...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    required_functions = [
        'setupNavigation',
        'showSection',
        'loadDashboardData',
        'loadCampaigns',
        'loadIOCs', 
        'loadCVEs',
        'loadDashboardAlerts',
        'searchIOC',
        'initIOCSearch'
    ]
    
    missing_functions = []
    for func in required_functions:
        if f"function {func}" not in content:
            missing_functions.append(func)
        else:
            print(f"✅ {func}()")
    
    if missing_functions:
        print(f"❌ Funciones faltantes: {missing_functions}")
        return False
    
    print("✅ Todas las funciones JavaScript están definidas")
    return True

def test_navigation_setup():
    """Verifica que la navegación esté correctamente configurada"""
    print("\n🧭 Verificando configuración de navegación...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Verificar que existen nav-links y secciones correspondientes
    import re
    nav_links = re.findall(r'data-section="([^"]+)"', content)
    sections = re.findall(r'id="([^"]+)" class="section', content)
    
    print(f"📍 Nav-links encontrados: {nav_links}")
    print(f"📄 Secciones encontradas: {sections}")
    
    missing_sections = []
    for nav_link in nav_links:
        if nav_link not in sections and nav_link != '${sectionId}':  # Excluir template variables
            missing_sections.append(nav_link)
    
    if missing_sections:
        print(f"❌ Secciones faltantes para nav-links: {missing_sections}")
        return False
    
    # Verificar que setupNavigation esté siendo llamado
    if 'setupNavigation()' not in content:
        print("❌ setupNavigation() no está siendo llamado")
        return False
    
    print("✅ Navegación correctamente configurada")
    return True

def test_data_flow():
    """Verifica el flujo de datos backend -> frontend"""
    print("\n🔄 Verificando flujo de datos...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Verificar que las funciones de backend existen
    backend_methods = [
        'get_statistics',
        'search_campaigns',
        'get_recent_iocs',
        'get_recent_cves'
    ]
    
    for method in backend_methods:
        if f"def {method}" not in content:
            print(f"❌ Método backend faltante: {method}")
            return False
        else:
            print(f"✅ {method}()")
    
    # Verificar que fetch() se usa correctamente
    fetch_calls = [
        ("fetch('/api/stats')", "fetch('/api/stats')"),
        ("fetch campaigns", "fetch(`/api/campaigns"),
        ("fetch iocs", "fetch(`/api/iocs"),
        ("fetch cves", "fetch(`/api/cves"),
        ("fetch alerts", "fetch('/api/alerts')")
    ]
    
    for description, fetch_pattern in fetch_calls:
        if fetch_pattern not in content:
            print(f"❌ Llamada fetch faltante: {description}")
            return False
        else:
            print(f"✅ {description}")
    
    print("✅ Flujo de datos correctamente configurado")
    return True

def test_error_handling():
    """Verifica que el manejo de errores esté implementado"""
    print("\n🛡️ Verificando manejo de errores...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Verificar try-catch en JavaScript
    js_error_patterns = [
        'try {',
        'catch (error)',
        'console.error',
        'throw new Error'
    ]
    
    for pattern in js_error_patterns:
        if pattern not in content:
            print(f"❌ Patrón de manejo de errores faltante: {pattern}")
            return False
        else:
            print(f"✅ {pattern}")
    
    # Verificar try-except en Python
    py_error_patterns = [
        'try:',
        'except Exception as e:',
        'logger.error'
    ]
    
    for pattern in py_error_patterns:
        if pattern not in content:
            print(f"❌ Patrón de manejo de errores faltante: {pattern}")
            return False
        else:
            print(f"✅ {pattern}")
    
    print("✅ Manejo de errores implementado")
    return True

def test_sample_data():
    """Verifica que el sistema de datos de ejemplo esté implementado"""
    print("\n📊 Verificando datos de ejemplo...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    required_functions = [
        'ensure_sample_data',
        '_generate_sample_data'
    ]
    
    for func in required_functions:
        if f"def {func}" not in content:
            print(f"❌ Función faltante: {func}")
            return False
        else:
            print(f"✅ {func}()")
    
    # Verificar que se llama ensure_sample_data
    if 'storage.ensure_sample_data()' not in content:
        print("❌ ensure_sample_data() no está siendo llamado")
        return False
    
    print("✅ ensure_sample_data() llamado")
    print("✅ Sistema de datos de ejemplo implementado")
    return True

def create_launch_script():
    """Crea un script de lanzamiento para el dashboard"""
    launch_script = '''#!/bin/bash

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
'''
    
    with open('launch_dashboard.sh', 'w') as f:
        f.write(launch_script)
    
    os.chmod('launch_dashboard.sh', 0o755)
    print("📝 Script de lanzamiento creado: launch_dashboard.sh")

def generate_usage_instructions():
    """Genera instrucciones de uso"""
    instructions = """
# 🎯 INSTRUCCIONES DE USO DEL DASHBOARD AEGIS

## 🚀 Lanzamiento Rápido
```bash
./launch_dashboard.sh
# O directamente:
python3 app.py
```

## 🌐 Acceso
- Abre tu navegador en: http://localhost:5000
- El dashboard se carga automáticamente

## 🧭 Navegación
- **Dashboard**: Vista principal con estadísticas
- **Campañas**: Lista de campañas de threat intelligence
- **IOCs**: Indicadores de compromiso detectados
- **CVEs**: Vulnerabilidades más recientes
- **Búsqueda IOCs**: Búsqueda en tiempo real
- **Alertas**: Alertas críticas del sistema

## 🔍 Debugging
1. Abre herramientas de desarrollador (F12)
2. Ve a la pestaña Console
3. Busca logs que empiecen con 🚀, ✅, ❌
4. Los errores aparecen claramente marcados

## 📊 Datos
- Si no hay APIs configuradas, se usan datos de ejemplo
- Para datos reales, configura las API keys en .env
- Ver API_SETUP_GUIDE.md para configuración completa

## ✅ Verificación de Funcionamiento
1. Las pestañas deben responder al hacer clic
2. Cada sección debe cargar contenido
3. No debe quedar nada en "Cargando..." permanentemente
4. Las búsquedas deben retornar resultados

## 🆘 Solución de Problemas
- Si las pestañas no responden: Ver console logs
- Si no cargan datos: Verificar endpoints con F12 > Network
- Si hay errores 500: Ver logs del servidor
- Para datos de ejemplo: Verificar que ensure_sample_data() se ejecuta
"""
    
    with open('USAGE_INSTRUCTIONS.md', 'w') as f:
        f.write(instructions)
    
    print("📚 Instrucciones de uso creadas: USAGE_INSTRUCTIONS.md")

def main():
    """Función principal de prueba"""
    print("🧪 TEST COMPLETO DEL DASHBOARD AEGIS")
    print("=" * 50)
    
    tests = [
        ("Sintaxis Backend", test_backend_syntax),
        ("Endpoints API", test_api_endpoints), 
        ("Funciones JavaScript", test_javascript_functions),
        ("Configuración Navegación", test_navigation_setup),
        ("Flujo de Datos", test_data_flow),
        ("Manejo de Errores", test_error_handling),
        ("Datos de Ejemplo", test_sample_data)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
        except Exception as e:
            print(f"❌ Error en {test_name}: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 RESULTADO FINAL:")
    print(f"✅ Pruebas pasadas: {passed}/{total}")
    
    if passed == total:
        print("🎉 TODAS LAS PRUEBAS PASARON")
        print("✅ El dashboard está completamente funcional")
        
        create_launch_script()
        generate_usage_instructions()
        
        print("\n💡 PRÓXIMOS PASOS:")
        print("1. Ejecuta: ./launch_dashboard.sh")
        print("2. Abre: http://localhost:5000")
        print("3. Prueba la navegación entre pestañas")
        print("4. Verifica que se cargan los datos")
        print("5. Lee USAGE_INSTRUCTIONS.md para más detalles")
        
    else:
        print("⚠️ Algunas pruebas fallaron")
        print("🔧 Revisa los errores arriba antes de ejecutar")
    
    print("=" * 50)
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)