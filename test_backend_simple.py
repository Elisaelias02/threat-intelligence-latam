#!/usr/bin/env python3
"""
Test simplificado usando solo biblioteca estándar
"""
import sys
import os
import json
import time
import subprocess
import urllib.request
import urllib.error

def test_endpoint_simple(url, endpoint_name):
    """Testa un endpoint usando urllib"""
    try:
        print(f"🔍 Testando {endpoint_name}...")
        
        # Crear request
        req = urllib.request.Request(url)
        
        # Hacer la request con timeout
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.getcode()
            print(f"  📊 Status: {status_code}")
            
            if status_code == 200:
                data = json.loads(response.read().decode())
                print(f"  📦 Tipo: {type(data)}")
                
                if isinstance(data, list):
                    print(f"  📋 Items: {len(data)}")
                    if len(data) > 0:
                        print(f"  📝 Primer item: {list(data[0].keys()) if isinstance(data[0], dict) else str(data[0])[:50]}")
                    else:
                        print(f"  ⚠️ Lista vacía")
                elif isinstance(data, dict):
                    print(f"  🔑 Keys: {list(data.keys())}")
                    for key, value in data.items():
                        if isinstance(value, (int, float)):
                            print(f"    {key}: {value}")
                
                return True, data
            else:
                print(f"  ❌ Error HTTP: {status_code}")
                return False, None
                
    except urllib.error.URLError as e:
        print(f"  ❌ Error de conexión: {e}")
        return False, None
    except urllib.error.HTTPError as e:
        print(f"  ❌ Error HTTP: {e.code} - {e.reason}")
        return False, None
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False, None

def check_server_running():
    """Verifica si el servidor está corriendo"""
    try:
        req = urllib.request.Request('http://localhost:5000/')
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.getcode() == 200
    except:
        return False

def main():
    print("🧪 TEST SIMPLIFICADO DE ENDPOINTS")
    print("=" * 40)
    
    # Verificar si el servidor ya está corriendo
    if check_server_running():
        print("✅ Servidor Flask ya está corriendo")
    else:
        print("❌ Servidor Flask no está corriendo")
        print("💡 Para testear:")
        print("   1. Ejecuta en otra terminal: python3 app.py")
        print("   2. Luego ejecuta este test otra vez")
        return False
    
    # Endpoints a probar
    endpoints = [
        ('http://localhost:5000/api/stats', 'Estadísticas'),
        ('http://localhost:5000/api/campaigns', 'Campañas'),
        ('http://localhost:5000/api/iocs', 'IOCs'),
        ('http://localhost:5000/api/cves', 'CVEs'),
        ('http://localhost:5000/api/alerts', 'Alertas')
    ]
    
    results = {}
    print("\n🔍 TESTANDO ENDPOINTS:")
    print("-" * 30)
    
    for url, name in endpoints:
        success, data = test_endpoint_simple(url, name)
        results[name] = {
            'success': success,
            'data': data
        }
        print()
    
    # Análisis de resultados
    print("📊 ANÁLISIS DE RESULTADOS:")
    print("-" * 30)
    
    successful = sum(1 for r in results.values() if r['success'])
    total = len(results)
    
    print(f"✅ Endpoints funcionando: {successful}/{total}")
    
    # Análisis específico
    for name, result in results.items():
        if result['success']:
            data = result['data']
            if isinstance(data, list) and len(data) == 0:
                print(f"⚠️ {name}: Funciona pero retorna lista vacía")
            elif isinstance(data, dict):
                # Analizar estadísticas
                if name == 'Estadísticas':
                    total_campaigns = data.get('total_campaigns', 0)
                    total_iocs = data.get('total_iocs', 0)
                    if total_campaigns > 0 or total_iocs > 0:
                        print(f"✅ {name}: {total_campaigns} campañas, {total_iocs} IOCs")
                    else:
                        print(f"⚠️ {name}: Estadísticas en cero")
            else:
                print(f"✅ {name}: Datos válidos")
        else:
            print(f"❌ {name}: No funciona")
    
    # Diagnóstico final
    print("\n🎯 DIAGNÓSTICO:")
    print("-" * 20)
    
    if successful == total:
        print("✅ Todos los endpoints funcionan")
        # Verificar si hay datos
        stats = results.get('Estadísticas', {}).get('data', {})
        campaigns = results.get('Campañas', {}).get('data', [])
        iocs = results.get('IOCs', {}).get('data', [])
        
        if len(campaigns) == 0 and len(iocs) == 0:
            print("⚠️ PROBLEMA: Endpoints funcionan pero no hay datos")
            print("💡 SOLUCIÓN: Verificar ensure_sample_data() y regenerar datos")
            print("\n🔧 PASOS PARA SOLUCIONAR:")
            print("1. El backend funciona pero no tiene datos")
            print("2. Verificar logs del servidor al iniciar")
            print("3. Buscar: 'No hay datos disponibles, generando datos de ejemplo...'")
            print("4. Si no aparece, hay problema con ensure_sample_data()")
        else:
            print("✅ Endpoints funcionan Y tienen datos")
            print("💡 PROBLEMA: Debe ser en el frontend JavaScript")
            print("\n🔧 PASOS PARA SOLUCIONAR:")
            print("1. Abrir dashboard en navegador")
            print("2. Presionar F12 → Console")
            print("3. Buscar errores de JavaScript")
            print("4. Verificar que se ejecuten loadCampaigns(), loadIOCs(), etc.")
    else:
        print(f"❌ {total - successful} endpoints fallan")
        print("💡 SOLUCIÓN: Revisar errores de servidor y configuración")
    
    return successful == total

if __name__ == "__main__":
    success = main()
    print("\n" + "=" * 40)
    if success:
        print("✅ TEST COMPLETADO - Backend funciona")
    else:
        print("❌ TEST FALLIDO - Revisar problemas")
    sys.exit(0 if success else 1)