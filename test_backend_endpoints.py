#!/usr/bin/env python3
"""
Test directo de los endpoints del backend para verificar respuestas
"""
import sys
import os
import json
import time
import subprocess
import threading
import requests
from datetime import datetime

def test_endpoint(url, endpoint_name):
    """Testa un endpoint específico"""
    try:
        print(f"🔍 Testando {endpoint_name}...")
        response = requests.get(url, timeout=10)
        
        print(f"  📊 Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
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
            print(f"  ❌ Error HTTP: {response.status_code}")
            print(f"  📝 Respuesta: {response.text[:200]}")
            return False, None
            
    except requests.exceptions.ConnectionError:
        print(f"  ❌ No se pudo conectar - servidor no está corriendo")
        return False, None
    except requests.exceptions.Timeout:
        print(f"  ❌ Timeout - endpoint muy lento")
        return False, None
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False, None

def run_server_background():
    """Ejecuta el servidor en background"""
    try:
        print("🚀 Iniciando servidor Flask...")
        process = subprocess.Popen(
            [sys.executable, 'app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='.'
        )
        
        # Esperar un poco para que el servidor inicie
        time.sleep(3)
        
        # Verificar que el proceso sigue corriendo
        if process.poll() is None:
            print("✅ Servidor iniciado correctamente")
            return process
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Error iniciando servidor:")
            print(f"STDOUT: {stdout.decode()}")
            print(f"STDERR: {stderr.decode()}")
            return None
            
    except Exception as e:
        print(f"❌ Error ejecutando servidor: {e}")
        return None

def main():
    print("🧪 TEST DIRECTO DE ENDPOINTS BACKEND")
    print("=" * 50)
    
    # Verificar que app.py existe
    if not os.path.exists('app.py'):
        print("❌ app.py no encontrado")
        return False
    
    # Iniciar servidor
    server_process = run_server_background()
    if not server_process:
        return False
    
    try:
        # Esperar un poco más para asegurar que el servidor esté listo
        print("⏳ Esperando que el servidor esté listo...")
        time.sleep(2)
        
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
            success, data = test_endpoint(url, name)
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
            else:
                print("✅ Endpoints funcionan Y tienen datos")
                print("💡 PROBLEMA: Debe ser en el frontend JavaScript")
        else:
            print(f"❌ {total - successful} endpoints fallan")
            print("💡 SOLUCIÓN: Revisar errores de servidor y configuración")
        
        return successful == total
        
    finally:
        # Terminar servidor
        if server_process:
            print("\n🛑 Terminando servidor...")
            server_process.terminate()
            server_process.wait()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)