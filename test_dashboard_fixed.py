#!/usr/bin/env python3
"""
Script de prueba para verificar la funcionalidad del dashboard
"""

import sys
import os

def test_dashboard_structure():
    """Verifica la estructura del dashboard"""
    print("🔍 Verificando estructura del dashboard...")
    
    if not os.path.exists('app.py'):
        print("❌ app.py no encontrado")
        return False
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    critical_elements = [
        'data-section="dashboard"',
        'data-section="campaigns"', 
        'data-section="iocs"',
        'data-section="cves"',
        'data-section="ioc-search"',
        'data-section="alerts"',
        'id="dashboard"',
        'id="campaigns"',
        'id="iocs"', 
        'id="cves"',
        'id="ioc-search"',
        'id="alerts"',
        'setupNavigation()',
        'showSection(',
        'loadCampaigns()',
        'loadIOCs()',
        'loadCVEs()',
        'searchIOC()',
        '@app.route(\'/\')',
        '@app.route(\'/api/stats\')',
        '@app.route(\'/api/campaigns\')',
        '@app.route(\'/api/ioc-search',
        'class Config:',
        'class AegisStorage',
        'class ProfessionalThreatIntelligence',
        'class RealTimeIOCSearcher'
    ]
    
    missing_elements = []
    for element in critical_elements:
        if element not in content:
            missing_elements.append(element)
    
    if missing_elements:
        print("❌ Elementos faltantes:")
        for element in missing_elements:
            print(f"   - {element}")
        return False
    
    print("✅ Todos los elementos críticos están presentes")
    return True

def test_navigation_functionality():
    """Verifica que la navegación esté bien configurada"""
    print("\n🧭 Verificando funcionalidad de navegación...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    navigation_sections = [
        'dashboard', 'campaigns', 'iocs', 'cves', 'ioc-search', 'alerts'
    ]
    
    all_good = True
    for section in navigation_sections:
        nav_link = f'data-section="{section}"' in content
        section_div = f'id="{section}"' in content
        
        if nav_link and section_div:
            print(f"   ✅ {section}: Nav-link ✓ | Section ✓")
        else:
            print(f"   ❌ {section}: Nav-link {'✓' if nav_link else '✗'} | Section {'✓' if section_div else '✗'}")
            all_good = False
    
    return all_good

def test_javascript_setup():
    """Verifica que las funciones JavaScript estén configuradas"""
    print("\n⚡ Verificando JavaScript...")
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    js_functions = [
        'document.addEventListener(\'DOMContentLoaded\'',
        'setupNavigation()',
        'showSection(',
        'console.log(\'🚀 Inicializando AEGIS Dashboard',
        'addEventListener(\'click\''
    ]
    
    all_present = True
    for func in js_functions:
        if func in content:
            print(f"   ✅ {func}")
        else:
            print(f"   ❌ {func}")
            all_present = False
    
    return all_present

def main():
    """Función principal de prueba"""
    print("🧪 PRUEBA RÁPIDA DEL DASHBOARD AEGIS")
    print("=" * 50)
    
    tests = [
        test_dashboard_structure,
        test_navigation_functionality,
        test_javascript_setup
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Error en prueba: {e}")
            results.append(False)
    
    # Resultado final
    print("\n" + "=" * 50)
    print("🎯 RESULTADO FINAL:")
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print("✅ TODAS LAS PRUEBAS PASARON")
        print("🎉 El dashboard debería funcionar correctamente")
        print("\n💡 Instrucciones:")
        print("   1. Ejecuta: python3 app.py")
        print("   2. Abre: http://localhost:5000")
        print("   3. Prueba la navegación entre pestañas")
    else:
        print(f"⚠️ {passed}/{total} PRUEBAS PASARON")
        print("🔧 Revisa los errores arriba")
    
    print("=" * 50)
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)