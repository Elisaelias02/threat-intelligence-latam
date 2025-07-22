#!/usr/bin/env python3
"""
Versión simplificada del dashboard AEGIS para pruebas
Sin dependencias externas
"""

import json
import sys
import os
from datetime import datetime
from urllib.parse import unquote

# Mock de flask
class MockFlask:
    def __init__(self, name):
        self.routes = {}
        self.methods = {}
    
    def route(self, path, methods=None):
        def decorator(func):
            self.routes[path] = func
            self.methods[path] = methods or ['GET']
            return func
        return decorator
    
    def run(self, host='0.0.0.0', port=5000, debug=False, threaded=True):
        print(f"🚀 Servidor de prueba iniciado en http://{host}:{port}")
        print("📝 Rutas disponibles:")
        for path in self.routes:
            methods = ', '.join(self.methods[path])
            print(f"   {methods:10} {path}")
        
        print("\n🌐 Para simular el dashboard:")
        print(f"   curl http://{host}:{port}/")
        print(f"   curl http://{host}:{port}/api/stats")
        
        # Simular servidor HTTP básico
        try:
            import http.server
            import socketserver
            
            class TestHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        html = self.generate_dashboard_html()
                        self.wfile.write(html.encode())
                    elif self.path == '/api/stats':
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        stats = self.generate_mock_stats()
                        self.wfile.write(json.dumps(stats).encode())
                    else:
                        super().do_GET()
                
                def generate_dashboard_html(self):
                    return '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>AEGIS Test Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: white; margin: 0; }
        .header { background: #2d3748; padding: 1rem; text-align: center; }
        .nav { background: #1a2332; padding: 1rem; }
        .nav-link { display: inline-block; margin: 0 1rem; padding: 0.5rem 1rem; 
                   background: #2d3748; color: white; text-decoration: none; 
                   border-radius: 4px; cursor: pointer; }
        .nav-link.active { background: #00ff7f; color: black; }
        .content { padding: 2rem; }
        .section { display: none; }
        .section.active { display: block; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 2rem 0; }
        .stat-card { background: #2d3748; padding: 1rem; border-radius: 8px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AEGIS Threat Intelligence - Test Dashboard</h1>
        <p>✅ Navegación funcionando correctamente</p>
    </div>
    
    <nav class="nav">
        <div class="nav-link active" data-section="dashboard">📊 Dashboard</div>
        <div class="nav-link" data-section="campaigns">🎯 Campañas</div>
        <div class="nav-link" data-section="iocs">🔍 IOCs</div>
        <div class="nav-link" data-section="cves">🐛 CVEs</div>
        <div class="nav-link" data-section="ioc-search">🔎 Búsqueda IOC</div>
        <div class="nav-link" data-section="alerts">⚠️ Alertas</div>
    </nav>
    
    <div class="content">
        <div id="dashboard" class="section active">
            <h2>📊 Dashboard Principal</h2>
            <div class="stats">
                <div class="stat-card">
                    <h3>Campañas</h3>
                    <div id="campaigns-count">0</div>
                </div>
                <div class="stat-card">
                    <h3>IOCs</h3>
                    <div id="iocs-count">0</div>
                </div>
                <div class="stat-card">
                    <h3>CVEs</h3>
                    <div id="cves-count">0</div>
                </div>
                <div class="stat-card">
                    <h3>Alertas</h3>
                    <div id="alerts-count">0</div>
                </div>
            </div>
        </div>
        
        <div id="campaigns" class="section">
            <h2>🎯 Campañas Activas</h2>
            <p>Aquí se mostrarían las campañas de threat intelligence.</p>
        </div>
        
        <div id="iocs" class="section">
            <h2>🔍 IOCs en Vivo</h2>
            <p>Aquí se mostrarían los indicadores de compromiso.</p>
        </div>
        
        <div id="cves" class="section">
            <h2>🐛 CVEs y Vulnerabilidades</h2>
            <p>Aquí se mostrarían las vulnerabilidades más recientes.</p>
        </div>
        
        <div id="ioc-search" class="section">
            <h2>🔎 Búsqueda de IOCs</h2>
            <input type="text" placeholder="Ingresa hash, IP, dominio o URL" style="width: 300px; padding: 0.5rem;">
            <button onclick="searchIOC()">Buscar</button>
            <div id="search-results" style="margin-top: 1rem;"></div>
        </div>
        
        <div id="alerts" class="section">
            <h2>⚠️ Alertas de Seguridad</h2>
            <p>Aquí se mostrarían las alertas en tiempo real.</p>
        </div>
    </div>
    
    <script>
        // Configurar navegación
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', function() {
                const section = this.dataset.section;
                showSection(section);
            });
        });
        
        function showSection(sectionId) {
            // Ocultar todas las secciones
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Mostrar la sección seleccionada
            document.getElementById(sectionId).classList.add('active');
            
            // Actualizar navegación
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');
            
            console.log('✅ Navegación a:', sectionId);
        }
        
        function searchIOC() {
            const input = document.querySelector('#ioc-search input');
            const results = document.getElementById('search-results');
            results.innerHTML = `<p>🔍 Buscando: ${input.value}</p><p>✅ Sistema funcionando correctamente</p>`;
        }
        
        // Cargar estadísticas
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('campaigns-count').textContent = data.total_campaigns || 0;
                document.getElementById('iocs-count').textContent = data.total_iocs || 0;
                document.getElementById('cves-count').textContent = data.total_cves || 0;
                document.getElementById('alerts-count').textContent = data.total_alerts || 0;
            })
            .catch(error => {
                console.log('Using mock data');
                document.getElementById('campaigns-count').textContent = '✅';
                document.getElementById('iocs-count').textContent = '✅';
                document.getElementById('cves-count').textContent = '✅';
                document.getElementById('alerts-count').textContent = '✅';
            });
        
        console.log('🎉 Dashboard de prueba cargado exitosamente');
    </script>
</body>
</html>'''
                
                def generate_mock_stats(self):
                    return {
                        'total_campaigns': 42,
                        'total_iocs': 158,
                        'total_cves': 89,
                        'total_alerts': 7,
                        'status': 'operational'
                    }
            
            print(f"🌐 Iniciando servidor HTTP en puerto {port}...")
            with socketserver.TCPServer(("", port), TestHandler) as httpd:
                print(f"✅ Servidor corriendo. Abre: http://localhost:{port}")
                print("Press Ctrl+C para detener")
                httpd.serve_forever()
                
        except ImportError:
            print("⚠️ Módulo http.server no disponible")
        except Exception as e:
            print(f"⚠️ No se pudo iniciar servidor: {e}")
        
        print("\n✅ Simulación completada")

# Mock de CORS
def CORS(app):
    pass

# Mock de jsonify
def jsonify(data):
    return json.dumps(data)

# Crear app de prueba
app = MockFlask(__name__)

# Mock de configuración
class Config:
    def __init__(self):
        self.config = {}
    
    def get(self, key, default=None):
        return os.environ.get(key, default)

# Mock de storage
class MockStorage:
    def get_statistics(self):
        return {
            'total_campaigns': 0,
            'total_iocs': 0,
            'campaigns_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'campaigns_by_source': {},
            'iocs_by_type': {},
            'iocs_by_country': {},
            'malware_families': {}
        }
    
    def search_campaigns(self, query="", filters=None):
        return []

# Rutas principales
@app.route('/')
def dashboard():
    """Dashboard principal de prueba"""
    return "Dashboard HTML"

@app.route('/api/stats')
def api_stats():
    """API de estadísticas de prueba"""
    storage = MockStorage()
    stats = storage.get_statistics()
    return jsonify(stats)

@app.route('/api/campaigns')
def api_campaigns():
    """API de campañas de prueba"""
    storage = MockStorage()
    campaigns = storage.search_campaigns()
    return jsonify(campaigns)

def main():
    """Función principal"""
    print("🧪 AEGIS DASHBOARD - VERSIÓN DE PRUEBA")
    print("=" * 50)
    print("📋 Esta versión permite probar la navegación sin dependencias")
    print("🔧 Solo requiere Python estándar")
    print("=" * 50)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n👋 Dashboard detenido por el usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()