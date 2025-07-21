# AEGIS Threat Intelligence LATAM - Professional Edition

🔎 **Descripción**  
Sistema profesional de threat intelligence especializado en amenazas de Latinoamérica. Integra múltiples APIs y fuentes de inteligencia para recolectar, correlacionar y analizar indicadores de compromiso (IOCs) y vulnerabilidades.

---

## 🚀 Nuevas Características Profesionales

### APIs Integradas
- **VirusTotal API** - Análisis de URLs y archivos maliciosos
- **IBM X-Force Exchange API** - Inteligencia corporativa y reputación
- **OTX AlienVault API** - Indicadores colaborativos de la comunidad
- **Hybrid Analysis API** - Análisis avanzado de malware
- **MalwareBazaar API** - Base de datos de muestras de malware
- **NVD API** - Vulnerabilidades CVE del NIST

### Funcionalidades Avanzadas
- **Correlación de IOCs** entre múltiples fuentes
- **Rate limiting inteligente** para respetar límites de APIs
- **Manejo robusto de errores** y recuperación automática
- **Sistema de confianza** basado en múltiples confirmaciones
- **Dashboard en tiempo real** con métricas actualizadas

### 🔎 Búsqueda de IOCs en Tiempo Real
- **Panel dedicado**: Interfaz intuitiva para búsqueda de indicadores
- **Detección automática**: Reconoce automáticamente el tipo de IOC (hash, IP, URL, dominio)
- **Múltiples fuentes**: Consulta simultánea a todas las APIs configuradas
- **Análisis consensuado**: Combina resultados para mayor precisión
- **Información completa**: Reputación, país, familia de malware, detalles técnicos
- **Validación de formato**: Verifica automáticamente la validez del IOC ingresado

---

## 📦 Instalación y Configuración

### 1. Requisitos del Sistema
```bash
# Python 3.8 o superior
python --version

# MongoDB (opcional - puede usar almacenamiento en memoria)
# Ubuntu/Debian:
sudo apt-get install mongodb

# macOS con Homebrew:
brew install mongodb-community
```

### 2. Instalación de Dependencias
```bash
# Clonar el repositorio
git clone <repository-url>
cd threat-intelligence-latam

# Instalar dependencias
pip install -r requirements.txt
```

### 3. Configuración de APIs

#### Crear archivo de configuración:
```bash
cp config_example.env .env
```

#### Configurar APIs (recomendado configurar al menos 3-4):

**VirusTotal** (Gratuito - 4 req/min)
1. Registrarse en: https://www.virustotal.com/gui/join-us
2. Obtener API key desde el perfil
3. Agregar a `.env`: `VIRUSTOTAL_API_KEY=tu_api_key`

**IBM X-Force Exchange** (Gratuito - 5000 req/mes)
1. Registrarse en: https://exchange.xforce.ibmcloud.com/
2. Crear credenciales en API Settings
3. Agregar a `.env`:
   ```
   IBM_XFORCE_API_KEY=tu_api_key
   IBM_XFORCE_PASSWORD=tu_password
   ```

**OTX AlienVault** (Gratuito - 1000 req/min)
1. Registrarse en: https://otx.alienvault.com/
2. Obtener OTX Key desde Settings > API Integration
3. Agregar a `.env`: `OTX_API_KEY=tu_api_key`

**Hybrid Analysis** (Gratuito - 200 req/min)
1. Registrarse en: https://www.hybrid-analysis.com/
2. Obtener API key desde Profile
3. Agregar a `.env`: `HYBRID_ANALYSIS_API_KEY=tu_api_key`

**NVD** (Opcional - mejores límites)
1. Solicitar en: https://nvd.nist.gov/developers/request-an-api-key
2. Agregar a `.env`: `NVD_API_KEY=tu_api_key`

---

## 🏃‍♂️ Ejecución

### Modo Básico
```bash
python app.py
```

### Con Variables de Entorno
```bash
# Cargar configuración desde .env
export $(cat .env | xargs)
python app.py
```

### Con Docker (Próximamente)
```bash
docker-compose up -d
```

---

## 📊 Uso del Dashboard

1. **Acceder al dashboard**: http://localhost:5000
2. **APIs configuradas**: Se muestran en la consola al iniciar
3. **Recolección automática**: Cada 6 horas (configurable)
4. **Recolección manual**: Botón "Ejecutar Scraping" en el dashboard

### Características del Dashboard:
- **Estadísticas en tiempo real**
- **Filtros por severidad, país, fuente**
- **Exportación CSV/JSON**
- **Alertas automáticas**
- **Correlación de IOCs**

---

## 🔧 Configuración Avanzada

### Variables de Entorno Importantes:
```bash
# Base de datos
MONGO_URI=mongodb://localhost:27017/
DATABASE_NAME=aegis_threat_intel_latam

# Frecuencia de recolección (horas)
SCRAPING_INTERVAL_HOURS=6

# Configuración de logging
LOG_LEVEL=INFO
```

### Sin APIs Configuradas:
- El sistema funcionará solo con fuentes de scraping públicas
- Funcionalidad limitada pero operativa
- Se pueden agregar APIs gradualmente

---

## 🌎 Enfoque LATAM

El sistema prioriza:
- **Phishing bancario** dirigido a usuarios de LATAM
- **Malware financiero** como Mekotio, Grandoreiro, Guildma
- **Vulnerabilidades** en tecnologías usadas en la región
- **Campañas dirigidas** a países específicos
- **IOCs correlacionados** entre múltiples fuentes

### Detección Inteligente:
- Keywords específicos de LATAM (bancos, servicios, gobierno)
- Dominios con TLDs regionales (.ar, .br, .mx, etc.)
- Análisis de contenido en español/portugués
- Correlación de amenazas regionales

---

## 📋 API Endpoints

### Información del Sistema:
- `GET /api/stats` - Estadísticas generales
- `GET /api/campaigns` - Lista de campañas
- `GET /api/alerts` - Alertas críticas

### Control del Sistema:
- `POST /api/scrape` - Ejecutar recolección manual
- `GET /api/export/csv` - Exportar datos en CSV
- `GET /api/export/json` - Exportar datos en JSON

---

## 🔒 Seguridad y Privacidad

- **API Keys**: Almacenadas solo en variables de entorno
- **Rate Limiting**: Respeta límites de todas las APIs
- **No almacenamiento** de datos sensibles
- **Logs auditables** de todas las operaciones
- **Conexiones HTTPS** para todas las APIs

---

## 📈 Monitoreo y Alertas

### Alertas Automáticas:
- **Campañas críticas** (malware bancario)
- **Múltiples confirmaciones** del mismo IOC
- **Vulnerabilidades de alto riesgo** para LATAM
- **Correlaciones sospechosas**

### Métricas Clave:
- IOCs recolectados por fuente
- Nivel de confianza promedio
- Cobertura geográfica
- Familias de malware detectadas

---

## 🛠️ Solución de Problemas

### APIs No Funcionan:
1. Verificar API keys en `.env`
2. Comprobar límites de rate limiting
3. Revisar logs para errores específicos
4. El sistema continúa con fuentes disponibles

### Base de Datos:
```bash
# Si MongoDB no está disponible:
# - El sistema usa almacenamiento en memoria
# - Funcionalidad completa pero datos no persisten

# Para instalar MongoDB:
# Ubuntu: sudo apt-get install mongodb
# macOS: brew install mongodb-community
```

### Dependencias:
```bash
# Si faltan librerías:
pip install --upgrade -r requirements.txt

# Para desarrollo:
pip install pytest black flake8
```

---

## 🧑‍💻 Desarrollo y Contribuciones

### Estructura del Código:
- `app.py` - Aplicación principal
- `ThreatIntelAPIs` - Configuración de APIs
- `ProfessionalThreatIntelligence` - Recolección profesional
- `AegisStorage` - Almacenamiento y consultas
- `Config` - Configuración centralizada

### Agregar Nueva Fuente:
1. Implementar método de consulta en `ThreatIntelAPIs`
2. Crear función de recolección en `ProfessionalThreatIntelligence`
3. Agregar a `collect_all_professional_intelligence`
4. Configurar rate limiting apropiado

---

## 📞 Contacto y Soporte

**Desarrollado por:** Elisa Elias  
**Organización:** AEGIS Security Consulting  
**LinkedIn:** www.linkedin.com/in/elisa-elias-0a7829268  

### Reportar Problemas:
- Issues en GitHub
- Email con logs relevantes
- Especificar configuración de APIs usadas

---

## 📄 Licencia

Este proyecto está bajo licencia MIT. Ver archivo `LICENSE` para detalles.

---

## 🔄 Actualizaciones Futuras

- [ ] Interfaz web mejorada
- [ ] Exportación a STIX/TAXII
- [ ] Integración con SIEM
- [ ] API propia para consultas
- [ ] Análisis de tendencias temporales
- [ ] Machine learning para detección de anomalías
