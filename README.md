# AEGIS Threat Intelligence LATAM - Dashboard Profesional

## 🚀 Sistema de Threat Intelligence en Tiempo Real para LATAM

Dashboard profesional de threat intelligence diseñado específicamente para la región de Latinoamérica, integrando múltiples fuentes de inteligencia de amenazas para proporcionar una visión completa del panorama de ciberseguridad.


### ✨ Características Principales

- **🔄 Datos en Tiempo Real**: Integración con APIs oficiales de threat intelligence
- **🌎 Enfoque LATAM**: Filtrado específico para amenazas dirigidas a países latinoamericanos
- **📊 Dashboard Interactivo**: Visualización moderna con gráficos y estadísticas en vivo
- **🛡️ Múltiples Fuentes**: Integración con VirusTotal, MalwareBazaar, OTX, IBM X-Force, NVD
- **⚡ Actualización Automática**: Sistema de recolección automática de IOCs y CVEs
- **💾 Almacenamiento Flexible**: Soporte para MongoDB y almacenamiento en memoria

### 🔌 Fuentes de Inteligencia Integradas

#### APIs Profesionales (Requieren API Keys)
- **VirusTotal**: Análisis de URLs, dominios, IPs y hashes maliciosos
- **IBM X-Force Exchange**: Inteligencia corporativa de amenazas
- **AlienVault OTX**: Pulsos colaborativos de threat intelligence
- **Hybrid Analysis**: Análisis de malware en sandbox
- **NVD**: Vulnerabilidades CVE del NIST

#### Fuentes Abiertas (Sin API Keys)
- **MalwareBazaar**: Muestras de malware de abuse.ch
- **OpenPhish**: URLs de phishing verificadas
- **PhishTank**: Base de datos colaborativa de phishing
- **URLhaus**: URLs maliciosas de abuse.ch
- **ThreatFox**: IOCs verificados de abuse.ch

### 🛠️ Instalación y Configuración

#### Requisitos Previos
```bash
- Python 3.8+
- MongoDB (opcional)
- Conexión a Internet
```

#### Instalación de Dependencias
```bash
pip install flask flask-cors pymongo requests beautifulsoup4 feedparser python-dotenv
```

#### Configuración de API Keys (Opcional)

Crea un archivo `.env` en el directorio raíz con tus API keys:

```env
# VirusTotal (https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=tu_api_key_aqui

# IBM X-Force Exchange (https://exchange.xforce.ibmcloud.com/)
IBM_XFORCE_API_KEY=tu_api_key_aqui
IBM_XFORCE_PASSWORD=tu_password_aqui

# AlienVault OTX (https://otx.alienvault.com/)
OTX_API_KEY=tu_api_key_aqui

# Hybrid Analysis (https://www.hybrid-analysis.com/)
HYBRID_ANALYSIS_API_KEY=tu_api_key_aqui

# NVD (Opcional - para rate limiting mejorado)
NVD_API_KEY=tu_api_key_aqui



### ✨ Características Principales

- **🔄 Datos en Tiempo Real**: Integración con APIs oficiales de threat intelligence
- **🌎 Enfoque LATAM**: Filtrado específico para amenazas dirigidas a países latinoamericanos
- **📊 Dashboard Interactivo**: Visualización moderna con gráficos y estadísticas en vivo
- **🛡️ Múltiples Fuentes**: Integración con VirusTotal, MalwareBazaar, OTX, IBM X-Force, NVD
- **⚡ Actualización Automática**: Sistema de recolección automática de IOCs y CVEs
- **💾 Almacenamiento Flexible**: Soporte para MongoDB y almacenamiento en memoria


### 🔌 Fuentes de Inteligencia Integradas

### 🔎 Búsqueda de IOCs en Tiempo Real
- **Panel dedicado**: Interfaz intuitiva para búsqueda de indicadores
- **Detección automática**: Reconoce automáticamente el tipo de IOC (hash, IP, URL, dominio)
- **Múltiples fuentes**: Consulta simultánea a todas las APIs configuradas
- **Análisis consensuado**: Combina resultados para mayor precisión
- **Información completa**: Reputación, país, familia de malware, detalles técnicos
- **Validación de formato**: Verifica automáticamente la validez del IOC ingresado

---


#### APIs Profesionales (Requieren API Keys)
- **VirusTotal**: Análisis de URLs, dominios, IPs y hashes maliciosos
- **IBM X-Force Exchange**: Inteligencia corporativa de amenazas
- **AlienVault OTX**: Pulsos colaborativos de threat intelligence
- **Hybrid Analysis**: Análisis de malware en sandbox
- **NVD**: Vulnerabilidades CVE del NIST

#### Fuentes Abiertas (Sin API Keys)
- **MalwareBazaar**: Muestras de malware de abuse.ch
- **OpenPhish**: URLs de phishing verificadas
- **PhishTank**: Base de datos colaborativa de phishing
- **URLhaus**: URLs maliciosas de abuse.ch
- **ThreatFox**: IOCs verificados de abuse.ch

### 🛠️ Instalación y Configuración

#### Requisitos Previos
```bash
- Python 3.8+
- MongoDB (opcional)
- Conexión a Internet
```

#### Instalación de Dependencias
```bash
pip install flask flask-cors pymongo requests beautifulsoup4 feedparser python-dotenv
```

#### Configuración de API Keys (Opcional)

Crea un archivo `.env` en el directorio raíz con tus API keys:

```env
# VirusTotal (https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY=tu_api_key_aqui

# IBM X-Force Exchange (https://exchange.xforce.ibmcloud.com/)
IBM_XFORCE_API_KEY=tu_api_key_aqui
IBM_XFORCE_PASSWORD=tu_password_aqui

# AlienVault OTX (https://otx.alienvault.com/)
OTX_API_KEY=tu_api_key_aqui

# Hybrid Analysis (https://www.hybrid-analysis.com/)
HYBRID_ANALYSIS_API_KEY=tu_api_key_aqui

# NVD (Opcional - para rate limiting mejorado)
NVD_API_KEY=tu_api_key_aqui


# MongoDB (Opcional)
MONGO_URI=mongodb://localhost:27017/
DATABASE_NAME=aegis_threat_intel_latam
```

#### ⚠️ Modo Demo
**El sistema funciona perfectamente SIN API keys**, utilizando datos demo realistas basados en patrones reales de amenazas en LATAM. Los datos incluyen:
- Campañas de banking trojans (Grandoreiro, Mekotio, Casbaneiro)
- IOCs de phishing dirigidos a bancos latinoamericanos
- Amenazas gubernamentales e infraestructura crítica
- CVEs reales desde NVD (esta funciona sin API key)

### 🚀 Ejecución

```bash
python app.py
```

El dashboard estará disponible en: `http://localhost:5000`

### 📱 Funcionalidades del Dashboard

#### 1. **Dashboard Principal**
- Vista general de estadísticas en tiempo real
- Gráficos interactivos de distribución de amenazas
- Alertas críticas recientes
- Métricas por país, severidad y fuente

#### 2. **Campañas Activas**
- Lista de campañas de amenaza detectadas
- Filtros por severidad, país y fuente
- Detalles de IOCs por campaña
- Información de threat actors y TTPs

#### 3. **IOCs en Vivo**
- Indicadores de compromiso en tiempo real
- Filtros por tipo (URL, dominio, IP, hash)
- Niveles de confianza y países afectados
- Búsqueda y exportación

#### 4. **Fuentes Específicas**
- **VirusTotal**: IOCs maliciosos con opción de búsqueda manual
- **MalwareBazaar**: Muestras de malware dirigidas a LATAM
- **AlienVault OTX**: Pulsos de amenaza de la comunidad
- **IBM X-Force**: Inteligencia corporativa profesional

#### 5. **CVEs y Vulnerabilidades**
- Vulnerabilidades recientes desde NVD
- Filtros por severidad y CVSS score
- Actualización automática
- Enlaces directos a detalles técnicos

#### 6. **Centro de Alertas**
- Alertas inteligentes para amenazas críticas
- Detección automática de malware bancario
- Campañas multi-país
- Clusters de alta confianza

#### 7. **Exportación de Datos**
- Exportación en formato CSV y JSON
- Scraping manual bajo demanda
- Estado de recolección en tiempo real

### 🔧 API Endpoints

#### Datos Generales
- `GET /api/stats` - Estadísticas del sistema
- `GET /api/campaigns` - Lista de campañas con filtros
- `GET /api/alerts` - Alertas críticas

#### CVEs
- `GET /api/cves` - Lista de CVEs con filtros
- `GET /api/cves/stats` - Estadísticas de vulnerabilidades
- `POST /api/cves/update` - Actualizar CVEs desde NVD

#### Fuentes Específicas
- `GET /api/source/{source_name}` - Datos de fuente específica
- `POST /api/update/source/{source_name}` - Actualizar fuente específica
- `POST /api/search/virustotal` - Búsqueda manual en VirusTotal

#### Operaciones
- `POST /api/scrape` - Ejecutar scraping completo
- `GET /api/export/{format}` - Exportar datos (CSV/JSON)

### 🎯 Casos de Uso

#### Para Analistas de Seguridad
- Monitoreo de amenazas específicas a su país/región
- Correlación de IOCs entre múltiples fuentes
- Seguimiento de campañas de threat actors conocidos
- Análisis de tendencias de vulnerabilidades

#### Para SOCs (Security Operations Centers)
- Dashboard centralizado para amenazas LATAM
- Alertas automáticas para amenazas críticas
- Integración con SIEM a través de API
- Exportación de IOCs para herramientas de seguridad

#### Para Investigadores
- Acceso a datos de múltiples fuentes threat intelligence
- Capacidad de búsqueda manual en VirusTotal
- Análisis de familias de malware específicas de LATAM
- Datos exportables para análisis adicional

### 🛡️ Seguridad y Privacidad

- Las API keys se almacenan como variables de entorno
- Tráfico HTTPS recomendado para producción
- Rate limiting respetado para todas las APIs
- Logs detallados para auditoría
- Sin almacenamiento de datos sensibles de usuarios

### 📈 Monitoreo y Mantenimiento

#### Logs del Sistema
Los logs se almacenan en `aegis_threat_intel.log` e incluyen:
- Actividad de scraping y recolección
- Errores de conexión a APIs
- Estadísticas de almacenamiento
- Alertas generadas

#### Actualización Automática
- CVEs: Actualizados automáticamente cada 24 horas
- IOCs: Recolección cada 6 horas (configurable)
- APIs: Respeta rate limits automáticamente
- Dashboard: Actualización en vivo cada 30 segundos

### 🔄 Desarrollo y Personalización

#### Estructura del Código
```
app.py
├── ThreatIntelAPIs        # Configuración de APIs
├── ProfessionalThreatIntelligence  # Recolección de datos
├── AegisStorage          # Almacenamiento y búsqueda
├── AegisAlertSystem      # Sistema de alertas
└── Flask App             # Dashboard web y APIs
```

#### Agregar Nuevas Fuentes
1. Implementa método de recolección en `ProfessionalThreatIntelligence`
2. Agrega configuración de API en `ThreatIntelAPIs`
3. Actualiza el sistema de alertas si es necesario
4. Añade endpoint API correspondiente

### 📞 Soporte y Documentación

- **Desarrollado por**: Elisa Elias - AEGIS Security Consulting
- **Versión**: 3.0.0 - Producción
- **Licencia**: Profesional
- **Soporte**: Contactar para soporte técnico y personalizaciones

### 🎉 Estado de Funcionalidades

| Funcionalidad | Estado | Notas |
|---------------|--------|-------|
| ✅ CVEs desde NVD | **Funcional** | Datos reales sin API key |
| ✅ Dashboard Interactivo | **Funcional** | UI completa y responsiva |
| ✅ VirusTotal Integration | **Funcional** | Demo + API real |
| ✅ MalwareBazaar | **Funcional** | Demo + API real |
| ✅ AlienVault OTX | **Funcional** | Demo + API real |
| ✅ IBM X-Force | **Funcional** | Demo + API real |
| ✅ Sistema de Alertas | **Funcional** | Detección inteligente |
| ✅ Exportación Datos | **Funcional** | CSV/JSON |
| ✅ Búsqueda Manual | **Funcional** | VirusTotal search |
| ✅ Filtros Avanzados | **Funcional** | Por país, severidad, tipo |

---

**🔥 El dashboard está listo para producción con datos reales y funcionalidad completa de threat intelligence para LATAM.**
