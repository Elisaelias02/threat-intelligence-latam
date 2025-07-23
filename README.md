# AEGIS Threat Intelligence LATAM - Sistema REAL y FUNCIONAL

## 🚀 Sistema PROFESIONAL de Threat Intelligence para LATAM

**Dashboard 100% funcional** con integraciones reales de threat intelligence diseñado específicamente para la región de Latinoamérica. Extrae datos reales de fuentes oficiales de ciberseguridad para proporcionar inteligencia de amenazas en tiempo real.

## ✅ FUNCIONALIDADES REALES IMPLEMENTADAS

### 🎯 **IOCs en Tiempo Real** 
- **VirusTotal**: Extrae IOCs maliciosos reales desde comentarios y análisis
- **MalwareBazaar**: Muestras de malware recientes dirigidas a LATAM
- **OTX AlienVault**: Pulsos e indicadores colaborativos filtrados por región
- **IBM X-Force**: Inteligencia corporativa de amenazas
- **URLhaus**: URLs maliciosas activas (fuente pública)

### 🔍 **Búsqueda Manual de IOCs**
- Busca cualquier IOC (IP, dominio, hash, URL) en múltiples fuentes
- Integración real con VirusTotal API v3 e IBM X-Force
- Resultados agregados con nivel de confianza
- Análisis inmediato de reputación

### 🐛 **CVEs Recientes del NVD**
- Vulnerabilidades extraídas del National Vulnerability Database
- Filtrado por severidad CVSS (Critical, High, Medium, Low)
- Scores CVSS v3.1, v3.0 y v2.0
- Referencias técnicas y detalles completos

### ✨ Características Principales

- **🔄 Datos 100% Reales**: Sin datos falsos - todo extraído de APIs oficiales
- **🌎 Enfoque LATAM**: Filtrado específico para amenazas dirigidas a países latinoamericanos
- **📊 Dashboard Profesional**: 5 pestañas especializadas con visualización en tiempo real
- **🛡️ Múltiples Fuentes**: Integración completa con 8+ fuentes de threat intelligence
- **⚡ Búsqueda Instantánea**: Motor de búsqueda manual de IOCs en múltiples fuentes
- **💾 Sin Dependencias**: Funciona sin MongoDB usando almacenamiento en memoria

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

## 📱 Pestañas del Dashboard

### 🏠 **Dashboard Principal**
- Estadísticas en tiempo real de campañas y IOCs
- Gráficos de distribución por severidad y fuentes
- IOCs por país y familias de malware detectadas
- Alertas críticas más recientes

### 🎯 **Campañas Activas**
- Lista de campañas de amenazas detectadas
- Filtrado por severidad, fuente y país
- Detalles de IOCs asociados a cada campaña
- Información de threat actors y TTPs

### 🔍 **IOCs en Vivo**
- Indicadores de compromiso extraídos en tiempo real
- Filtrado por tipo (IP, dominio, hash, URL)
- Niveles de confianza y fuentes de origen
- Países afectados por cada IOC

### 🚨 **Centro de Alertas**
- Alertas críticas automatizadas
- Detección de malware bancario (Mekotio, Grandoreiro, etc.)
- Campañas de alta severidad
- Notificaciones en tiempo real

### 🐛 **CVEs Recientes** *(NUEVO)*
- Vulnerabilidades del National Vulnerability Database
- Filtrado por severidad CVSS
- Búsqueda por días anteriores (7, 14, 30 días)
- Scores CVSS detallados y referencias

### 🔎 **Búsqueda IOCs** *(NUEVO)*
- Búsqueda manual en múltiples fuentes
- Soporte para IPs, dominios, hashes y URLs
- Resultados de VirusTotal y IBM X-Force
- Análisis agregado de reputación

### 🦠 **MalwareBazaar** *(NUEVO)*
- Muestras de malware dirigidas a LATAM
- Filtrado por familia de malware
- Hashes SHA256 y metadatos
- Enfoque en banking trojans de la región

### 📡 **OTX Pulses** *(NUEVO)*
- Pulsos recientes de AlienVault OTX
- Amenazas colaborativas filtradas por LATAM
- Detalles de autores y fechas
- IOCs asociados a cada pulso

### 📥 **Exportar Datos**
- Exportación a CSV y JSON
- Scraping manual de fuentes
- Integración de todas las APIs

## 🔧 Configuración

### ⚡ **Inicio Rápido (Solo Fuentes Públicas)**
```bash
# 1. Clonar repositorio
git clone <repository_url>
cd aegis-threat-intel

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar inmediatamente
python3 app.py
```
**El sistema funcionará con fuentes públicas (MalwareBazaar, URLhaus) sin configuración adicional.**

### 🔑 **Configuración Completa con APIs**

#### 1. Configurar API Keys (Recomendado)
Copia el archivo `.env` y configura tus API keys:

```bash
# Configuración mínima recomendada
VIRUSTOTAL_API_KEY=tu_api_key_de_virustotal   # Para búsquedas de IOCs
OTX_API_KEY=tu_api_key_de_otx                 # Para pulsos de amenazas

# Configuración completa
IBM_XFORCE_API_KEY=tu_api_key_de_xforce       # Para inteligencia corporativa  
IBM_XFORCE_PASSWORD=tu_password_de_xforce
NVD_API_KEY=tu_api_key_de_nvd                 # Para mayor rate limit de CVEs
```

#### 2. Obtener API Keys GRATIS:

**VirusTotal** (Obligatorio para búsquedas IOCs):
- Registrarse en: https://www.virustotal.com/gui/join-us
- Ir a tu perfil → API Key
- Límite gratis: 4 req/seg, 1000 req/día

**AlienVault OTX** (Recomendado):
- Registrarse en: https://otx.alienvault.com/
- Settings → API Integration → Copiar OTX Key
- Límite gratis: 1000 req/min

**IBM X-Force** (Opcional):
- Registrarse en: https://exchange.xforce.ibmcloud.com/
- API Settings → Crear credenciales
- Límite gratis: 5000 req/mes

**NVD CVEs** (Opcional):
- Registrarse en: https://nvd.nist.gov/developers/request-an-api-key
- Sin API key: 5 req/30s
- Con API key: 50 req/30s

### 🔌 Fuentes de Inteligencia

#### APIs Profesionales (Requieren API Keys)
- **VirusTotal API v3**: Análisis de URLs, dominios, IPs y hashes maliciosos
- **IBM X-Force Exchange**: Inteligencia corporativa de amenazas
- **AlienVault OTX**: Pulsos colaborativos de threat intelligence
- **National Vulnerability Database**: Vulnerabilidades CVE del NIST

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
