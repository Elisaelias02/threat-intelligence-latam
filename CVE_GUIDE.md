# 🐛 Guía de Funcionalidades CVE - AEGIS Threat Intelligence

## Descripción General

El sistema AEGIS ahora incluye una funcionalidad completa para la recolección, análisis y monitoreo de vulnerabilidades CVE desde la base de datos oficial del NIST (NVD - National Vulnerability Database).

## 🚀 Características Principales

### 1. **Recolección Automática desde NVD**
- ✅ Consulta directa a la API oficial de NVD (https://nvd.nist.gov/developers/vulnerabilities)
- ✅ Recolección de CVEs recientes con todos los metadatos
- ✅ Rate limiting inteligente (5 req/30s sin API key, 50 req/30s con API key)
- ✅ Manejo robusto de errores y reintentos

### 2. **Panel de CVEs en el Dashboard**
- 📊 **Estadísticas en tiempo real**: Total de CVEs, críticos, alta severidad, recientes
- 🔍 **Filtros avanzados**: Por severidad (CRITICAL, HIGH, MEDIUM, LOW) y límite de resultados
- 📅 **Ordenación**: CVEs ordenados por fecha de publicación (más recientes primero)
- 🎯 **Enlaces directos**: Acceso directo a la página oficial de cada CVE en NVD

### 3. **Información Completa por CVE**
- 🆔 **CVE ID**: Identificador único de la vulnerabilidad
- 📝 **Descripción**: Descripción completa de la vulnerabilidad
- 📅 **Fecha de publicación**: Cuándo fue publicado el CVE
- 🎯 **CVSS Score**: Puntuación de severidad con código de colores
- ⚠️ **Nivel de severidad**: CRITICAL, HIGH, MEDIUM, LOW
- 🔗 **Enlaces**: Acceso directo a NVD y referencias adicionales

## 📱 Uso del Panel de CVEs

### Acceso
1. Abrir el dashboard: `http://localhost:5000`
2. Hacer clic en **"CVEs y Vulnerabilidades"** en el menú lateral
3. El icono 🐛 indica la sección de CVEs

### Estadísticas
El panel muestra métricas clave:
- **Total CVEs**: Número total de CVEs en la base de datos
- **Críticos**: CVEs con severidad CRITICAL
- **Alta Severidad**: CVEs con severidad HIGH
- **Últimos 7 días**: CVEs publicados recientemente

### Filtros Disponibles
- **Severidad**: CRITICAL, HIGH, MEDIUM, LOW, Todas
- **Límite de resultados**: 50, 100, 200 CVEs por página

### Acciones Rápidas
- **Actualizar CVEs desde NVD**: Recolecta nuevos CVEs manualmente
- **Exportar CVEs**: Descarga los datos en formato JSON
- **Actualizar Lista**: Refresca la tabla con los filtros aplicados

## 🔧 APIs Disponibles

### 1. Obtener CVEs
```bash
GET /api/cves?severity=CRITICAL&limit=50
```

**Parámetros:**
- `severity` (opcional): CRITICAL, HIGH, MEDIUM, LOW
- `limit` (opcional): Número máximo de CVEs (default: 50)

### 2. Estadísticas de CVEs
```bash
GET /api/cves/stats
```

**Respuesta:**
```json
{
  "total_cves": 1250,
  "critical_count": 45,
  "high_severity_count": 180,
  "recent_count": 25,
  "by_severity": {
    "CRITICAL": 45,
    "HIGH": 135,
    "MEDIUM": 320,
    "LOW": 750
  }
}
```

### 3. Actualizar CVEs
```bash
POST /api/cves/update
Content-Type: application/json

{
  "days_back": 30,
  "limit": 100
}
```

## ⚙️ Configuración

### Variables de Entorno (.env)
```bash
# API Key opcional para mejores límites de rate
NVD_API_KEY=tu_api_key_nvd

# Configuración de CVEs
CVE_UPDATE_INTERVAL_HOURS=6
CVE_DAYS_BACK=30
CVE_MAX_LIMIT=200
```

### Obtener API Key de NVD (Opcional)
1. Visitar: https://nvd.nist.gov/developers/request-an-api-key
2. Completar el formulario de solicitud
3. Agregar la key al archivo `.env`

**Beneficios del API Key:**
- Sin API key: 5 requests cada 30 segundos
- Con API key: 50 requests cada 30 segundos

## 🔄 Automatización

### Actualización Automática
- Los CVEs se actualizan automáticamente durante el scraping general
- Frecuencia configurable (default: cada 6 horas)
- Búsqueda de CVEs de los últimos 30 días (configurable)

### Integración con Scraping
```python
# Los CVEs se actualizan automáticamente cuando se ejecuta:
POST /api/scrape
```

## 📊 Formato de Datos

### Estructura de un CVE
```json
{
  "id": "CVE-2024-12345",
  "description": "A critical vulnerability in...",
  "published_date": "2024-01-15T10:00:00Z",
  "last_modified": "2024-01-16T14:30:00Z",
  "cvss_score": 9.8,
  "cvss_severity": "CRITICAL",
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "source": "nvd",
  "references": [
    "https://example.com/advisory",
    "https://github.com/project/security"
  ],
  "cwe_ids": ["CWE-79", "CWE-89"],
  "affected_products": ["vendor:product"]
}
```

## 🎨 Interfaz Visual

### Códigos de Color por Severidad
- 🔴 **CRITICAL**: Rojo (#dc2626)
- 🟠 **HIGH**: Naranja (#ea580c)
- 🟡 **MEDIUM**: Amarillo (#ca8a04)
- 🟢 **LOW**: Verde (#16a34a)
- ⚫ **UNKNOWN**: Gris (#6b7280)

### Tabla de CVEs
- **Responsiva**: Se adapta a diferentes tamaños de pantalla
- **Ordenación**: Por fecha de publicación (más recientes primero)
- **Hover effects**: Resaltado al pasar el mouse
- **Enlaces externos**: Abren en nueva pestaña

## 🔗 Enlaces Útiles

- **NVD Official**: https://nvd.nist.gov/
- **API Documentation**: https://nvd.nist.gov/developers/vulnerabilities
- **CVSS Calculator**: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- **CWE Database**: https://cwe.mitre.org/

## 📝 Notas Importantes

1. **Rate Limiting**: El sistema respeta automáticamente los límites de la API de NVD
2. **Almacenamiento**: Los CVEs se almacenan en MongoDB o memoria según la configuración
3. **Actualizaciones**: Los CVEs existentes se actualizan si hay cambios en NVD
4. **Filtrado**: Solo se muestran CVEs relevantes y verificados
5. **Performance**: La tabla está optimizada para cargar rápidamente

## 🚨 Troubleshooting

### Problemas Comunes

**Error: "No se encontraron CVEs"**
- Verificar conexión a internet
- Comprobar si el servicio NVD está disponible
- Revisar logs del sistema

**Actualización lenta de CVEs**
- Considerar obtener un API key de NVD
- Reducir el parámetro `days_back`
- Verificar rate limiting

**Errores de API**
- Verificar que la API key sea válida
- Comprobar formato de las requests
- Revisar logs para detalles específicos

## 🎯 Próximas Funcionalidades

- [ ] Alertas automáticas para CVEs críticos
- [ ] Correlación de CVEs con IOCs existentes
- [ ] Análisis de tendencias de vulnerabilidades
- [ ] Integración con feeds de vulnerabilidades LATAM
- [ ] Exportación específica de CVEs en múltiples formatos