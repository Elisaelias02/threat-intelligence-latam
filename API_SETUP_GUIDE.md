# 🔑 Guía de Configuración de APIs - AEGIS Threat Intelligence

## 📋 Resumen de APIs Integradas

El sistema AEGIS integra las siguientes APIs profesionales de threat intelligence:

| API | Tipo | Costo | Rate Limit | Funcionalidad |
|-----|------|-------|------------|---------------|
| **VirusTotal** | Freemium | Gratis/Pago | 4 req/s | Análisis de archivos, URLs, dominios, IPs |
| **IBM X-Force** | Freemium | Gratis/Pago | 5000 req/mes | Reputación de URLs, IPs, análisis de malware |
| **OTX AlienVault** | Gratuito | Gratis | 1000 req/min | Indicadores colaborativos, pulses |
| **MalwareBazaar** | Gratuito | Gratis | Sin límite | Base de datos de muestras de malware |
| **Hybrid Analysis** | Freemium | Gratis/Pago | 200 req/min | Análisis dinámico de malware |
| **NVD** | Gratuito | Gratis | 50 req/30s | Vulnerabilidades CVE |

---

## 🚀 Configuración Rápida (5 minutos)

### 1. Configuración Mínima (Solo VirusTotal)
```bash
# 1. Registrarse en VirusTotal
# 2. Obtener API key
# 3. Agregar al archivo .env:
VIRUSTOTAL_API_KEY=tu_api_key_aqui
```

### 2. Configuración Completa (Todas las APIs)
```bash
# Copiar archivo de configuración
cp config_example.env .env

# Editar y agregar todas las API keys
nano .env
```

---

## 🔧 Configuración Detallada por API

### 1. VirusTotal API v3 (⭐ RECOMENDADO)

**Registro:**
1. Ir a: https://www.virustotal.com/gui/join-us
2. Crear cuenta con email
3. Verificar email
4. Ir a: https://www.virustotal.com/gui/my-apikey
5. Copiar la API key

**Configuración:**
```bash
# Agregar al archivo .env:
VIRUSTOTAL_API_KEY=tu_api_key_de_64_caracteres
```

**Límites Gratuitos:**
- 4 requests por segundo
- 1,000 requests por día
- Análisis de archivos hasta 650MB

**Tipos de IOC soportados:**
- ✅ Hashes (MD5, SHA1, SHA256)
- ✅ URLs
- ✅ Dominios
- ✅ Direcciones IP

---

### 2. IBM X-Force Exchange API

**Registro:**
1. Ir a: https://exchange.xforce.ibmcloud.com/
2. Crear cuenta IBM ID
3. Ir a: Settings > API Access
4. Generar credenciales (Key + Password)

**Configuración:**
```bash
# Agregar al archivo .env:
IBM_XFORCE_API_KEY=tu_api_key
IBM_XFORCE_PASSWORD=tu_password
```

**Límites Gratuitos:**
- 5,000 requests por mes
- Rate limit: 60 requests por minuto

**Tipos de IOC soportados:**
- ✅ URLs (análisis de reputación)
- ✅ Direcciones IP
- ✅ Dominios
- ✅ Hashes de malware

---

### 3. OTX AlienVault API

**Registro:**
1. Ir a: https://otx.alienvault.com/
2. Crear cuenta gratuita
3. Ir a: Settings > API Integration
4. Copiar "OTX Key"

**Configuración:**
```bash
# Agregar al archivo .env:
OTX_API_KEY=tu_otx_key_de_64_caracteres
```

**Límites Gratuitos:**
- 1,000 requests por minuto
- Sin límite diario
- Acceso a todos los pulses públicos

**Tipos de IOC soportados:**
- ✅ Dominios
- ✅ Direcciones IP
- ✅ URLs
- ✅ Hashes de archivos

---

### 4. MalwareBazaar API (Sin API Key)

**Configuración:**
- ✅ **No requiere API key**
- ✅ **No requiere registro**
- ✅ **Funciona automáticamente**

**Límites:**
- Sin límites conocidos
- Rate limiting automático

**Tipos de IOC soportados:**
- ✅ Hashes MD5
- ✅ Hashes SHA1
- ✅ Hashes SHA256

---

### 5. Hybrid Analysis API (Opcional)

**Registro:**
1. Ir a: https://www.hybrid-analysis.com/
2. Crear cuenta gratuita
3. Ir a: Profile > API key
4. Copiar API key

**Configuración:**
```bash
# Agregar al archivo .env:
HYBRID_ANALYSIS_API_KEY=tu_api_key
```

**Límites Gratuitos:**
- 200 requests por minuto
- Análisis limitado por día

---

### 6. NVD API (Opcional para CVEs)

**Registro:**
1. Ir a: https://nvd.nist.gov/developers/request-an-api-key
2. Completar formulario
3. Esperar aprobación (puede tomar días)

**Configuración:**
```bash
# Agregar al archivo .env:
NVD_API_KEY=tu_nvd_api_key
```

**Beneficios con API Key:**
- Sin key: 5 requests cada 30 segundos
- Con key: 50 requests cada 30 segundos

---

## 📝 Archivo .env Completo

```bash
# AEGIS Threat Intelligence Configuration

# VirusTotal (Recomendado - Registro rápido)
VIRUSTOTAL_API_KEY=your_64_char_key_here

# IBM X-Force (Opcional - Requiere cuenta IBM)
IBM_XFORCE_API_KEY=your_xforce_key
IBM_XFORCE_PASSWORD=your_xforce_password

# OTX AlienVault (Recomendado - Gratis)
OTX_API_KEY=your_64_char_otx_key

# Hybrid Analysis (Opcional)
HYBRID_ANALYSIS_API_KEY=your_hybrid_key

# NVD (Opcional - Solo para mejores límites de CVE)
NVD_API_KEY=your_nvd_key

# MalwareBazaar - No requiere configuración

# Database
MONGO_URI=mongodb://localhost:27017/
DATABASE_NAME=aegis_threat_intel_latam
```

---

## 🧪 Verificación de Configuración

### Verificar APIs desde el Dashboard:
1. Ejecutar: `python3 app.py`
2. Ir a: http://localhost:5000
3. Navegar a: "Búsqueda de IOCs"
4. Ver "Fuentes configuradas" en la interfaz

### Verificar desde línea de comandos:
```bash
# Probar VirusTotal
curl -H "x-apikey: TU_API_KEY" \
  "https://www.virustotal.com/api/v3/domains/google.com"

# Probar IBM X-Force
curl -u "TU_API_KEY:TU_PASSWORD" \
  "https://api.xforce.ibmcloud.com/ipr/8.8.8.8"

# Probar OTX
curl -H "X-OTX-API-KEY: TU_OTX_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/domain/google.com/general"
```

---

## 🎯 Estrategias de Configuración

### Configuración Básica (Solo Búsqueda)
```bash
# Mínimo para funcionalidad completa
VIRUSTOTAL_API_KEY=tu_key
# + MalwareBazaar (automático)
```

### Configuración Balanceada (Recomendada)
```bash
# Cobertura completa con buena calidad
VIRUSTOTAL_API_KEY=tu_key
OTX_API_KEY=tu_key
# + MalwareBazaar (automático)
```

### Configuración Empresarial (Completa)
```bash
# Todas las fuentes para máxima cobertura
VIRUSTOTAL_API_KEY=tu_key
IBM_XFORCE_API_KEY=tu_key
IBM_XFORCE_PASSWORD=tu_password
OTX_API_KEY=tu_key
HYBRID_ANALYSIS_API_KEY=tu_key
NVD_API_KEY=tu_key
# + MalwareBazaar (automático)
```

---

## 🚨 Troubleshooting

### Error: "API key not valid"
```bash
# Verificar que la key esté correcta
echo $VIRUSTOTAL_API_KEY

# Probar la key manualmente
curl -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/domains/google.com"
```

### Error: "Rate limit exceeded"
- **Causa**: Demasiadas requests por segundo/minuto
- **Solución**: El sistema maneja automáticamente, esperar
- **Prevención**: Configurar múltiples APIs para balancear

### Error: "No sources configured"
```bash
# Verificar archivo .env
cat .env | grep API_KEY

# Verificar que las variables estén cargadas
python3 -c "import os; print(os.environ.get('VIRUSTOTAL_API_KEY', 'NOT_SET'))"
```

### Error: "Connection timeout"
```bash
# Verificar conectividad
curl -I https://www.virustotal.com/api/v3/
curl -I https://api.xforce.ibmcloud.com/
curl -I https://otx.alienvault.com/api/v1/
```

---

## 💡 Consejos y Mejores Prácticas

### Optimización de Rate Limits:
1. **Configurar múltiples APIs** para balancear carga
2. **Usar caché local** para evitar requests repetidos
3. **Priorizar APIs** según calidad de datos

### Gestión de API Keys:
1. **Nunca** commitear keys al repositorio
2. **Usar archivos .env** para desarrollo
3. **Variables de entorno** para producción
4. **Rotar keys** periódicamente

### Monitoreo de Uso:
1. **Verificar límites** en dashboards de APIs
2. **Monitorear logs** para errores de rate limit
3. **Configurar alertas** para límites próximos

---

## 📊 Comparación de Calidad por Fuente

| Criterio | VirusTotal | IBM X-Force | OTX | MalwareBazaar |
|----------|------------|-------------|-----|---------------|
| **Cobertura** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Precisión** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Velocidad** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Facilidad Setup** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

### Recomendación de Prioridad:
1. 🥇 **VirusTotal** - Esencial para cualquier implementación
2. 🥈 **OTX AlienVault** - Excelente cobertura, fácil setup
3. 🥉 **MalwareBazaar** - Automático, específico para malware
4. 🏅 **IBM X-Force** - Calidad empresarial, setup más complejo

---

## 📞 Soporte

### Documentación Oficial:
- [VirusTotal API](https://developers.virustotal.com/reference)
- [IBM X-Force API](https://exchange.xforce.ibmcloud.com/api/doc/)
- [OTX API](https://otx.alienvault.com/api)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)

### Contacto del Proyecto:
- **GitHub Issues**: Para reportar problemas
- **Email**: Para soporte directo
- **LinkedIn**: [Elisa Elias](https://www.linkedin.com/in/elisa-elias-0a7829268)