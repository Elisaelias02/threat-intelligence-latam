
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
