# Threat Intelligence LATAM - Open Source Framework

🔎 **Descripción**  
Este proyecto es un framework open-source enfocado en la recolección, análisis y visualización de indicadores de compromiso (IOCs) relacionados con amenazas específicas de Latinoamérica. El objetivo es proporcionar a analistas y organizaciones un sistema adaptable para monitorizar campañas de phishing, malware y smishing dirigidas a la región.

---

## 📊 Funcionalidades
- Recolección automatizada de IOCs desde fuentes OSINT y feeds locales.
- Almacenamiento eficiente en **MongoDB** (o ElasticSearch) para consultas rápidas.
- Dashboard web con métricas en tiempo real sobre campañas activas.
- Correlación básica de patrones y detección de campañas recurrentes.

---

## 🌎 Enfoque LATAM
El framework prioriza amenazas relevantes para la región, como:
- **Phishing bancario dirigido a usuarios de LATAM.**
- **Malware financiero como Mekotio, Grandoreiro y Guildma.**
- **Campañas de smishing (SMS phishing) relacionadas con servicios locales.**

---

## 📦 Estructura del Proyecto
```text
threat-intelligence-latam/
├── docs/                     # Documentación y papers relacionados
├── scripts/                   # Scrapers, ETL y scripts de ingestión
├── dashboard/                 # Código fuente del dashboard Flask
├── docker/                     # Configuración Docker Compose
├── README.md                   # Este archivo
└── LICENSE                     # Licencia del proyecto (MIT, Apache, etc.)

⚙️ Requisitos Técnicos
Python 3.10+
MongoDB o ElasticSearch
Docker & Docker Compose

🧑‍💻 Contacto
Proyecto desarrollado por Elisa Elias - www.linkedin.com/in/elisa-elias-0a7829268
Contribuciones y feedback son bienvenidos.
