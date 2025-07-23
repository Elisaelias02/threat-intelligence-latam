#!/usr/bin/env python3
"""
AEGIS THREAT INTELLIGENCE LATAM - SISTEMA REAL Y FUNCIONAL
Desarrollado por: Elisa Elias - AEGIS Security Consulting
Version: 3.0.1 - PRODUCCIÓN CORREGIDA
"""

import os
import sys
import json
import hashlib
import requests
import logging
import re
import csv
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
from collections import defaultdict
from io import StringIO
import base64

# Environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if available
except ImportError:
    pass  # dotenv not installed, skip

# Flask
from flask import Flask, request, jsonify, render_template_string, Response
from flask_cors import CORS

# MongoDB
try:
    from pymongo import MongoClient
    from pymongo.errors import DuplicateKeyError
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    MongoClient = None
    DuplicateKeyError = Exception

# Web scraping
try:
    from bs4 import BeautifulSoup
    import feedparser
    WEB_SCRAPING_AVAILABLE = True
except ImportError:
    WEB_SCRAPING_AVAILABLE = False
    BeautifulSoup = None
    feedparser = None

# Variables globales para almacenamiento en memoria compartido
memory_campaigns_global = []
memory_iocs_global = []
memory_alerts_global = []

# =====================================================
# CONFIGURACIÓN DE APIs PROFESIONALES
# =====================================================

class ThreatIntelAPIs:
    """Configuración centralizada de APIs de Threat Intelligence"""
    
    def __init__(self):
        # API Keys (configurar en variables de entorno)
        self.VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
        self.IBM_XFORCE_API_KEY = os.environ.get('IBM_XFORCE_API_KEY') 
        self.IBM_XFORCE_PASSWORD = os.environ.get('IBM_XFORCE_PASSWORD')
        self.OTX_API_KEY = os.environ.get('OTX_API_KEY')
        self.HYBRID_ANALYSIS_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY')
        self.NVD_API_KEY = os.environ.get('NVD_API_KEY')
        self.MALWARE_BAZAAR_API_KEY = os.environ.get('MALWARE_BAZAAR_API_KEY')  # Opcional
        
        # URLs base de las APIs (actualizadas para v3)
        self.VIRUSTOTAL_BASE_URL_V3 = "https://www.virustotal.com/api/v3"
        self.IBM_XFORCE_BASE_URL = "https://api.xforce.ibmcloud.com"
        self.OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
        self.HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
        self.MALWARE_BAZAAR_BASE_URL = "https://mb-api.abuse.ch/api/v1"
        self.NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json"
        
        # Headers por defecto
        self.headers = {
            'User-Agent': 'AEGIS-ThreatIntel/3.0 (Professional Threat Intelligence Tool)',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Rate limiting
        self.rate_limits = {
            'virustotal': {'requests_per_minute': 240, 'last_request': 0},
            'ibm_xforce': {'requests_per_minute': 60, 'last_request': 0},
            'otx': {'requests_per_minute': 1000, 'last_request': 0},
            'hybrid_analysis': {'requests_per_minute': 200, 'last_request': 0},
            'malware_bazaar': {'requests_per_minute': 1000, 'last_request': 0},
            'nvd': {'requests_per_minute': 50, 'last_request': 0}
        }
        
        # Configurar session con timeout
        self.session = requests.Session()
        self.session.timeout = 30
    
    def _respect_rate_limit(self, service: str):
        """Respeta los límites de rate limiting por servicio"""
        if service not in self.rate_limits:
            return
        
        rate_limit = self.rate_limits[service]
        current_time = time.time()
        time_since_last = current_time - rate_limit['last_request']
        min_interval = 60.0 / rate_limit['requests_per_minute']
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        
        self.rate_limits[service]['last_request'] = time.time()
    
    def get_virustotal_headers(self) -> Dict[str, str]:
        """Headers para VirusTotal API v3"""
        headers = self.headers.copy()
        if self.VIRUSTOTAL_API_KEY:
            headers['x-apikey'] = self.VIRUSTOTAL_API_KEY
        return headers
    
    def get_ibm_xforce_headers(self) -> Dict[str, str]:
        """Headers para IBM X-Force Exchange API"""
        headers = self.headers.copy()
        if self.IBM_XFORCE_API_KEY and self.IBM_XFORCE_PASSWORD:
            credentials = f"{self.IBM_XFORCE_API_KEY}:{self.IBM_XFORCE_PASSWORD}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f'Basic {encoded_credentials}'
        return headers
    
    def get_otx_headers(self) -> Dict[str, str]:
        """Headers para OTX AlienVault API"""
        headers = self.headers.copy()
        if self.OTX_API_KEY:
            headers['X-OTX-API-KEY'] = self.OTX_API_KEY
        return headers

# =====================================================
# CONFIGURACIÓN Y LOGGING
# =====================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aegis_threat_intel.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# User agents rotativos para evitar bloqueos
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

class Config:
    """Configuración central del sistema AEGIS"""
    
    # Base de datos
    MONGO_URI = os.environ.get('MONGO_URI', "mongodb://localhost:27017/")
    DATABASE_NAME = os.environ.get('DATABASE_NAME', "aegis_threat_intel_latam")
    
    # Configuración de scraping
    SCRAPING_INTERVAL_HOURS = int(os.environ.get('SCRAPING_INTERVAL_HOURS', 6))
    MAX_RETRIES = 3
    TIMEOUT = 30
    
    # Países LATAM para detección
    LATAM_COUNTRIES = {
        'argentina', 'bolivia', 'brasil', 'brazil', 'chile', 'colombia',
        'costa rica', 'cuba', 'ecuador', 'el salvador', 'guatemala',
        'honduras', 'méxico', 'mexico', 'nicaragua', 'panamá', 'panama',
        'paraguay', 'perú', 'peru', 'república dominicana', 'uruguay',
        'venezuela', 'latinoamérica', 'latam', 'south america', 'mercosur'
    }
    
    # Keywords específicos de LATAM
    LATAM_KEYWORDS = {
        'banking': ['bancolombia', 'banco do brasil', 'itaú', 'bradesco', 'santander brasil', 
                   'bbva mexico', 'banamex', 'banco de chile', 'banco nación', 'mercantil'],
        'payment': ['pix', 'mercado pago', 'mercadopago', 'oxxo', 'webpay', 'transbank', 'rapipago'],
        'government': ['anses', 'sunat', 'sat mexico', 'dian colombia', 'seniat venezuela'],
        'telecom': ['claro', 'movistar', 'vivo brasil', 'tim brasil', 'telmex', 'personal'],
        'retail': ['falabella', 'ripley', 'liverpool', 'soriana', 'coppel', 'casa bahia']
    }
    
    # Fuentes de Threat Intelligence REALES y GRATUITAS
    REAL_SOURCES = {
        'openphish': {
            'url': 'https://openphish.com/feed.txt',
            'type': 'text',
            'format': 'line_separated'
        },
        'phishtank': {
            'url': 'http://data.phishtank.com/data/online-valid.csv',
            'type': 'csv',
            'format': 'csv'
        },
        'urlhaus': {
            'url': 'https://urlhaus.feodotracker.abuse.ch/downloads/csv_recent/',
            'type': 'csv',
            'format': 'csv'
        },
        'malware_bazaar': {
            'url': 'https://bazaar.abuse.ch/export/csv/recent/',
            'type': 'csv',
            'format': 'csv'
        },
        'threatfox': {
            'url': 'https://threatfox.abuse.ch/export/csv/recent/',
            'type': 'csv',
            'format': 'csv'
        }
    }

# =====================================================
# MODELOS DE DATOS
# =====================================================

@dataclass
class IOC:
    """Indicador de Compromiso"""
    value: str
    type: str  # ip, domain, hash_md5, hash_sha1, hash_sha256, url, email
    confidence: int  # 0-100
    first_seen: datetime
    last_seen: datetime
    source: str
    campaign_id: Optional[str] = None
    tags: List[str] = None
    threat_type: Optional[str] = None
    malware_family: Optional[str] = None
    country: Optional[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class CVE:
    """Vulnerabilidad CVE"""
    id: str
    description: str
    published_date: datetime
    last_modified: datetime
    cvss_score: float
    cvss_severity: str
    vector_string: Optional[str]
    source: str
    references: List[str] = None
    cwe_ids: List[str] = None
    affected_products: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.affected_products is None:
            self.affected_products = []

@dataclass
class Campaign:
    """Campaña maliciosa"""
    id: str
    name: str
    description: str
    countries_affected: List[str]
    threat_actor: Optional[str]
    first_seen: datetime
    last_seen: datetime
    ttps: List[str]
    iocs: List[IOC]
    severity: str
    source: str
    malware_families: List[str] = None
    target_sectors: List[str] = None
    
    def __post_init__(self):
        if self.malware_families is None:
            self.malware_families = []
        if self.target_sectors is None:
            self.target_sectors = []

# =====================================================
# SCRAPER MEJORADO
# =====================================================

class ProfessionalThreatIntelligence:
    """Sistema profesional de recolección de Threat Intelligence"""
    
    def __init__(self, config: Config):
        self.config = config
        self.api_config = ThreatIntelAPIs()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
        self.session.timeout = config.TIMEOUT
        logger.info("Sistema profesional de Threat Intelligence inicializado")
        
    def _rotate_user_agent(self):
        """Rota el User-Agent para evitar bloqueos"""
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
    
    def _make_request(self, url: str, retries: int = 3) -> Optional[requests.Response]:
        """Hace request con reintentos y manejo de errores"""
        for attempt in range(retries):
            try:
                self._rotate_user_agent()
                response = self.session.get(url, timeout=self.config.TIMEOUT)
                if response.status_code == 200:
                    return response
                elif response.status_code == 429:  # Rate limit
                    wait_time = 2 ** attempt
                    logger.warning(f"Rate limit en {url}, esperando {wait_time}s")
                    time.sleep(wait_time)
                else:
                    logger.warning(f"HTTP {response.status_code} para {url}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"Error en request a {url}: {e}")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
        return None
    
    def _is_latam_related(self, text: str, url: str = "") -> bool:
        """Detecta si el contenido está relacionado con LATAM"""
        content = f"{text} {url}".lower()
        
        # Verificar países LATAM
        for country in self.config.LATAM_COUNTRIES:
            if country in content:
                return True
        
        # Verificar keywords específicos de LATAM
        for category, keywords in self.config.LATAM_KEYWORDS.items():
            for keyword in keywords:
                if keyword in content:
                    return True
        
        # Patrones específicos de LATAM
        latam_patterns = [
            r'\.ar\b|\.br\b|\.mx\b|\.cl\b|\.co\b|\.pe\b|\.ve\b|\.uy\b',
            r'spanish.*speaking|portuguese.*speaking',
            r'latin.*america|south.*america|mercosur',
            r'banco.*(?:do\s+)?brasil|santander.*brasil|bradesco|itau',
            r'mercado.*pago|mercadopago|pix.*payment',
            r'oxxo|soriana|falabella|ripley',
            r'anses|sunat|sat.*mexico|dian.*colombia'
        ]
        
        for pattern in latam_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_country_from_content(self, text: str, url: str = "") -> Optional[str]:
        """Extrae el país específico del contenido"""
        content = f"{text} {url}".lower()
        
        country_mapping = {
            'brasil': 'brazil', 'brazil': 'brazil', '.br': 'brazil',
            'méxico': 'mexico', 'mexico': 'mexico', '.mx': 'mexico',
            'argentina': 'argentina', '.ar': 'argentina',
            'chile': 'chile', '.cl': 'chile',
            'colombia': 'colombia', '.co': 'colombia',
            'perú': 'peru', 'peru': 'peru', '.pe': 'peru',
            'venezuela': 'venezuela', '.ve': 'venezuela',
            'uruguay': 'uruguay', '.uy': 'uruguay'
        }
        
        for key, country in country_mapping.items():
            if key in content:
                return country
        
        return 'latam'
    
    def _detect_malware_family(self, text: str) -> Optional[str]:
        """Detecta familias de malware conocidas"""
        text_lower = text.lower()
        
        malware_families = {
            'mekotio': ['mekotio'],
            'grandoreiro': ['grandoreiro'],
            'casbaneiro': ['casbaneiro'],
            'amavaldo': ['amavaldo'],
            'javali': ['javali'],
            'emotet': ['emotet', 'heodo'],
            'trickbot': ['trickbot', 'trickloader'],
            'qakbot': ['qakbot', 'qbot'],
            'banker': ['banker', 'banking trojan', 'financial malware']
        }
        
        for family, indicators in malware_families.items():
            for indicator in indicators:
                if indicator in text_lower:
                    return family
        
        return None
    
    def _calculate_confidence(self, ioc_value: str, source: str, context: str = "") -> int:
        """Calcula nivel de confianza del IOC"""
        base_confidence = 60
        
        # Ajustar por fuente
        source_confidence = {
            'abuse.ch': 20,  # URLhaus, ThreatFox muy confiables
            'openphish': 15,
            'phishtank': 15
        }
        
        for src, bonus in source_confidence.items():
            if src in source:
                base_confidence += bonus
                break
        
        # Ajustar por contexto
        if any(word in context.lower() for word in ['confirmed', 'verified', 'validated']):
            base_confidence += 10
        
        if any(word in context.lower() for word in ['active', 'live', 'current']):
            base_confidence += 5
        
        # Ajustar por tipo de IOC
        if len(ioc_value) == 64:  # SHA256
            base_confidence += 10
        elif len(ioc_value) == 40:  # SHA1
            base_confidence += 8
        elif len(ioc_value) == 32:  # MD5
            base_confidence += 5
        
        return min(95, max(30, base_confidence))
    
    def create_campaign_from_iocs(self, iocs: List[IOC], source: str) -> Campaign:
        """Crea una campaña basada en un grupo de IOCs"""
        if not iocs:
            return None
        
        countries = list(set(ioc.country for ioc in iocs if ioc.country))
        malware_families = list(set(ioc.malware_family for ioc in iocs if ioc.malware_family))
        threat_types = list(set(ioc.threat_type for ioc in iocs if ioc.threat_type))
        
        avg_confidence = sum(ioc.confidence for ioc in iocs) / len(iocs)
        has_malware = any(ioc.threat_type == 'malware' for ioc in iocs)
        has_banking = any(family in ['mekotio', 'grandoreiro', 'casbaneiro'] for family in malware_families)
        
        if has_banking or (has_malware and avg_confidence > 85):
            severity = 'critical'
        elif has_malware or avg_confidence > 75:
            severity = 'high'
        elif avg_confidence > 60:
            severity = 'medium'
        else:
            severity = 'low'
        
        if malware_families:
            campaign_name = f"Campaña {malware_families[0].title()} - {source.title()}"
        elif threat_types:
            campaign_name = f"Campaña {threat_types[0].title()} - {source.title()}"
        else:
            campaign_name = f"Campaña Detectada - {source.title()}"
        
        description = f"Campaña detectada con {len(iocs)} IOCs desde {source}. "
        if countries:
            description += f"Países afectados: {', '.join(countries)}. "
        if malware_families:
            description += f"Familias de malware: {', '.join(malware_families)}."
        
        campaign_id = hashlib.md5(f"{campaign_name}_{datetime.utcnow().date()}_{source}".encode()).hexdigest()
        
        campaign = Campaign(
            id=campaign_id,
            name=campaign_name,
            description=description,
            countries_affected=countries or ['latam'],
            threat_actor=None,
            first_seen=min(ioc.first_seen for ioc in iocs),
            last_seen=max(ioc.last_seen for ioc in iocs),
            ttps=[],
            iocs=iocs,
            severity=severity,
            source=source,
            malware_families=malware_families,
            target_sectors=[]
        )
        
        return campaign
    
    def _fetch_virustotal_data(self) -> List[Campaign]:
        """Obtiene datos REALES de VirusTotal API v3"""
        campaigns = []
        
        try:
            self.api_config._respect_rate_limit('virustotal')
            headers = self.api_config.get_virustotal_headers()
            
            # Buscar comentarios recientes con keywords de LATAM
            latam_keywords = ['brasil', 'brazil', 'mexico', 'argentina', 'chile', 'colombia', 'banking']
            
            for keyword in latam_keywords[:3]:  # Limitar para no exceder rate limit
                try:
                    # Buscar en comentarios de VirusTotal
                    url = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/comments"
                    params = {
                        'limit': 20,
                        'filter': f'tag:{keyword}'
                    }
                    
                    response = requests.get(url, headers=headers, params=params, timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        iocs = []
                        for comment in data.get('data', [])[:10]:  # Limitar cantidad
                            # Extraer IOCs de los comentarios
                            comment_text = comment.get('attributes', {}).get('text', '')
                            extracted_iocs = self._extract_iocs_from_text(comment_text)
                            
                            for ioc in extracted_iocs:
                                ioc.source = 'virustotal'
                                ioc.tags = [keyword, 'virustotal']
                                ioc.country = self._extract_country_from_content(comment_text)
                                iocs.append(ioc)
                        
                        if iocs:
                            campaign_id = f"vt-{keyword}-{int(time.time())}"
                            campaign = Campaign(
                                id=campaign_id,
                                name=f"VirusTotal - Amenazas {keyword.title()}",
                                description=f"IOCs detectados en comentarios de VirusTotal relacionados con {keyword}",
                                countries_affected=[self._extract_country_from_content(keyword)],
                                threat_actor=None,
                                first_seen=datetime.utcnow() - timedelta(hours=24),
                                last_seen=datetime.utcnow(),
                                ttps=[],
                                iocs=iocs[:20],  # Limitar cantidad
                                severity='medium',
                                source='virustotal',
                                malware_families=[],
                                target_sectors=[]
                            )
                            campaigns.append(campaign)
                    
                    time.sleep(2)  # Rate limiting adicional
                    
                except Exception as e:
                    logger.warning(f"Error procesando keyword {keyword} en VirusTotal: {e}")
                    continue
                
        except Exception as e:
            logger.error(f"Error general en VirusTotal API: {e}")
        
        return campaigns
    
    def _fetch_malwarebazaar_data(self) -> List[Campaign]:
        """Obtiene datos REALES de MalwareBazaar API"""
        campaigns = []
        
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            
            # Obtener muestras recientes
            payload = {
                'query': 'get_recent',
                'selector': '100'
            }
            
            response = requests.post(url, data=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    # Filtrar por países LATAM o keywords relevantes
                    latam_samples = []
                    for sample in data.get('data', []):
                        sample_info = str(sample).lower()
                        
                        # Verificar si es relevante para LATAM
                        is_latam = any(keyword in sample_info for keyword in 
                                     ['br', 'brasil', 'brazil', 'mx', 'mexico', 'ar', 'argentina', 
                                      'cl', 'chile', 'co', 'colombia', 'banking', 'banco'])
                        
                        if is_latam:
                            latam_samples.append(sample)
                    
                    # Crear campañas agrupadas por familia de malware
                    malware_families = {}
                    for sample in latam_samples[:30]:  # Limitar cantidad
                        family = sample.get('signature', 'unknown')
                        if family not in malware_families:
                            malware_families[family] = []
                        malware_families[family].append(sample)
                    
                    for family, samples in malware_families.items():
                        iocs = []
                        countries = set()
                        
                        for sample in samples:
                            # Hash IOC
                            if sample.get('sha256_hash'):
                                ioc = IOC(
                                    value=sample['sha256_hash'],
                                    type='hash_sha256',
                                    confidence=85,
                                    first_seen=datetime.fromisoformat(sample.get('first_seen', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                                    last_seen=datetime.utcnow(),
                                    source='malware_bazaar',
                                    tags=['malware', family],
                                    threat_type='malware',
                                    malware_family=family,
                                    country=self._extract_country_from_content(str(sample))
                                )
                                iocs.append(ioc)
                            
                            # Determinar país afectado
                            sample_str = str(sample).lower()
                            if 'brazil' in sample_str or 'brasil' in sample_str or '.br' in sample_str:
                                countries.add('brazil')
                            elif 'mexico' in sample_str or '.mx' in sample_str:
                                countries.add('mexico')
                            elif 'argentina' in sample_str or '.ar' in sample_str:
                                countries.add('argentina')
                            elif 'chile' in sample_str or '.cl' in sample_str:
                                countries.add('chile')
                            elif 'colombia' in sample_str or '.co' in sample_str:
                                countries.add('colombia')
                            else:
                                countries.add('latam')
                        
                        if iocs:
                            campaign = Campaign(
                                id=f"mb-{family}-{int(time.time())}",
                                name=f"MalwareBazaar - {family.title()}",
                                description=f"Muestras de malware {family} detectadas por MalwareBazaar relevantes para LATAM",
                                countries_affected=list(countries) if countries else ['latam'],
                                threat_actor=None,
                                first_seen=datetime.utcnow() - timedelta(hours=12),
                                last_seen=datetime.utcnow(),
                                ttps=[],
                                iocs=iocs[:15],  # Limitar cantidad
                                severity='high' if family in ['mekotio', 'grandoreiro', 'casbaneiro'] else 'medium',
                                source='malware_bazaar',
                                malware_families=[family],
                                target_sectors=['banking', 'financial'] if 'bank' in family.lower() else []
                            )
                            campaigns.append(campaign)
                            
        except Exception as e:
            logger.error(f"Error en MalwareBazaar API: {e}")
        
        return campaigns
    
    def _fetch_otx_data(self) -> List[Campaign]:
        """Obtiene datos REALES de OTX AlienVault API"""
        campaigns = []
        
        try:
            self.api_config._respect_rate_limit('otx')
            headers = self.api_config.get_otx_headers()
            
            # Buscar pulsos relacionados con LATAM
            url = f"{self.api_config.OTX_BASE_URL}/pulses/subscribed"
            params = {
                'limit': 50,
                'modified_since': (datetime.utcnow() - timedelta(days=7)).isoformat()
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for pulse in data.get('results', [])[:20]:  # Limitar cantidad
                    try:
                        # Filtrar pulsos relevantes para LATAM
                        pulse_name = pulse.get('name', '').lower()
                        pulse_desc = pulse.get('description', '').lower()
                        pulse_tags = [tag.lower() for tag in pulse.get('tags', [])]
                        
                        is_latam = any(country in pulse_name or country in pulse_desc 
                                     for country in self.config.LATAM_COUNTRIES)
                        is_latam = is_latam or any(tag in pulse_tags for tag in ['latam', 'brazil', 'mexico', 'argentina', 'banking'])
                        
                        if is_latam:
                            # Extraer IOCs del pulso
                            iocs = []
                            for indicator in pulse.get('indicators', [])[:15]:  # Limitar cantidad
                                ioc_type = indicator.get('type')
                                ioc_value = indicator.get('indicator')
                                
                                # Mapear tipos de OTX a nuestros tipos
                                type_mapping = {
                                    'IPv4': 'ip',
                                    'domain': 'domain',
                                    'hostname': 'domain',
                                    'URL': 'url',
                                    'FileHash-MD5': 'hash_md5',
                                    'FileHash-SHA1': 'hash_sha1',
                                    'FileHash-SHA256': 'hash_sha256'
                                }
                                
                                mapped_type = type_mapping.get(ioc_type, 'unknown')
                                
                                if mapped_type != 'unknown':
                                    ioc = IOC(
                                        value=ioc_value,
                                        type=mapped_type,
                                        confidence=75,
                                        first_seen=datetime.fromisoformat(pulse.get('created', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                                        last_seen=datetime.utcnow(),
                                        source='otx',
                                        tags=pulse_tags[:5],  # Limitar tags
                                        threat_type=pulse.get('malware_families', [None])[0] if pulse.get('malware_families') else None,
                                        malware_family=pulse.get('malware_families', [None])[0] if pulse.get('malware_families') else None,
                                        country=self._extract_country_from_content(pulse_name + ' ' + pulse_desc)
                                    )
                                    iocs.append(ioc)
                            
                            if iocs:
                                campaign = Campaign(
                                    id=f"otx-{pulse.get('id', int(time.time()))}",
                                    name=f"OTX - {pulse.get('name', 'Amenaza LATAM')[:50]}...",  # Limitar longitud
                                    description=pulse.get('description', '')[:200] + '...' if len(pulse.get('description', '')) > 200 else pulse.get('description', ''),
                                    countries_affected=[self._extract_country_from_content(pulse_name + ' ' + pulse_desc)],
                                    threat_actor=pulse.get('author_name'),
                                    first_seen=datetime.fromisoformat(pulse.get('created', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                                    last_seen=datetime.fromisoformat(pulse.get('modified', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                                    ttps=[],
                                    iocs=iocs,
                                    severity='medium',
                                    source='otx',
                                    malware_families=pulse.get('malware_families', [])[:3],  # Limitar cantidad
                                    target_sectors=[]
                                )
                                campaigns.append(campaign)
                    
                    except Exception as e:
                        logger.warning(f"Error procesando pulso OTX: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error en OTX API: {e}")
        
        return campaigns
    
    def _fetch_xforce_data(self) -> List[Campaign]:
        """Obtiene datos REALES de IBM X-Force Exchange API"""
        campaigns = []
        
        try:
            self.api_config._respect_rate_limit('ibm_xforce')
            headers = self.api_config.get_ibm_xforce_headers()
            
            # Buscar amenazas recientes
            url = f"{self.api_config.IBM_XFORCE_BASE_URL}/collections"
            params = {
                'limit': 20,
                'bookmarked': 'false'
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for collection in data.get('collections', [])[:10]:  # Limitar cantidad
                    try:
                        # Filtrar por relevancia LATAM
                        title = collection.get('title', '').lower()
                        description = collection.get('description', '').lower()
                        
                        is_latam = any(country in title or country in description 
                                     for country in self.config.LATAM_COUNTRIES)
                        is_latam = is_latam or any(keyword in title or keyword in description 
                                                 for keyword in ['banking', 'financial', 'banco'])
                        
                        if is_latam:
                            # Crear campaña básica (X-Force no siempre proporciona IOCs detallados en la API pública)
                            campaign = Campaign(
                                id=f"xforce-{collection.get('id', int(time.time()))}",
                                name=f"IBM X-Force - {collection.get('title', 'Amenaza LATAM')[:50]}...",
                                description=collection.get('description', '')[:200] + '...' if len(collection.get('description', '')) > 200 else collection.get('description', ''),
                                countries_affected=[self._extract_country_from_content(title + ' ' + description)],
                                threat_actor=None,
                                first_seen=datetime.fromisoformat(collection.get('created', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                                last_seen=datetime.utcnow(),
                                ttps=[],
                                iocs=[],  # X-Force API pública limitada para IOCs específicos
                                severity='medium',
                                source='ibm_xforce',
                                malware_families=[],
                                target_sectors=[]
                            )
                            campaigns.append(campaign)
                        
                        time.sleep(2)  # Rate limiting adicional
                    
                    except Exception as e:
                        logger.warning(f"Error procesando colección X-Force: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error en IBM X-Force API: {e}")
        
        return campaigns
    
    def _fetch_public_sources(self) -> List[Campaign]:
        """Obtiene datos REALES de fuentes públicas sin API key"""
        campaigns = []
        
        try:
            # URLhaus - abuse.ch (fuente pública confiable)
            response = requests.get('https://urlhaus.feodotracker.abuse.ch/downloads/csv_recent/', timeout=30)
            
            if response.status_code == 200:
                csv_data = response.text
                lines = csv_data.strip().split('\n')
                
                # Saltar header si existe
                if lines and lines[0].startswith('#'):
                    lines = lines[1:]
                
                iocs = []
                for line in lines[:100]:  # Limitar cantidad
                    try:
                        if line and not line.startswith('#'):
                            parts = line.split(',')
                            if len(parts) >= 8:
                                url = parts[2].strip('"')
                                url_status = parts[3].strip('"')
                                
                                # Solo URLs activas
                                if url_status == 'online':
                                    # Verificar si es relevante para LATAM
                                    is_latam = any(keyword in url.lower() for keyword in 
                                                 ['.br', '.mx', '.ar', '.cl', '.co', 'brasil', 'mexico', 'banco'])
                                    
                                    if is_latam:
                                        ioc = IOC(
                                            value=url,
                                            type='url',
                                            confidence=80,
                                            first_seen=datetime.utcnow() - timedelta(hours=6),
                                            last_seen=datetime.utcnow(),
                                            source='urlhaus',
                                            tags=['malware', 'url', 'latam'],
                                            threat_type='malware',
                                            malware_family=parts[5].strip('"') if len(parts) > 5 else 'unknown',
                                            country=self._extract_country_from_content(url)
                                        )
                                        iocs.append(ioc)
                    except Exception as e:
                        continue  # Saltar líneas problemáticas
                
                if iocs:
                    campaign = Campaign(
                        id=f"urlhaus-{int(time.time())}",
                        name="URLhaus - URLs Maliciosas LATAM",
                        description=f"URLs maliciosas detectadas por URLhaus relevantes para LATAM ({len(iocs)} IOCs)",
                        countries_affected=['latam'],
                        threat_actor=None,
                        first_seen=datetime.utcnow() - timedelta(hours=6),
                        last_seen=datetime.utcnow(),
                        ttps=[],
                        iocs=iocs[:30],  # Limitar cantidad
                        severity='medium',
                        source='urlhaus',
                        malware_families=list(set([ioc.malware_family for ioc in iocs if ioc.malware_family and ioc.malware_family != 'unknown']))[:5],
                        target_sectors=[]
                    )
                    campaigns.append(campaign)
                    
        except Exception as e:
            logger.error(f"Error obteniendo fuentes públicas: {e}")
        
        return campaigns
    
    def _extract_iocs_from_text(self, text: str) -> List[IOC]:
        """Extrae IOCs de texto usando regex"""
        iocs = []
        
        # Regex patterns para diferentes tipos de IOCs
        patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"{}|\\^`[\]]+',
        }
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            
            for match in matches[:5]:  # Limitar cantidad por tipo
                # Filtrar falsos positivos comunes
                if ioc_type == 'domain':
                    if any(fp in match.lower() for fp in ['example.com', 'test.com', 'localhost']):
                        continue
                elif ioc_type == 'ip':
                    if any(fp in match for fp in ['127.0.0.1', '0.0.0.0', '255.255.255.255']):
                        continue
                
                ioc = IOC(
                    value=match,
                    type=ioc_type,
                    confidence=65,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    source='text_extraction',
                    tags=[],
                    threat_type=None,
                    malware_family=None,
                    country=None
                )
                iocs.append(ioc)
        
        return iocs
    
    def _generate_minimal_demo_data(self) -> List[Campaign]:
        """Genera datos mínimos de demostración cuando no hay APIs configuradas"""
        logger.info("Generando datos mínimos de demostración - configura las API keys para datos reales")
        
        demo_iocs = [
            IOC(
                value="ejemplo-dominio-malicioso.tk",
                type='domain',
                confidence=75,
                first_seen=datetime.utcnow() - timedelta(hours=24),
                last_seen=datetime.utcnow(),
                source='demo',
                tags=['demo', 'phishing'],
                threat_type='phishing',
                malware_family=None,
                country='latam'
            )
        ]
        
        demo_campaign = Campaign(
            id=f"demo-{int(time.time())}",
            name="Campaña de Demostración",
            description="Configure las API keys (VIRUSTOTAL_API_KEY, OTX_API_KEY, etc.) para obtener datos reales de threat intelligence",
            countries_affected=['latam'],
            threat_actor=None,
            first_seen=datetime.utcnow() - timedelta(hours=24),
            last_seen=datetime.utcnow(),
            ttps=[],
            iocs=demo_iocs,
            severity='low',
            source='demo',
            malware_families=[],
            target_sectors=[]
        )
        
        return [demo_campaign]
    
    def scrape_all_sources(self) -> List[Campaign]:
        """Ejecuta recolección REAL de todas las fuentes de threat intelligence"""
        logger.info("=== INICIANDO RECOLECCIÓN REAL DE THREAT INTELLIGENCE ===")
        
        campaigns = []
        
        # 1. VirusTotal IOCs
        if self.api_config.VIRUSTOTAL_API_KEY:
            try:
                vt_campaigns = self._fetch_virustotal_data()
                campaigns.extend(vt_campaigns)
                logger.info(f"VirusTotal: {len(vt_campaigns)} campañas obtenidas")
            except Exception as e:
                logger.error(f"Error obteniendo datos de VirusTotal: {e}")
        else:
            logger.warning("VirusTotal API key no configurada - saltando")
        
        # 2. MalwareBazaar (No requiere API key)
        try:
            mb_campaigns = self._fetch_malwarebazaar_data()
            campaigns.extend(mb_campaigns)
            logger.info(f"MalwareBazaar: {len(mb_campaigns)} campañas obtenidas")
        except Exception as e:
            logger.error(f"Error obteniendo datos de MalwareBazaar: {e}")
        
        # 3. OTX AlienVault
        if self.api_config.OTX_API_KEY:
            try:
                otx_campaigns = self._fetch_otx_data()
                campaigns.extend(otx_campaigns)
                logger.info(f"OTX AlienVault: {len(otx_campaigns)} campañas obtenidas")
            except Exception as e:
                logger.error(f"Error obteniendo datos de OTX: {e}")
        else:
            logger.warning("OTX API key no configurada - saltando")
        
        # 4. IBM X-Force
        if self.api_config.IBM_XFORCE_API_KEY:
            try:
                xforce_campaigns = self._fetch_xforce_data()
                campaigns.extend(xforce_campaigns)
                logger.info(f"IBM X-Force: {len(xforce_campaigns)} campañas obtenidas")
            except Exception as e:
                logger.error(f"Error obteniendo datos de IBM X-Force: {e}")
        else:
            logger.warning("IBM X-Force API key no configurada - saltando")
        
        # 5. Fuentes públicas (No requieren API key)
        try:
            public_campaigns = self._fetch_public_sources()
            campaigns.extend(public_campaigns)
            logger.info(f"Fuentes públicas: {len(public_campaigns)} campañas obtenidas")
        except Exception as e:
            logger.error(f"Error obteniendo datos de fuentes públicas: {e}")
        
        # Si no se obtuvo ningún dato real, generar datos mínimos para demo
        if not campaigns:
            logger.warning("No se obtuvieron datos reales, generando datos mínimos de demostración")
            campaigns = self._generate_minimal_demo_data()
        
        logger.info(f"=== RECOLECCIÓN REAL COMPLETADA: {len(campaigns)} campañas ===")
        return campaigns

# =====================================================
# ALMACENAMIENTO
# =====================================================

class AegisStorage:
    """Sistema de almacenamiento AEGIS"""
    
    def __init__(self, config: Config):
        self.config = config
        
        if MONGODB_AVAILABLE:
            try:
                self.mongo_client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
                self.db = self.mongo_client[config.DATABASE_NAME]
                self.campaigns_collection = self.db.campaigns
                self.iocs_collection = self.db.iocs
                self.cves_collection = self.db.cves
                
                self.mongo_client.server_info()
                logger.info("MongoDB conectado correctamente")
                self.use_memory = False
                self._setup_indexes()
                
            except Exception as e:
                logger.warning(f"MongoDB no disponible: {e}. Usando almacenamiento en memoria.")
                self.use_memory = True
                self._init_memory_storage()
        else:
            logger.warning("PyMongo no disponible. Usando almacenamiento en memoria.")
            self.use_memory = True
            self._init_memory_storage()
    
    def _init_memory_storage(self):
        """Inicializa almacenamiento en memoria"""
        global memory_campaigns_global, memory_iocs_global, memory_alerts_global
        self.memory_campaigns = memory_campaigns_global
        self.memory_iocs = memory_iocs_global
        self.memory_cves = []
    
    def _setup_indexes(self):
        """Configura índices para optimizar consultas"""
        if self.use_memory:
            return
            
        try:
            self.campaigns_collection.create_index("id", unique=True)
            self.campaigns_collection.create_index("countries_affected")
            self.campaigns_collection.create_index("severity")
            self.campaigns_collection.create_index("source")
            
            self.iocs_collection.create_index("value", unique=True)
            self.iocs_collection.create_index("type")
            self.iocs_collection.create_index("campaign_id")
            
            logger.info("Índices de base de datos configurados")
            
        except Exception as e:
            logger.warning(f"Error configurando índices: {e}")
    
    def store_campaign(self, campaign: Campaign) -> bool:
        """Almacena campaña con manejo robusto de errores"""
        try:
            campaign_dict = asdict(campaign)
            campaign_dict['first_seen'] = campaign.first_seen.isoformat()
            campaign_dict['last_seen'] = campaign.last_seen.isoformat()
            
            iocs_list = []
            for ioc in campaign.iocs:
                ioc_dict = asdict(ioc)
                ioc_dict['first_seen'] = ioc.first_seen.isoformat()
                ioc_dict['last_seen'] = ioc.last_seen.isoformat()
                iocs_list.append(ioc_dict)
            
            campaign_dict['iocs'] = iocs_list
            
            if self.use_memory:
                global memory_campaigns_global, memory_iocs_global
                if not any(c['id'] == campaign.id for c in memory_campaigns_global):
                    memory_campaigns_global.append(campaign_dict)
                    self.memory_campaigns.append(campaign_dict)
                    logger.debug(f"Campaña almacenada en memoria: {campaign.name} (total: {len(memory_campaigns_global)})")
                    
                    for ioc in campaign.iocs:
                        ioc_dict = asdict(ioc)
                        ioc_dict['first_seen'] = ioc.first_seen.isoformat()
                        ioc_dict['last_seen'] = ioc.last_seen.isoformat()
                        ioc_dict['campaign_id'] = campaign.id
                        
                        if not any(i['value'] == ioc.value for i in memory_iocs_global):
                            memory_iocs_global.append(ioc_dict)
                            self.memory_iocs.append(ioc_dict)
                else:
                    logger.debug(f"Campaña duplicada no almacenada: {campaign.id}")
                    return False
            else:
                self.campaigns_collection.insert_one(campaign_dict)
                
                for ioc in campaign.iocs:
                    ioc_dict = asdict(ioc)
                    ioc_dict['first_seen'] = ioc.first_seen.isoformat()
                    ioc_dict['last_seen'] = ioc.last_seen.isoformat()
                    ioc_dict['campaign_id'] = campaign.id
                    
                    try:
                        self.iocs_collection.insert_one(ioc_dict)
                    except DuplicateKeyError:
                        self.iocs_collection.update_one(
                            {"value": ioc.value},
                            {"$set": {
                                "last_seen": ioc.last_seen.isoformat(),
                                "campaign_id": campaign.id
                            }}
                        )
            
            logger.info(f"Campaña almacenada: {campaign.name} ({len(campaign.iocs)} IOCs)")
            return True
            
        except Exception as e:
            if "duplicate" in str(e).lower():
                logger.warning(f"Campaña duplicada: {campaign.id}")
                return False
            else:
                logger.error(f"Error almacenando campaña: {e}")
                return False
    
    def get_recent_iocs(self, limit: int = 100) -> List[Dict]:
        """Obtiene IOCs recientes ordenados por fecha de último avistamiento"""
        try:
            if self.use_memory:
                iocs = self.memory_iocs.copy()
                
                # Convertir IOCs a formato dict si es necesario
                formatted_iocs = []
                for ioc in iocs:
                    if hasattr(ioc, '__dict__'):
                        # Es un objeto IOC
                        ioc_dict = {
                            'value': ioc.value,
                            'type': ioc.type,
                            'confidence': ioc.confidence,
                            'first_seen': ioc.first_seen.isoformat() if hasattr(ioc.first_seen, 'isoformat') else str(ioc.first_seen),
                            'last_seen': ioc.last_seen.isoformat() if hasattr(ioc.last_seen, 'isoformat') else str(ioc.last_seen),
                            'source': ioc.source,
                            'tags': ioc.tags,
                            'threat_type': ioc.threat_type,
                            'malware_family': ioc.malware_family,
                            'country': ioc.country
                        }
                    else:
                        # Ya es un dict
                        ioc_dict = ioc
                    
                    formatted_iocs.append(ioc_dict)
                
                # Ordenar por last_seen (más reciente primero)
                formatted_iocs.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
                return formatted_iocs[:limit]
                
            else:
                iocs = list(self.iocs_collection.find({})
                           .sort("last_seen", -1)
                           .limit(limit))
                
                for ioc in iocs:
                    ioc['_id'] = str(ioc['_id'])
                    # Asegurar formato de fechas
                    if 'first_seen' in ioc and hasattr(ioc['first_seen'], 'isoformat'):
                        ioc['first_seen'] = ioc['first_seen'].isoformat()
                    if 'last_seen' in ioc and hasattr(ioc['last_seen'], 'isoformat'):
                        ioc['last_seen'] = ioc['last_seen'].isoformat()
                
                return iocs
                
        except Exception as e:
            logger.error(f"Error obteniendo IOCs: {e}")
            return []
    
    def search_campaigns(self, query: str = "", filters: Dict = None) -> List[Dict]:
        """Busca campañas con filtros avanzados"""
        try:
            if self.use_memory:
                global memory_campaigns_global
                logger.debug(f"Buscando campañas en memoria. Total disponibles: {len(memory_campaigns_global)}")
                campaigns = memory_campaigns_global.copy()
                
                if query:
                    campaigns = [c for c in campaigns if 
                               query.lower() in c['name'].lower() or 
                               query.lower() in c['description'].lower()]
                
                if filters:
                    if 'severity' in filters and filters['severity']:
                        campaigns = [c for c in campaigns if c['severity'] == filters['severity']]
                    if 'source' in filters and filters['source']:
                        campaigns = [c for c in campaigns if filters['source'] in c['source']]
                    if 'country' in filters and filters['country']:
                        campaigns = [c for c in campaigns if filters['country'] in c['countries_affected']]
                
                campaigns.sort(key=lambda x: x['last_seen'], reverse=True)
                logger.debug(f"Campañas después de filtros: {len(campaigns)}")
                return campaigns[:100]
            
            else:
                search_filter = {}
                
                if query:
                    search_filter["$or"] = [
                        {"name": {"$regex": query, "$options": "i"}},
                        {"description": {"$regex": query, "$options": "i"}}
                    ]
                
                if filters:
                    if 'severity' in filters and filters['severity']:
                        search_filter['severity'] = filters['severity']
                    if 'source' in filters and filters['source']:
                        search_filter['source'] = {"$regex": filters['source'], "$options": "i"}
                    if 'country' in filters and filters['country']:
                        search_filter['countries_affected'] = {"$in": [filters['country']]}
                
                campaigns = list(self.campaigns_collection.find(search_filter).sort("last_seen", -1).limit(100))
                
                for campaign in campaigns:
                    campaign['_id'] = str(campaign['_id'])
                
                return campaigns
            
        except Exception as e:
            logger.error(f"Error buscando campañas: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas detalladas del sistema"""
        try:
            if self.use_memory:
                global memory_campaigns_global, memory_iocs_global
                stats = {
                    'total_campaigns': len(memory_campaigns_global),
                    'total_iocs': len(memory_iocs_global),
                    'campaigns_by_severity': {},
                    'campaigns_by_source': {},
                    'iocs_by_type': {},
                    'iocs_by_country': {},
                    'malware_families': {}
                }
                
                for campaign in memory_campaigns_global:
                    severity = campaign['severity']
                    stats['campaigns_by_severity'][severity] = stats['campaigns_by_severity'].get(severity, 0) + 1
                
                for campaign in memory_campaigns_global:
                    source = campaign['source']
                    stats['campaigns_by_source'][source] = stats['campaigns_by_source'].get(source, 0) + 1
                
                for ioc in memory_iocs_global:
                    ioc_type = ioc['type']
                    stats['iocs_by_type'][ioc_type] = stats['iocs_by_type'].get(ioc_type, 0) + 1
                    
                    country = ioc.get('country', 'unknown')
                    stats['iocs_by_country'][country] = stats['iocs_by_country'].get(country, 0) + 1
                
                for campaign in memory_campaigns_global:
                    for family in campaign.get('malware_families', []):
                        stats['malware_families'][family] = stats['malware_families'].get(family, 0) + 1
                
                return stats
            
            else:
                stats = {
                    'total_campaigns': self.campaigns_collection.count_documents({}),
                    'total_iocs': self.iocs_collection.count_documents({}),
                    'campaigns_by_severity': {},
                    'campaigns_by_source': {},
                    'iocs_by_type': {},
                    'iocs_by_country': {},
                    'malware_families': {}
                }
                
                # Agregaciones simples para MongoDB
                pipelines = [
                    ("severity", [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]),
                    ("source", [{"$group": {"_id": "$source", "count": {"$sum": 1}}}])
                ]
                
                for field, pipeline in pipelines:
                    for result in self.campaigns_collection.aggregate(pipeline):
                        stats[f'campaigns_by_{field}'][result['_id']] = result['count']
                
                return stats
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            # Devolver estadísticas mínimas para que el dashboard funcione
            return self._get_default_stats()
    
    def _get_default_stats(self) -> Dict:
        """Devuelve estadísticas por defecto cuando no hay datos"""
        return {
            'total_campaigns': 0,
            'total_iocs': 0,
            'campaigns_by_severity': {
                'critical': 0,
                'high': 0, 
                'medium': 0,
                'low': 0
            },
            'campaigns_by_source': {
                'virustotal': 0,
                'malware_bazaar': 0,
                'otx_alienvault': 0,
                'ibm_xforce': 0
            },
            'iocs_by_type': {
                'url': 0,
                'domain': 0,
                'ip': 0,
                'hash_sha256': 0
            },
            'iocs_by_country': {
                'unknown': 0
            },
            'malware_families': {}
        }
    
    def export_to_csv(self, campaign_ids: List[str] = None) -> str:
        """Exporta datos a formato CSV"""
        try:
            output = StringIO()
            
            if self.use_memory:
                global memory_campaigns_global
                campaigns = memory_campaigns_global
                if campaign_ids:
                    campaigns = [c for c in campaigns if c['id'] in campaign_ids]
            else:
                filter_dict = {}
                if campaign_ids:
                    filter_dict['id'] = {"$in": campaign_ids}
                campaigns = list(self.campaigns_collection.find(filter_dict))
            
            fieldnames = [
                'campaign_id', 'campaign_name', 'severity', 'source', 'countries_affected',
                'malware_families', 'first_seen', 'last_seen',
                'ioc_value', 'ioc_type', 'ioc_confidence', 'ioc_threat_type', 
                'ioc_country', 'ioc_source'
            ]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for campaign in campaigns:
                base_row = {
                    'campaign_id': campaign['id'],
                    'campaign_name': campaign['name'],
                    'severity': campaign['severity'],
                    'source': campaign['source'],
                    'countries_affected': ', '.join(campaign.get('countries_affected', [])),
                    'malware_families': ', '.join(campaign.get('malware_families', [])),
                    'first_seen': campaign['first_seen'],
                    'last_seen': campaign['last_seen']
                }
                
                if campaign.get('iocs'):
                    for ioc_data in campaign['iocs']:
                        row = base_row.copy()
                        row.update({
                            'ioc_value': ioc_data['value'],
                            'ioc_type': ioc_data['type'],
                            'ioc_confidence': ioc_data['confidence'],
                            'ioc_threat_type': ioc_data.get('threat_type', ''),
                            'ioc_country': ioc_data.get('country', ''),
                            'ioc_source': ioc_data['source']
                        })
                        writer.writerow(row)
                else:
                    row = base_row.copy()
                    row.update({
                        'ioc_value': '', 'ioc_type': '', 'ioc_confidence': '',
                        'ioc_threat_type': '', 'ioc_country': '', 'ioc_source': ''
                    })
                    writer.writerow(row)
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error exportando a CSV: {e}")
            return ""
    
    def ensure_sample_data(self):
        """Genera datos de ejemplo si no hay datos reales disponibles"""
        try:
            # Verificar si ya hay datos
            campaigns_count = len(self.memory_campaigns) if self.use_memory else self.campaigns_collection.count_documents({})
            
            logger.info(f"📊 Estado actual: {campaigns_count} campañas")
            
            # Si no hay datos, generar algunos de ejemplo
            if campaigns_count == 0:
                logger.info("No hay datos disponibles, generando datos de ejemplo...")
                self._generate_sample_data()
                
        except Exception as e:
            logger.error(f"Error verificando/generando datos de ejemplo: {e}")
    
    def _generate_sample_data(self):
        """Genera datos de ejemplo para demostración"""
        sample_campaigns = [
            {
                'id': 'demo-campaign-001',
                'name': 'Campaña de Demostración - VirusTotal',
                'description': 'Campaña de ejemplo detectada por VirusTotal para demostración del sistema',
                'severity': 'medium',
                'source': 'virustotal',
                'countries_affected': ['brazil', 'mexico'],
                'malware_families': ['mekotio'],
                'first_seen': (datetime.utcnow() - timedelta(hours=24)).isoformat(),
                'last_seen': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                'iocs': [
                    {
                        'value': 'demo-malicious-domain.tk',
                        'type': 'domain',
                        'confidence': 85,
                        'first_seen': (datetime.utcnow() - timedelta(hours=20)).isoformat(),
                        'last_seen': (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                        'source': 'virustotal',
                        'tags': ['phishing', 'demo'],
                        'threat_type': 'phishing',
                        'malware_family': 'mekotio',
                        'country': 'brazil'
                    },
                    {
                        'value': '203.0.113.100',
                        'type': 'ip',
                        'confidence': 90,
                        'first_seen': (datetime.utcnow() - timedelta(hours=18)).isoformat(),
                        'last_seen': (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                        'source': 'virustotal',
                        'tags': ['c2', 'demo'],
                        'threat_type': 'c2',
                        'malware_family': 'mekotio',
                        'country': 'mexico'
                    }
                ]
            },
            {
                'id': 'demo-campaign-002',
                'name': 'Campaña de Demostración - MalwareBazaar',
                'description': 'Campaña de ejemplo detectada por MalwareBazaar',
                'severity': 'high',
                'source': 'malware_bazaar',
                'countries_affected': ['argentina', 'chile'],
                'malware_families': ['grandoreiro'],
                'first_seen': (datetime.utcnow() - timedelta(hours=12)).isoformat(),
                'last_seen': (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                'iocs': [
                    {
                        'value': 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
                        'type': 'hash_sha256',
                        'confidence': 95,
                        'first_seen': (datetime.utcnow() - timedelta(hours=12)).isoformat(),
                        'last_seen': (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                        'source': 'malware_bazaar',
                        'tags': ['malware', 'banking', 'demo'],
                        'threat_type': 'malware',
                        'malware_family': 'grandoreiro',
                        'country': 'argentina'
                    }
                ]
            }
        ]
        
        # Almacenar campañas de ejemplo
        for campaign_data in sample_campaigns:
            if self.use_memory:
                global memory_campaigns_global, memory_iocs_global
                memory_campaigns_global.append(campaign_data)
                self.memory_campaigns.append(campaign_data)
                
                # Almacenar IOCs
                for ioc_data in campaign_data.get('iocs', []):
                    ioc_data['campaign_id'] = campaign_data['id']
                    memory_iocs_global.append(ioc_data)
                    self.memory_iocs.append(ioc_data)
            else:
                # Para MongoDB
                self.campaigns_collection.insert_one(campaign_data)
        
        logger.info(f"Datos de ejemplo generados: {len(sample_campaigns)} campañas")

# =====================================================
# SISTEMA DE ALERTAS
# =====================================================

class AegisAlertSystem:
    """Sistema de alertas inteligente para amenazas críticas"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def check_critical_indicators(self, campaigns: List[Campaign]) -> List[Dict]:
        """Verifica indicadores críticos y genera alertas inteligentes"""
        alerts = []
        
        for campaign in campaigns:
            if campaign.severity == 'critical':
                alerts.append({
                    'type': 'critical_campaign',
                    'title': f'Campaña Crítica: {campaign.name}',
                    'description': f'{campaign.description} - {len(campaign.iocs)} IOCs detectados',
                    'severity': 'critical',
                    'timestamp': datetime.utcnow().isoformat(),
                    'campaign_id': campaign.id,
                    'countries': campaign.countries_affected,
                    'ioc_count': len(campaign.iocs)
                })
            
            banking_malware = ['mekotio', 'grandoreiro', 'casbaneiro', 'amavaldo', 'javali']
            detected_banking = [m for m in campaign.malware_families if m in banking_malware]
            if detected_banking:
                alerts.append({
                    'type': 'banking_malware',
                    'title': f'Malware Bancario: {", ".join(detected_banking).title()}',
                    'description': f'Detectado malware bancario dirigido a LATAM en {", ".join(campaign.countries_affected)}',
                    'severity': 'critical',
                    'timestamp': datetime.utcnow().isoformat(),
                    'campaign_id': campaign.id,
                    'malware_families': detected_banking,
                    'countries': campaign.countries_affected
                })
        
        # Limitar a 10 alertas más recientes
        alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        return alerts[:10]

# =====================================================
# INTEGRACIÓN CON CVE / NVD
# =====================================================

class CVEIntegration:
    """Integración con National Vulnerability Database (NVD)"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            'User-Agent': 'AEGIS-ThreatIntel/3.0',
            'Accept': 'application/json'
        }
        if self.api_key:
            self.headers['apiKey'] = self.api_key
    
    def fetch_recent_cves(self, days_back: int = 7) -> List[CVE]:
        """Obtiene CVEs recientes de NVD"""
        cves = []
        
        try:
            # Calcular fechas
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                'pubStartDate': start_date.isoformat(),
                'pubEndDate': end_date.isoformat(),
                'resultsPerPage': 100
            }
            
            response = requests.get(self.base_url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for vulnerability in data.get('vulnerabilities', []):
                    cve_data = vulnerability.get('cve', {})
                    
                    # Extraer información básica
                    cve_id = cve_data.get('id', '')
                    descriptions = cve_data.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Fechas
                    published = cve_data.get('published', datetime.utcnow().isoformat())
                    modified = cve_data.get('lastModified', datetime.utcnow().isoformat())
                    
                    # CVSS Score
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 0.0
                    cvss_severity = 'unknown'
                    vector_string = None
                    
                    # Buscar CVSS v3.1 primero, luego v3.0, luego v2.0
                    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if version in metrics and metrics[version]:
                            cvss_data = metrics[version][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_severity = cvss_data.get('baseSeverity', 'unknown').lower()
                            vector_string = cvss_data.get('vectorString')
                            break
                    
                    # Referencias
                    references = []
                    for ref in cve_data.get('references', []):
                        references.append(ref.get('url', ''))
                    
                    # CWE IDs
                    cwe_ids = []
                    for weakness in cve_data.get('weaknesses', []):
                        for description in weakness.get('description', []):
                            cwe_ids.append(description.get('value', ''))
                    
                    cve = CVE(
                        id=cve_id,
                        description=description,
                        published_date=datetime.fromisoformat(published.replace('Z', '+00:00')),
                        last_modified=datetime.fromisoformat(modified.replace('Z', '+00:00')),
                        cvss_score=cvss_score,
                        cvss_severity=cvss_severity,
                        vector_string=vector_string,
                        source='nvd',
                        references=references,
                        cwe_ids=cwe_ids,
                        affected_products=[]
                    )
                    cves.append(cve)
            else:
                logger.warning(f"Error en NVD API: HTTP {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error obteniendo CVEs de NVD: {e}")
        
        return cves

# =====================================================
# BÚSQUEDA MANUAL DE IOCs
# =====================================================

class IOCSearchEngine:
    """Motor de búsqueda manual de IOCs"""
    
    def __init__(self, api_config: ThreatIntelAPIs):
        self.api_config = api_config
    
    def search_ioc(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Busca un IOC específico en múltiples fuentes"""
        results = {
            'ioc': ioc_value,
            'type': ioc_type,
            'sources': {},
            'summary': {
                'malicious': 0,
                'total_engines': 0,
                'confidence': 0
            }
        }
        
        # VirusTotal
        if self.api_config.VIRUSTOTAL_API_KEY:
            try:
                vt_result = self._search_virustotal(ioc_value, ioc_type)
                results['sources']['virustotal'] = vt_result
                
                if vt_result.get('malicious', 0) > 0:
                    results['summary']['malicious'] += 1
                results['summary']['total_engines'] += 1
                    
            except Exception as e:
                logger.error(f"Error buscando en VirusTotal: {e}")
                results['sources']['virustotal'] = {'error': str(e)}
        
        # IBM X-Force
        if self.api_config.IBM_XFORCE_API_KEY:
            try:
                xf_result = self._search_xforce(ioc_value, ioc_type)
                results['sources']['xforce'] = xf_result
                
                if xf_result.get('malicious', False):
                    results['summary']['malicious'] += 1
                results['summary']['total_engines'] += 1
                    
            except Exception as e:
                logger.error(f"Error buscando en X-Force: {e}")
                results['sources']['xforce'] = {'error': str(e)}
        
        # Calcular confianza
        if results['summary']['total_engines'] > 0:
            results['summary']['confidence'] = int(
                (results['summary']['malicious'] / results['summary']['total_engines']) * 100
            )
        
        return results
    
    def _search_virustotal(self, ioc_value: str, ioc_type: str) -> Dict:
        """Busca IOC en VirusTotal"""
        self.api_config._respect_rate_limit('virustotal')
        headers = self.api_config.get_virustotal_headers()
        
        # Mapear tipos de IOC a endpoints de VT
        endpoint_mapping = {
            'ip': f"ip_addresses/{ioc_value}",
            'domain': f"domains/{ioc_value}",
            'url': f"urls/{base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip('=')}",
            'hash_md5': f"files/{ioc_value}",
            'hash_sha1': f"files/{ioc_value}",
            'hash_sha256': f"files/{ioc_value}"
        }
        
        endpoint = endpoint_mapping.get(ioc_type)
        if not endpoint:
            return {'error': 'Tipo de IOC no soportado'}
        
        url = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/{endpoint}"
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'scan_date': attributes.get('last_analysis_date'),
                'reputation': attributes.get('reputation', 0)
            }
        elif response.status_code == 404:
            return {'error': 'IOC no encontrado'}
        else:
            return {'error': f'HTTP {response.status_code}'}
    
    def _search_xforce(self, ioc_value: str, ioc_type: str) -> Dict:
        """Busca IOC en IBM X-Force"""
        self.api_config._respect_rate_limit('ibm_xforce')
        headers = self.api_config.get_ibm_xforce_headers()
        
        # Mapear tipos de IOC a endpoints de X-Force
        endpoint_mapping = {
            'ip': f"ipr/{ioc_value}",
            'domain': f"url/{ioc_value}",
            'url': f"url/{ioc_value}",
            'hash_md5': f"malware/{ioc_value}",
            'hash_sha1': f"malware/{ioc_value}",
            'hash_sha256': f"malware/{ioc_value}"
        }
        
        endpoint = endpoint_mapping.get(ioc_type)
        if not endpoint:
            return {'error': 'Tipo de IOC no soportado'}
        
        url = f"{self.api_config.IBM_XFORCE_BASE_URL}/{endpoint}"
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if ioc_type == 'ip':
                score = data.get('score', 0)
                return {
                    'malicious': score >= 3,
                    'score': score,
                    'categories': data.get('cats', {}),
                    'country': data.get('geo', {}).get('country')
                }
            elif ioc_type in ['domain', 'url']:
                result = data.get('result', {})
                score = result.get('score', 0)
                return {
                    'malicious': score >= 3,
                    'score': score,
                    'categories': result.get('cats', {})
                }
            else:  # hash
                malware = data.get('malware', {})
                return {
                    'malicious': bool(malware),
                    'family': malware.get('family'),
                    'type': malware.get('type')
                }
        elif response.status_code == 404:
            return {'error': 'IOC no encontrado'}
        else:
            return {'error': f'HTTP {response.status_code}'}

# =====================================================
# APLICACIÓN WEB
# =====================================================

def create_app():
    """Crea la aplicación Flask con todas las funcionalidades"""
    app = Flask(__name__)
    CORS(app)
    
    config = Config()
    storage = AegisStorage(config)
    scraper = ProfessionalThreatIntelligence(config)
    alert_system = AegisAlertSystem(config)
    
    # Nuevos componentes para funcionalidad real
    cve_integration = CVEIntegration(os.environ.get('NVD_API_KEY'))
    ioc_search_engine = IOCSearchEngine(ThreatIntelAPIs())
    
    # Asegurar que hay datos disponibles para demostración
    storage.ensure_sample_data()
    
    DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS Threat Intelligence LATAM</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e13 0%, #1a2332 100%);
            color: #ffffff;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(90deg, #1a2332 0%, #2d3748 100%);
            padding: 1rem 2rem;
            box-shadow: 0 4px 20px rgba(0, 255, 127, 0.3);
            border-bottom: 2px solid #00ff7f;
        }
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .logo i {
            font-size: 2.5rem;
            color: #00ff7f;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        .logo-text {
            display: flex;
            flex-direction: column;
        }
        .logo-title {
            font-size: 1.8rem;
            font-weight: bold;
            color: #00ff7f;
            text-shadow: 0 0 10px rgba(0, 255, 127, 0.5);
        }
        .logo-subtitle {
            font-size: 0.9rem;
            color: #a0aec0;
        }
        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: rgba(0, 255, 127, 0.1);
            border: 1px solid #00ff7f;
            border-radius: 20px;
            font-size: 0.9rem;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: #00ff7f;
            border-radius: 50%;
            animation: blink 1.5s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        .main-container {
            display: grid;
            grid-template-columns: 280px 1fr;
            min-height: calc(100vh - 80px);
        }
        .sidebar {
            background: linear-gradient(180deg, #1a2332 0%, #2d3748 100%);
            padding: 2rem 1rem;
            border-right: 2px solid #00ff7f;
        }
        .nav-menu {
            list-style: none;
        }
        .nav-item {
            margin-bottom: 0.5rem;
        }
        .nav-link {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            color: #a0aec0;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .nav-link:hover, .nav-link.active {
            background: linear-gradient(90deg, rgba(0, 255, 127, 0.2), rgba(0, 255, 127, 0.1));
            color: #00ff7f;
            transform: translateX(5px);
        }
        .content {
            padding: 2rem;
            overflow-y: auto;
        }
        .section {
            display: none;
        }
        .section.active {
            display: block;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        .card {
            background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(0, 255, 127, 0.2);
            transition: all 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 255, 127, 0.2);
        }
        .card-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        .card-icon {
            font-size: 1.5rem;
            color: #00ff7f;
        }
        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #ffffff;
        }
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #00ff7f;
            text-shadow: 0 0 10px rgba(0, 255, 127, 0.5);
        }
        .stat-label {
            font-size: 0.9rem;
            color: #a0aec0;
            margin-top: 0.5rem;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 1rem;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: rgba(26, 35, 50, 0.5);
            border-radius: 8px;
            overflow: hidden;
        }
        .data-table th,
        .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid rgba(0, 255, 127, 0.2);
        }
        .data-table th {
            background: rgba(0, 255, 127, 0.1);
            color: #00ff7f;
            font-weight: 600;
        }
        .data-table tr:hover {
            background: rgba(0, 255, 127, 0.05);
        }
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical {
            background: rgba(255, 69, 58, 0.2);
            color: #ff453a;
            border: 1px solid #ff453a;
        }
        .severity-high {
            background: rgba(255, 149, 0, 0.2);
            color: #ff9500;
            border: 1px solid #ff9500;
        }
        .severity-medium {
            background: rgba(255, 204, 2, 0.2);
            color: #ffcc02;
            border: 1px solid #ffcc02;
        }
        .severity-low {
            background: rgba(48, 209, 88, 0.2);
            color: #30d158;
            border: 1px solid #30d158;
        }
        .filters {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            align-items: end;
        }
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .filter-label {
            font-size: 0.9rem;
            color: #a0aec0;
        }
        .filter-select, .filter-input {
            background: #2d3748;
            border: 1px solid rgba(0, 255, 127, 0.3);
            border-radius: 6px;
            padding: 0.5rem;
            color: #ffffff;
            min-width: 150px;
        }
        .action-btn {
            background: linear-gradient(45deg, #00ff7f, #00cc66);
            border: none;
            border-radius: 6px;
            padding: 0.75rem 1.5rem;
            color: #000000;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 255, 127, 0.4);
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(0, 255, 127, 0.3);
            border-radius: 50%;
            border-top-color: #00ff7f;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .stats-mini-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .mini-stat {
            background: rgba(0, 255, 127, 0.1);
            border: 1px solid rgba(0, 255, 127, 0.3);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .mini-stat-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #00ff7f;
        }
        .mini-stat-label {
            font-size: 0.8rem;
            color: #a0aec0;
            margin-top: 0.25rem;
        }
        .country-tag {
            display: inline-block;
            background: rgba(0, 255, 127, 0.2);
            color: #00ff7f;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.1rem;
        }
        .ioc-value {
            font-family: 'Courier New', monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            word-break: break-all;
            font-size: 0.9rem;
        }
        .alert-item {
            background: linear-gradient(90deg, rgba(255, 69, 58, 0.1), rgba(255, 69, 58, 0.05));
            border: 1px solid rgba(255, 69, 58, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .alert-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        .alert-title {
            font-weight: 600;
            color: #ffffff;
        }
        .alert-time {
            font-size: 0.8rem;
            color: #a0aec0;
            margin-left: auto;
        }
        .real-data-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(45deg, #00ff7f, #00cc66);
            color: #000000;
            border-radius: 20px;
            padding: 0.5rem 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            z-index: 1000;
            font-weight: bold;
            box-shadow: 0 4px 20px rgba(0, 255, 127, 0.3);
        }
        .real-dot {
            width: 8px;
            height: 8px;
            background: #000000;
            border-radius: 50%;
            animation: blink 1s infinite;
        }
    </style>
</head>
<body>
    <div class="real-data-indicator">
        <div class="real-dot"></div>
        <span>SISTEMA REAL EN VIVO</span>
    </div>

    <header class="header">
        <div class="header-content">
            <div class="logo">
                <i class="fas fa-shield-virus"></i>
                <div class="logo-text">
                    <div class="logo-title">AEGIS Threat Intelligence</div>
                    <div class="logo-subtitle">LATAM Real-Time Security Operations</div>
                </div>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                <span>Sistema Real Activo</span>
            </div>
        </div>
    </header>

    <div class="main-container">
        <aside class="sidebar">
            <nav>
                <ul class="nav-menu">
                    <li class="nav-item">
                        <div class="nav-link active" data-section="dashboard">
                            <i class="fas fa-tachometer-alt"></i>
                            Dashboard
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="campaigns">
                            <i class="fas fa-bullseye"></i>
                            Campañas Activas
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="iocs">
                            <i class="fas fa-search"></i>
                            IOCs en Vivo
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="alerts">
                            <i class="fas fa-exclamation-triangle"></i>
                            Centro de Alertas
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="cves">
                            <i class="fas fa-bug"></i>
                            CVEs Recientes
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="search">
                            <i class="fas fa-search-plus"></i>
                            Búsqueda IOCs
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="malware">
                            <i class="fas fa-virus"></i>
                            MalwareBazaar
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="otx">
                            <i class="fas fa-satellite-dish"></i>
                            OTX Pulses
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="export">
                            <i class="fas fa-download"></i>
                            Exportar Datos
                        </div>
                    </li>
                </ul>
            </nav>
        </aside>

        <main class="content">
            <div id="dashboard" class="section active">
                <div class="stats-mini-grid">
                    <div class="mini-stat">
                        <div class="mini-stat-value" id="totalCampaigns">{{ stats.total_campaigns }}</div>
                        <div class="mini-stat-label">Campañas Activas</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value" id="totalIOCs">{{ stats.total_iocs }}</div>
                        <div class="mini-stat-label">IOCs Reales</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value" id="criticalAlerts">{{ stats.campaigns_by_severity.get('critical', 0) }}</div>
                        <div class="mini-stat-label">Alertas Críticas</div>
                    </div>
                    <div class="mini-stat">
                        <div class="mini-stat-value" id="countriesAffected">{{ stats.iocs_by_country|length }}</div>
                        <div class="mini-stat-label">Países Afectados</div>
                    </div>
                </div>

                <div class="dashboard-grid">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-pie card-icon"></i>
                            <h3 class="card-title">Distribución por Severidad</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-bar card-icon"></i>
                            <h3 class="card-title">Fuentes de Inteligencia</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="sourceChart"></canvas>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-globe-americas card-icon"></i>
                            <h3 class="card-title">IOCs por País</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="countryChart"></canvas>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-virus card-icon"></i>
                            <h3 class="card-title">Familias de Malware</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="malwareChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-bell card-icon"></i>
                        <h3 class="card-title">Alertas Críticas Recientes</h3>
                    </div>
                    <div id="dashboardAlerts">
                        <div class="loading"></div> Cargando alertas...
                    </div>
                </div>
            </div>

            <div id="campaigns" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-bullseye"></i> Campañas de Amenaza Detectadas
                </h2>
                
                <div class="filters">
                    <div class="filter-group">
                        <label class="filter-label">Buscar Campaña</label>
                        <input type="text" id="campaignSearch" class="filter-input" placeholder="Buscar por nombre...">
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">Severidad</label>
                        <select class="filter-select" id="campaignSeverityFilter">
                            <option value="">Todas las severidades</option>
                            <option value="critical">Crítica</option>
                            <option value="high">Alta</option>
                            <option value="medium">Media</option>
                            <option value="low">Baja</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">País</label>
                        <select class="filter-select" id="campaignCountryFilter">
                            <option value="">Todos los países</option>
                            <option value="brazil">Brasil</option>
                            <option value="mexico">México</option>
                            <option value="argentina">Argentina</option>
                            <option value="colombia">Colombia</option>
                            <option value="chile">Chile</option>
                            <option value="peru">Perú</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <button class="action-btn" onclick="loadCampaigns()">
                            <i class="fas fa-sync"></i>
                            Actualizar
                        </button>
                    </div>
                </div>

                <div id="campaignsTable">
                    <div class="loading"></div> Cargando campañas...
                </div>
            </div>

            <div id="iocs" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-search"></i> Indicadores de Compromiso (IOCs)
                </h2>
                
                <div class="filters">
                    <div class="filter-group">
                        <label class="filter-label">Tipo de IOC</label>
                        <select class="filter-select" id="iocTypeFilter">
                            <option value="">Todos los tipos</option>
                            <option value="url">URLs Maliciosas</option>
                            <option value="domain">Dominios</option>
                            <option value="ip">Direcciones IP</option>
                            <option value="hash_sha256">Hashes SHA256</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">Confianza Mínima</label>
                        <select class="filter-select" id="iocConfidenceFilter">
                            <option value="">Cualquier confianza</option>
                            <option value="90">≥ 90% (Muy Alta)</option>
                            <option value="80">≥ 80% (Alta)</option>
                            <option value="70">≥ 70% (Media)</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <button class="action-btn" onclick="loadIOCs()">
                            <i class="fas fa-sync"></i>
                            Actualizar IOCs
                        </button>
                    </div>
                </div>

                <div id="iocsTable">
                    <div class="loading"></div> Cargando IOCs...
                </div>
            </div>

            <div id="alerts" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-exclamation-triangle"></i> Centro de Alertas
                </h2>
                
                <div id="detailedAlertsContainer">
                    <div class="loading"></div> Cargando alertas...
                </div>
            </div>

            <div id="export" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-download"></i> Exportar Datos
                </h2>
                
                <div class="dashboard-grid">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-file-csv card-icon"></i>
                            <h3 class="card-title">Exportar a CSV</h3>
                        </div>
                        <p style="color: #a0aec0; margin-bottom: 1rem;">
                            Descarga todos los IOCs y campañas en formato CSV
                        </p>
                        <button class="action-btn" onclick="exportData('csv')">
                            <i class="fas fa-file-csv"></i>
                            Descargar CSV
                        </button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-file-code card-icon"></i>
                            <h3 class="card-title">Exportar JSON</h3>
                        </div>
                        <p style="color: #a0aec0; margin-bottom: 1rem;">
                            Formato compatible con otras plataformas
                        </p>
                        <button class="action-btn" onclick="exportData('json')">
                            <i class="fas fa-file-code"></i>
                            Descargar JSON
                        </button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-cogs card-icon"></i>
                            <h3 class="card-title">Ejecutar Scraping</h3>
                        </div>
                        <p style="color: #a0aec0; margin-bottom: 1rem;">
                            Recolectar datos en tiempo real de fuentes
                        </p>
                        <button class="action-btn" onclick="runScraping()" id="scrapingBtn">
                            <i class="fas fa-download"></i>
                            Ejecutar Scraping
                        </button>
                        <div id="scrapingStatus" style="margin-top: 1rem;"></div>
                    </div>
                </div>
            </div>

            <!-- Nueva sección CVEs -->
            <div id="cves" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-bug"></i> CVEs Recientes - NVD
                </h2>
                
                <div class="filters">
                    <div class="filter-group">
                        <label class="filter-label">Severidad CVSS</label>
                        <select class="filter-select" id="cveSeverityFilter">
                            <option value="">Todas las severidades</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">Días atrás</label>
                        <select class="filter-select" id="cveDaysFilter">
                            <option value="7">7 días</option>
                            <option value="14">14 días</option>
                            <option value="30">30 días</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <button class="action-btn" onclick="loadCVEs()">
                            <i class="fas fa-sync"></i> Actualizar CVEs
                        </button>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-bug card-icon"></i>
                        <h3 class="card-title">Vulnerabilidades Críticas</h3>
                    </div>
                    <div id="cvesContainer">
                        <div class="loading"></div> Cargando CVEs...
                    </div>
                </div>
            </div>

            <!-- Nueva sección búsqueda IOCs -->
            <div id="search" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-search-plus"></i> Búsqueda Manual de IOCs
                </h2>
                
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-search card-icon"></i>
                        <h3 class="card-title">Buscar en Múltiples Fuentes</h3>
                    </div>
                    
                    <div class="filters" style="margin: 1rem;">
                        <div class="filter-group">
                            <label class="filter-label">Tipo de IOC</label>
                            <select class="filter-select" id="iocTypeSelect">
                                <option value="ip">Dirección IP</option>
                                <option value="domain">Dominio</option>
                                <option value="url">URL</option>
                                <option value="hash_md5">Hash MD5</option>
                                <option value="hash_sha1">Hash SHA1</option>
                                <option value="hash_sha256">Hash SHA256</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label class="filter-label">Valor del IOC</label>
                            <input type="text" class="filter-input" id="iocValueInput" placeholder="Ingrese IP, dominio, hash, etc." style="min-width: 300px;">
                        </div>
                        <div class="filter-group">
                            <button class="action-btn" onclick="searchIOC()" id="searchBtn">
                                <i class="fas fa-search"></i> Buscar IOC
                            </button>
                        </div>
                    </div>
                    
                    <div id="iocSearchResults" style="margin: 1rem;">
                        <p style="color: #a0aec0; text-align: center;">
                            <i class="fas fa-info-circle"></i> 
                            Ingrese un IOC para buscarlo en VirusTotal, IBM X-Force y otras fuentes
                        </p>
                    </div>
                </div>
            </div>

            <!-- Nueva sección MalwareBazaar -->
            <div id="malware" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-virus"></i> MalwareBazaar - Muestras LATAM
                </h2>
                
                <div class="filters">
                    <div class="filter-group">
                        <label class="filter-label">Familia de Malware</label>
                        <select class="filter-select" id="malwareFamilyFilter">
                            <option value="">Todas las familias</option>
                            <option value="mekotio">Mekotio</option>
                            <option value="grandoreiro">Grandoreiro</option>
                            <option value="casbaneiro">Casbaneiro</option>
                            <option value="amavaldo">Amavaldo</option>
                            <option value="javali">Javali</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label class="filter-label">País</label>
                        <select class="filter-select" id="malwareCountryFilter">
                            <option value="">Todos los países</option>
                            <option value="brazil">Brasil</option>
                            <option value="mexico">México</option>
                            <option value="argentina">Argentina</option>
                            <option value="chile">Chile</option>
                            <option value="colombia">Colombia</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <button class="action-btn" onclick="loadMalwareSamples()">
                            <i class="fas fa-sync"></i> Actualizar Muestras
                        </button>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-virus card-icon"></i>
                        <h3 class="card-title">Muestras de Malware Recientes</h3>
                    </div>
                    <div id="malwareSamplesContainer">
                        <div class="loading"></div> Cargando muestras de malware...
                    </div>
                </div>
            </div>

            <!-- Nueva sección OTX -->
            <div id="otx" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-satellite-dish"></i> OTX AlienVault - Pulsos LATAM
                </h2>
                
                <div class="filters">
                    <div class="filter-group">
                        <button class="action-btn" onclick="loadOTXPulses()">
                            <i class="fas fa-sync"></i> Actualizar Pulsos
                        </button>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-satellite-dish card-icon"></i>
                        <h3 class="card-title">Pulsos de Amenazas Recientes</h3>
                    </div>
                    <div id="otxPulsesContainer">
                        <div class="loading"></div> Cargando pulsos de OTX...
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script type="text/javascript">
        console.log('🚀 AEGIS Dashboard JavaScript cargado:', new Date().toISOString());
        const COLORS = {
            primary: '#00ff7f',
            critical: '#ff453a',
            high: '#ff9500',
            medium: '#ffcc02',
            low: '#30d158',
            background: '#1a2332'
        };

        let dashboardData = null;
        let currentSection = 'dashboard';

        // Función de inicialización
        function initializeDashboard() {
            console.log('🚀 Inicializando AEGIS Dashboard...');
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', initializeDashboard);
                return;
            }
            
            setTimeout(() => {
                setupNavigation();
                loadDashboardData();
                startAutoRefresh();
                setupEventListeners();
                console.log('✅ Dashboard inicializado correctamente');
            }, 100);
        }

        // Configurar navegación
        function setupNavigation() {
            console.log('🔧 Configurando navegación...');
            
            const navigationLinks = document.querySelectorAll('.nav-link');
            
            navigationLinks.forEach((link) => {
                const sectionId = link.dataset.section;
                
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log(`🖱️ Click en sección: "${sectionId}"`);
                    showSection(sectionId);
                });
            });
            
            console.log(`✅ Navegación configurada: ${navigationLinks.length} enlaces`);
        }

        // Mostrar sección
        function showSection(sectionId) {
            console.log(`📱 Mostrando sección: ${sectionId}`);
            
            try {
                // Remover clase active de todas las secciones
                const sections = document.querySelectorAll('.section');
                sections.forEach(section => {
                    section.classList.remove('active');
                });
                
                // Mostrar la sección seleccionada
                const targetSection = document.getElementById(sectionId);
                if (!targetSection) {
                    console.error(`❌ Sección no encontrada: ${sectionId}`);
                    return;
                }
                
                targetSection.classList.add('active');
                
                // Actualizar navegación visual
                const navLinks = document.querySelectorAll('.nav-link');
                navLinks.forEach(link => {
                    link.classList.remove('active');
                });
                
                const activeNavLink = document.querySelector(`[data-section="${sectionId}"]`);
                if (activeNavLink) {
                    activeNavLink.classList.add('active');
                }
                
                currentSection = sectionId;
                
                // Ejecutar función específica de la sección
                switch(sectionId) {
                    case 'dashboard':
                        loadDashboardData();
                        break;
                    case 'campaigns':
                        loadCampaigns();
                        break;
                    case 'iocs':
                        loadIOCs();
                        break;
                    case 'alerts':
                        loadAlerts();
                        break;
                    case 'export':
                        break;
                }
                
                console.log(`✅ Sección ${sectionId} cargada exitosamente`);
                
            } catch (error) {
                console.error(`❌ Error mostrando sección ${sectionId}:`, error);
            }
        }
        
        function setupEventListeners() {
            // Event listener para búsqueda de campaña
            const searchInput = document.getElementById('campaignSearch');
            if (searchInput) {
                let timeout;
                searchInput.addEventListener('input', function() {
                    clearTimeout(timeout);
                    timeout = setTimeout(loadCampaigns, 500);
                });
            }
            
            // Event listeners para filtros
            ['campaignSeverityFilter', 'campaignCountryFilter', 'iocTypeFilter', 'iocConfidenceFilter'].forEach(id => {
                const element = document.getElementById(id);
                if (element) {
                    element.addEventListener('change', () => {
                        if (id.startsWith('campaign')) {
                            loadCampaigns();
                        } else {
                            loadIOCs();
                        }
                    });
                }
            });
            
            console.log('✅ Event listeners configurados');
        }

        async function loadDashboardData() {
            try {
                console.log('🔄 Cargando datos del dashboard...');
                
                const response = await fetch('/api/stats');
                dashboardData = await response.json();
                
                console.log('📊 Datos del dashboard cargados:', dashboardData);
                
                updateDashboardStats();
                initCharts();
                
                await loadDashboardAlerts();
                
                console.log('✅ Todos los datos cargados correctamente');
                
            } catch (error) {
                console.error('❌ Error cargando datos:', error);
                const errorMsg = `<p style="color: #ff453a;">Error cargando datos: ${error.message}</p>`;
                const alertsContainer = document.getElementById('dashboardAlerts');
                if (alertsContainer) {
                    alertsContainer.innerHTML = errorMsg;
                }
            }
        }

        function updateDashboardStats() {
            if (!dashboardData) return;
            
            const updateElement = (id, value) => {
                const element = document.getElementById(id);
                if (element) element.textContent = value;
            };
            
            updateElement('totalCampaigns', dashboardData.total_campaigns || 0);
            updateElement('totalIOCs', dashboardData.total_iocs || 0);
            updateElement('criticalAlerts', dashboardData.campaigns_by_severity?.critical || 0);
            updateElement('countriesAffected', Object.keys(dashboardData.iocs_by_country || {}).length);
        }

        function initCharts() {
            if (!dashboardData) return;
            
            try {
                // Gráfica de severidad
                const severityCtx = document.getElementById('severityChart');
                if (severityCtx) {
                    new Chart(severityCtx.getContext('2d'), {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(dashboardData.campaigns_by_severity || {}),
                            datasets: [{
                                data: Object.values(dashboardData.campaigns_by_severity || {}),
                                backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low],
                                borderWidth: 2,
                                borderColor: COLORS.background
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: { color: '#ffffff' }
                                }
                            }
                        }
                    });
                }

                // Gráfica de fuentes
                const sourceCtx = document.getElementById('sourceChart');
                if (sourceCtx) {
                    new Chart(sourceCtx.getContext('2d'), {
                        type: 'bar',
                        data: {
                            labels: Object.keys(dashboardData.campaigns_by_source || {}),
                            datasets: [{
                                label: 'Campañas',
                                data: Object.values(dashboardData.campaigns_by_source || {}),
                                backgroundColor: COLORS.primary + '80',
                                borderColor: COLORS.primary,
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: { color: '#ffffff' },
                                    grid: { color: '#2d3748' }
                                },
                                x: {
                                    ticks: { color: '#ffffff' },
                                    grid: { color: '#2d3748' }
                                }
                            },
                            plugins: {
                                legend: { labels: { color: '#ffffff' } }
                            }
                        }
                    });
                }

                // Gráfica de países
                const countryCtx = document.getElementById('countryChart');
                if (countryCtx) {
                    new Chart(countryCtx.getContext('2d'), {
                        type: 'polarArea',
                        data: {
                            labels: Object.keys(dashboardData.iocs_by_country || {}),
                            datasets: [{
                                data: Object.values(dashboardData.iocs_by_country || {}),
                                backgroundColor: [
                                    COLORS.primary + '80',
                                    COLORS.high + '80',
                                    COLORS.medium + '80',
                                    COLORS.low + '80'
                                ],
                                borderColor: COLORS.primary,
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: { color: '#ffffff' }
                                }
                            },
                            scales: {
                                r: {
                                    ticks: { color: '#ffffff' },
                                    grid: { color: '#2d3748' }
                                }
                            }
                        }
                    });
                }

                // Gráfica de malware
                const malwareCtx = document.getElementById('malwareChart');
                if (malwareCtx) {
                    new Chart(malwareCtx.getContext('2d'), {
                        type: 'bar',
                        data: {
                            labels: Object.keys(dashboardData.malware_families || {}),
                            datasets: [{
                                label: 'Detecciones',
                                data: Object.values(dashboardData.malware_families || {}),
                                backgroundColor: COLORS.critical + '80',
                                borderColor: COLORS.critical,
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: { color: '#ffffff' },
                                    grid: { color: '#2d3748' }
                                },
                                x: {
                                    ticks: { color: '#ffffff' },
                                    grid: { color: '#2d3748' }
                                }
                            },
                            plugins: {
                                legend: { labels: { color: '#ffffff' } }
                            }
                        }
                    });
                }
            } catch (error) {
                console.error('Error inicializando gráficas:', error);
            }
        }

        async function loadDashboardAlerts() {
            const container = document.getElementById('dashboardAlerts');
            if (!container) return;

            try {
                container.innerHTML = '<div class="loading"></div> Cargando alertas...';
                
                const response = await fetch('/api/alerts');
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const alerts = await response.json();
                
                if (!Array.isArray(alerts) || alerts.length === 0) {
                    container.innerHTML = `
                        <div style="padding: 1rem; text-align: center; color: #a0aec0;">
                            <i class="fas fa-shield-alt" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                            <p>No hay alertas críticas actualmente</p>
                            <p style="font-size: 0.8rem;">El sistema está monitoreando amenazas...</p>
                        </div>
                    `;
                    return;
                }

                container.innerHTML = alerts.slice(0, 5).map(alert => `
                    <div class="alert-item">
                        <div class="alert-header">
                            <span class="alert-title">${alert.title || 'Alerta'}</span>
                            <span class="alert-time">${alert.timestamp ? formatTimestamp(alert.timestamp) : 'Reciente'}</span>
                        </div>
                        <p style="margin: 0; color: #a0aec0; font-size: 0.9rem;">${alert.description || 'Sin descripción'}</p>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Error cargando alertas:', error);
                container.innerHTML = `
                    <div style="padding: 1rem; text-align: center; color: #ff9500;">
                        <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <p>Error cargando alertas</p>
                        <button class="action-btn" onclick="loadDashboardAlerts()" style="margin-top: 0.5rem; font-size: 0.8rem;">
                            <i class="fas fa-sync"></i> Reintentar
                        </button>
                    </div>
                `;
            }
        }

        async function loadCampaigns() {
            try {
                const container = document.getElementById('campaignsTable');
                if (!container) return;
                
                container.innerHTML = '<div class="loading"></div> Cargando campañas...';
                
                const params = new URLSearchParams();
                const search = document.getElementById('campaignSearch')?.value;
                const severity = document.getElementById('campaignSeverityFilter')?.value;
                const country = document.getElementById('campaignCountryFilter')?.value;
                
                if (search) params.append('q', search);
                if (severity) params.append('severity', severity);
                if (country) params.append('country', country);
                
                const response = await fetch(`/api/campaigns?${params}`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const campaigns = await response.json();
                
                if (campaigns.length === 0) {
                    container.innerHTML = '<p style="color: #a0aec0;">No se encontraron campañas</p>';
                    return;
                }
                
                container.innerHTML = `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Nombre de Campaña</th>
                                <th>Severidad</th>
                                <th>Países Afectados</th>
                                <th>IOCs</th>
                                <th>Fuente</th>
                                <th>Última Actividad</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${campaigns.map(campaign => `
                                <tr>
                                    <td>
                                        <strong>${campaign.name}</strong>
                                        <div style="font-size: 0.8rem; color: #a0aec0; margin-top: 0.25rem;">
                                            ${campaign.description.substring(0, 80)}...
                                        </div>
                                    </td>
                                    <td><span class="severity-badge severity-${campaign.severity}">${campaign.severity}</span></td>
                                    <td>
                                        ${campaign.countries_affected.map(country => 
                                            `<span class="country-tag">${country}</span>`
                                        ).join('')}
                                    </td>
                                    <td><strong style="color: #00ff7f;">${campaign.iocs ? campaign.iocs.length : 0}</strong></td>
                                    <td style="font-family: monospace; color: #00ff7f;">${campaign.source}</td>
                                    <td style="font-size: 0.9rem;">${formatTimestamp(campaign.last_seen)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
                
            } catch (error) {
                console.error('❌ Error cargando campañas:', error);
                const container = document.getElementById('campaignsTable');
                if (container) {
                    container.innerHTML = `<p style="color: #ff453a;">Error cargando campañas: ${error.message}</p>`;
                }
            }
        }

        async function loadIOCs() {
            try {
                const container = document.getElementById('iocsTable');
                if (!container) return;
                
                container.innerHTML = '<div class="loading"></div> Cargando IOCs...';
                
                const params = new URLSearchParams();
                const typeFilter = document.getElementById('iocTypeFilter')?.value;
                const confidenceFilter = document.getElementById('iocConfidenceFilter')?.value;
                const limit = '100';
                
                if (typeFilter) params.append('type', typeFilter);
                if (confidenceFilter) params.append('confidence', confidenceFilter);
                params.append('limit', limit);
                
                const response = await fetch(`/api/iocs?${params}`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const allIOCs = await response.json();
                
                if (allIOCs.length === 0) {
                    container.innerHTML = '<p style="color: #a0aec0;">No se encontraron IOCs</p>';
                    return;
                }
                
                allIOCs.sort((a, b) => b.confidence - a.confidence);
                
                container.innerHTML = `
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Valor del IOC</th>
                                <th>Tipo</th>
                                <th>Confianza</th>
                                <th>País</th>
                                <th>Fuente</th>
                                <th>Campaña</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${allIOCs.slice(0, 100).map(ioc => `
                                <tr>
                                    <td>
                                        <div class="ioc-value">${ioc.value}</div>
                                    </td>
                                    <td>
                                        <span style="background: rgba(0, 255, 127, 0.2); color: #00ff7f; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem;">
                                            ${ioc.type.toUpperCase()}
                                        </span>
                                    </td>
                                    <td>
                                        <span style="color: ${ioc.confidence >= 80 ? '#00ff7f' : ioc.confidence >= 60 ? '#ffcc02' : '#ff9500'}; font-weight: bold;">
                                            ${ioc.confidence}%
                                        </span>
                                    </td>
                                    <td>
                                        ${ioc.country ? `<span class="country-tag">${ioc.country}</span>` : '-'}
                                    </td>
                                    <td style="font-family: monospace; color: #00ff7f; font-size: 0.9rem;">
                                        ${ioc.source}
                                    </td>
                                    <td style="font-size: 0.9rem; color: #a0aec0;">
                                        ${ioc.campaign_name ? ioc.campaign_name.substring(0, 30) + '...' : '-'}
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
                
            } catch (error) {
                console.error('❌ Error cargando IOCs:', error);
                const container = document.getElementById('iocsTable');
                if (container) {
                    container.innerHTML = `<p style="color: #ff453a;">Error cargando IOCs: ${error.message}</p>`;
                }
            }
        }

        async function loadAlerts() {
            try {
                const container = document.getElementById('detailedAlertsContainer');
                if (!container) return;
                
                container.innerHTML = '<div class="loading"></div> Cargando alertas...';
                
                const response = await fetch('/api/alerts');
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const alerts = await response.json();
                
                if (alerts.length === 0) {
                    container.innerHTML = '<p style="color: #a0aec0;">No hay alertas actualmente</p>';
                    return;
                }
                
                container.innerHTML = alerts.map(alert => `
                    <div class="alert-item">
                        <div class="alert-header">
                            <span class="alert-title">${alert.title}</span>
                            <span class="alert-time">${formatTimestamp(alert.timestamp)}</span>
                        </div>
                        <p style="margin: 0.5rem 0; color: #ffffff;">${alert.description}</p>
                        <div style="display: flex; gap: 1rem; align-items: center; margin-top: 1rem; flex-wrap: wrap;">
                            <span style="background: rgba(0, 255, 127, 0.2); color: #00ff7f; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem;">
                                Tipo: ${alert.type.replace('_', ' ').toUpperCase()}
                            </span>
                            ${alert.countries ? `
                                <span style="background: rgba(255, 149, 0, 0.2); color: #ff9500; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem;">
                                    Países: ${alert.countries.join(', ')}
                                </span>
                            ` : ''}
                        </div>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Error cargando alertas:', error);
                const container = document.getElementById('detailedAlertsContainer');
                if (container) {
                    container.innerHTML = '<p style="color: #ff453a;">Error cargando alertas</p>';
                }
            }
        }

        async function runScraping() {
            try {
                const button = document.getElementById('scrapingBtn');
                const status = document.getElementById('scrapingStatus');
                
                if (!button || !status) return;
                
                button.innerHTML = '<div class="loading"></div> Ejecutando Scraping...';
                button.disabled = true;
                
                status.innerHTML = '<div style="color: #00ff7f;">Conectando a fuentes de threat intelligence...</div>';
                
                const response = await fetch('/api/scrape', { method: 'POST' });
                const result = await response.json();
                
                if (result.success) {
                    status.innerHTML = `
                        <div style="color: #30d158;">
                            Scraping completado: ${result.stored_campaigns} campañas nuevas detectadas
                        </div>
                    `;
                    
                    await loadDashboardData();
                    if (currentSection === 'campaigns') {
                        await loadCampaigns();
                    }
                } else {
                    status.innerHTML = `
                        <div style="color: #ff453a;">
                            Error en scraping: ${result.message}
                        </div>
                    `;
                }
                
                button.innerHTML = '<i class="fas fa-download"></i> Ejecutar Scraping';
                button.disabled = false;
                
            } catch (error) {
                console.error('Error ejecutando scraping:', error);
                const status = document.getElementById('scrapingStatus');
                if (status) {
                    status.innerHTML = `<div style="color: #ff453a;">Error de conexión: ${error.message}</div>`;
                }
                
                const button = document.getElementById('scrapingBtn');
                if (button) {
                    button.innerHTML = '<i class="fas fa-download"></i> Ejecutar Scraping';
                    button.disabled = false;
                }
            }
        }

        function exportData(format) {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            window.open(`/api/export/${format}?timestamp=${timestamp}`, '_blank');
        }

        function startAutoRefresh() {
            setInterval(async () => {
                try {
                    const indicator = document.querySelector('.real-data-indicator span');
                    if (indicator) {
                        indicator.textContent = `SISTEMA REAL - ${new Date().toLocaleTimeString()}`;
                    }
                    
                    if (currentSection === 'dashboard') {
                        const response = await fetch('/api/stats');
                        const newData = await response.json();
                        
                        if (JSON.stringify(newData) !== JSON.stringify(dashboardData)) {
                            dashboardData = newData;
                            updateDashboardStats();
                            loadDashboardAlerts();
                        }
                    }
                    
                } catch (error) {
                    console.error('Error en actualización automática:', error);
                }
            }, 30000);
        }

        function formatTimestamp(timestamp) {
            try {
                if (!timestamp) return 'Sin fecha';
                
                const date = new Date(timestamp);
                if (isNaN(date.getTime())) {
                    return 'Fecha inválida';
                }
                
                return date.toLocaleString('es-ES', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            } catch (error) {
                console.error('Error formateando timestamp:', error);
                return 'Error en fecha';
            }
        }

        // ===== NUEVAS FUNCIONES PARA LAS APIS REALES =====

        async function loadCVEs() {
            try {
                const severityFilter = document.getElementById('cveSeverityFilter').value;
                const daysFilter = document.getElementById('cveDaysFilter').value;
                
                const params = new URLSearchParams();
                if (severityFilter) params.append('severity', severityFilter);
                params.append('days', daysFilter);
                params.append('limit', '50');
                
                const response = await fetch(`/api/cves?${params}`);
                const cves = await response.json();
                
                displayCVEs(cves);
            } catch (error) {
                console.error('Error cargando CVEs:', error);
                document.getElementById('cvesContainer').innerHTML = 
                    '<p style="color: #ff6b6b;">Error cargando CVEs. Verifique la configuración de NVD API.</p>';
            }
        }

        function displayCVEs(cves) {
            const container = document.getElementById('cvesContainer');
            
            if (!cves || cves.length === 0) {
                container.innerHTML = '<p style="color: #a0aec0;">No se encontraron CVEs para los criterios seleccionados.</p>';
                return;
            }
            
            let html = '<table class="data-table"><thead><tr>';
            html += '<th>CVE ID</th><th>Severidad</th><th>Score CVSS</th><th>Fecha</th><th>Descripción</th>';
            html += '</tr></thead><tbody>';
            
            cves.forEach(cve => {
                const severityClass = cve.cvss_severity ? `severity-${cve.cvss_severity}` : 'severity-low';
                html += `<tr>
                    <td><strong>${cve.id}</strong></td>
                    <td><span class="severity-badge ${severityClass}">${cve.cvss_severity || 'N/A'}</span></td>
                    <td>${cve.cvss_score || 'N/A'}</td>
                    <td>${formatTimestamp(cve.published_date)}</td>
                    <td style="max-width: 400px;">${cve.description.substring(0, 200)}${cve.description.length > 200 ? '...' : ''}</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        async function searchIOC() {
            const iocValue = document.getElementById('iocValueInput').value.trim();
            const iocType = document.getElementById('iocTypeSelect').value;
            const resultsContainer = document.getElementById('iocSearchResults');
            const searchBtn = document.getElementById('searchBtn');
            
            if (!iocValue) {
                alert('Por favor ingrese un valor de IOC');
                return;
            }
            
            searchBtn.disabled = true;
            searchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Buscando...';
            
            try {
                const response = await fetch('/api/search_ioc', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        ioc: iocValue,
                        type: iocType
                    })
                });
                
                const result = await response.json();
                displayIOCResults(result);
                
            } catch (error) {
                console.error('Error buscando IOC:', error);
                resultsContainer.innerHTML = '<p style="color: #ff6b6b;">Error en la búsqueda. Verifique las API keys.</p>';
            } finally {
                searchBtn.disabled = false;
                searchBtn.innerHTML = '<i class="fas fa-search"></i> Buscar IOC';
            }
        }

        function displayIOCResults(result) {
            const container = document.getElementById('iocSearchResults');
            
            if (!result || result.error) {
                container.innerHTML = `<p style="color: #ff6b6b;">Error: ${result?.error || 'Error desconocido'}</p>`;
                return;
            }
            
            let html = `
                <div style="margin-bottom: 2rem;">
                    <h4 style="color: #00ff7f; margin-bottom: 1rem;">
                        Resultados para: ${result.ioc} (${result.type})
                    </h4>
                    <div style="background: rgba(0,255,127,0.1); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                        <strong>Resumen:</strong> 
                        ${result.summary.malicious}/${result.summary.total_engines} fuentes reportan como malicioso
                        (Confianza: ${result.summary.confidence}%)
                    </div>
                </div>
            `;
            
            // VirusTotal results
            if (result.sources.virustotal) {
                const vt = result.sources.virustotal;
                html += `
                    <div class="card" style="margin-bottom: 1rem;">
                        <div class="card-header">
                            <h4>VirusTotal</h4>
                        </div>
                        <div style="padding: 1rem;">
                `;
                
                if (vt.error) {
                    html += `<p style="color: #ff6b6b;">Error: ${vt.error}</p>`;
                } else {
                    html += `
                        <p><strong>Malicioso:</strong> ${vt.malicious || 0}</p>
                        <p><strong>Sospechoso:</strong> ${vt.suspicious || 0}</p>
                        <p><strong>Inofensivo:</strong> ${vt.harmless || 0}</p>
                        <p><strong>Total motores:</strong> ${vt.total_engines || 0}</p>
                    `;
                }
                html += '</div></div>';
            }
            
            // IBM X-Force results
            if (result.sources.xforce) {
                const xf = result.sources.xforce;
                html += `
                    <div class="card" style="margin-bottom: 1rem;">
                        <div class="card-header">
                            <h4>IBM X-Force</h4>
                        </div>
                        <div style="padding: 1rem;">
                `;
                
                if (xf.error) {
                    html += `<p style="color: #ff6b6b;">Error: ${xf.error}</p>`;
                } else {
                    html += `
                        <p><strong>Malicioso:</strong> ${xf.malicious ? 'Sí' : 'No'}</p>
                        <p><strong>Score:</strong> ${xf.score || 'N/A'}</p>
                        ${xf.country ? `<p><strong>País:</strong> ${xf.country}</p>` : ''}
                    `;
                }
                html += '</div></div>';
            }
            
            container.innerHTML = html;
        }

        async function loadMalwareSamples() {
            try {
                const familyFilter = document.getElementById('malwareFamilyFilter').value;
                const countryFilter = document.getElementById('malwareCountryFilter').value;
                
                const params = new URLSearchParams();
                if (familyFilter) params.append('family', familyFilter);
                if (countryFilter) params.append('country', countryFilter);
                params.append('limit', '30');
                
                const response = await fetch(`/api/malware_samples?${params}`);
                const samples = await response.json();
                
                displayMalwareSamples(samples);
            } catch (error) {
                console.error('Error cargando muestras de malware:', error);
                document.getElementById('malwareSamplesContainer').innerHTML = 
                    '<p style="color: #ff6b6b;">Error cargando muestras de MalwareBazaar.</p>';
            }
        }

        function displayMalwareSamples(samples) {
            const container = document.getElementById('malwareSamplesContainer');
            
            if (!samples || samples.length === 0) {
                container.innerHTML = '<p style="color: #a0aec0;">No se encontraron muestras para los criterios seleccionados.</p>';
                return;
            }
            
            let html = '<table class="data-table"><thead><tr>';
            html += '<th>SHA256</th><th>Familia</th><th>País</th><th>Última Vista</th><th>Confianza</th>';
            html += '</tr></thead><tbody>';
            
            samples.forEach(sample => {
                html += `<tr>
                    <td><code style="font-size: 0.8rem;">${sample.sha256.substring(0, 16)}...</code></td>
                    <td><strong>${sample.malware_family || 'N/A'}</strong></td>
                    <td>${sample.country || 'N/A'}</td>
                    <td>${formatTimestamp(sample.last_seen)}</td>
                    <td>${sample.confidence}%</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        async function loadOTXPulses() {
            try {
                const response = await fetch('/api/otx_pulses?limit=20');
                const pulses = await response.json();
                
                displayOTXPulses(pulses);
            } catch (error) {
                console.error('Error cargando pulsos de OTX:', error);
                document.getElementById('otxPulsesContainer').innerHTML = 
                    '<p style="color: #ff6b6b;">Error cargando pulsos de OTX. Verifique la configuración de API.</p>';
            }
        }

        function displayOTXPulses(pulses) {
            const container = document.getElementById('otxPulsesContainer');
            
            if (!pulses || pulses.length === 0) {
                container.innerHTML = '<p style="color: #a0aec0;">No se encontraron pulsos recientes.</p>';
                return;
            }
            
            let html = '';
            
            pulses.forEach(pulse => {
                html += `
                    <div class="card" style="margin-bottom: 1rem;">
                        <div class="card-header">
                            <h4>${pulse.name}</h4>
                            <span class="severity-badge severity-${pulse.severity}">${pulse.severity}</span>
                        </div>
                        <div style="padding: 1rem;">
                            <p style="color: #a0aec0; margin-bottom: 1rem;">${pulse.description}</p>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                                <div>
                                    <strong>Autor:</strong> ${pulse.author || 'N/A'}<br>
                                    <strong>IOCs:</strong> ${pulse.ioc_count}<br>
                                    <strong>Países:</strong> ${pulse.countries_affected.join(', ')}
                                </div>
                                <div>
                                    <strong>Creado:</strong> ${formatTimestamp(pulse.created)}<br>
                                    <strong>Modificado:</strong> ${formatTimestamp(pulse.modified)}<br>
                                    <strong>Familias:</strong> ${pulse.malware_families.join(', ') || 'N/A'}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }

        // Cargar datos automáticamente al cambiar a las nuevas secciones
        document.addEventListener('DOMContentLoaded', function() {
            const navLinks = document.querySelectorAll('.nav-link');
            
            navLinks.forEach(link => {
                link.addEventListener('click', function() {
                    const section = this.getAttribute('data-section');
                    
                    // Cargar datos automáticamente para nuevas secciones
                    setTimeout(() => {
                        switch(section) {
                            case 'cves':
                                loadCVEs();
                                break;
                            case 'malware':
                                loadMalwareSamples();
                                break;
                            case 'otx':
                                loadOTXPulses();
                                break;
                        }
                    }, 100);
                });
            });
        });

        // Agregar event listener para Enter en búsqueda de IOCs
        document.addEventListener('DOMContentLoaded', function() {
            const iocInput = document.getElementById('iocValueInput');
            if (iocInput) {
                iocInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        searchIOC();
                    }
                });
            }
        });

        // Inicializar dashboard
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeDashboard);
        } else {
            initializeDashboard();
        }
    </script>
</body>
</html>
    '''
    
    @app.route('/')
    def dashboard():
        """Dashboard principal con datos reales"""
        try:
            stats = storage.get_statistics()
            return render_template_string(DASHBOARD_TEMPLATE, stats=stats)
        except Exception as e:
            logger.error(f"Error cargando dashboard: {e}")
            return f"Error cargando dashboard: {e}", 500
    
    @app.route('/api/campaigns')
    def api_campaigns():
        """API para obtener campañas reales"""
        try:
            query = request.args.get('q', '')
            filters = {}
            
            if request.args.get('severity'):
                filters['severity'] = request.args.get('severity')
            if request.args.get('country'):
                filters['country'] = request.args.get('country')
            
            campaigns = storage.search_campaigns(query, filters)
            return jsonify(campaigns)
            
        except Exception as e:
            logger.error(f"Error en API campañas: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/iocs')
    def api_iocs():
        """API para obtener IOCs (Indicators of Compromise)"""
        try:
            ioc_type = request.args.get('type', '')
            confidence = request.args.get('confidence', '')
            country = request.args.get('country', '')
            limit = int(request.args.get('limit', 100))
            
            iocs = storage.get_recent_iocs(limit=limit)
            
            # Aplicar filtros
            if ioc_type:
                iocs = [ioc for ioc in iocs if ioc.get('type') == ioc_type]
            
            if confidence:
                min_confidence = int(confidence)
                iocs = [ioc for ioc in iocs if ioc.get('confidence', 0) >= min_confidence]
            
            if country:
                iocs = [ioc for ioc in iocs if ioc.get('country', '').lower() == country.lower()]
            
            # Formatear respuesta
            formatted_iocs = []
            for ioc in iocs:
                formatted_ioc = {
                    'id': ioc.get('_id', str(ioc.get('id', ''))),
                    'value': ioc.get('value', ''),
                    'type': ioc.get('type', ''),
                    'confidence': ioc.get('confidence', 0),
                    'first_seen': ioc.get('first_seen', ''),
                    'last_seen': ioc.get('last_seen', ''),
                    'source': ioc.get('source', ''),
                    'tags': ioc.get('tags', []),
                    'threat_type': ioc.get('threat_type', ''),
                    'malware_family': ioc.get('malware_family', ''),
                    'country': ioc.get('country', ''),
                }
                formatted_iocs.append(formatted_ioc)
            
            return jsonify(formatted_iocs)
            
        except Exception as e:
            logger.error(f"Error en API IOCs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats')
    def api_stats():
        """API para estadísticas del sistema"""
        try:
            stats = storage.get_statistics()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error en API stats: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/alerts')
    def api_alerts():
        """API para alertas de seguridad"""
        try:
            campaigns = storage.search_campaigns("")
            
            campaign_objects = []
            for campaign_data in campaigns[:20]:
                try:
                    iocs = []
                    for ioc_data in campaign_data.get('iocs', []):
                        try:
                            first_seen = ioc_data['first_seen']
                            if isinstance(first_seen, str):
                                first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                            
                            last_seen = ioc_data['last_seen']
                            if isinstance(last_seen, str):
                                last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                            
                            ioc = IOC(
                                value=ioc_data['value'],
                                type=ioc_data['type'],
                                confidence=ioc_data['confidence'],
                                first_seen=first_seen,
                                last_seen=last_seen,
                                source=ioc_data['source'],
                                tags=ioc_data.get('tags', []),
                                threat_type=ioc_data.get('threat_type'),
                                malware_family=ioc_data.get('malware_family'),
                                country=ioc_data.get('country')
                            )
                            iocs.append(ioc)
                        except Exception as ioc_error:
                            logger.warning(f"Error procesando IOC: {ioc_error}")
                            continue
                    
                    first_seen = campaign_data['first_seen']
                    if isinstance(first_seen, str):
                        first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    
                    last_seen = campaign_data['last_seen']
                    if isinstance(last_seen, str):
                        last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    
                    campaign = Campaign(
                        id=campaign_data['id'],
                        name=campaign_data['name'],
                        description=campaign_data['description'],
                        countries_affected=campaign_data['countries_affected'],
                        threat_actor=campaign_data.get('threat_actor'),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        ttps=campaign_data.get('ttps', []),
                        iocs=iocs,
                        severity=campaign_data['severity'],
                        source=campaign_data['source'],
                        malware_families=campaign_data.get('malware_families', []),
                        target_sectors=campaign_data.get('target_sectors', [])
                    )
                    campaign_objects.append(campaign)
                except Exception as e:
                    logger.warning(f"Error procesando campaña para alertas: {e}")
                    continue
            
            alerts = alert_system.check_critical_indicators(campaign_objects)
            return jsonify(alerts)
            
        except Exception as e:
            logger.error(f"Error en API alertas: {e}")
            return jsonify([])
    
    @app.route('/api/export/<format>')
    def api_export(format):
        """API para exportar datos reales"""
        try:
            filters = {}
            campaigns = storage.search_campaigns("", filters)
            campaign_ids = [c['id'] for c in campaigns]
            
            timestamp = request.args.get('timestamp', datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
            
            if format.lower() == 'csv':
                csv_data = storage.export_to_csv(campaign_ids)
                return Response(
                    csv_data,
                    mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=aegis_data_{timestamp}.csv'}
                )
            elif format.lower() == 'json':
                json_data = json.dumps(campaigns, indent=2, default=str)
                return Response(
                    json_data,
                    mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename=aegis_data_{timestamp}.json'}
                )
            else:
                return jsonify({'error': 'Formato no soportado'}), 400
                
        except Exception as e:
            logger.error(f"Error exportando datos: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/scrape', methods=['POST'])
    def api_scrape():
        """API para ejecutar scraping real de fuentes"""
        try:
            logger.info("INICIANDO SCRAPING REAL DE FUENTES DE THREAT INTELLIGENCE...")
            
            campaigns = scraper.scrape_all_sources()
            
            stored_count = 0
            for campaign in campaigns:
                if storage.store_campaign(campaign):
                    stored_count += 1
            
            message = f'Scraping de fuentes completado exitosamente'
            
            logger.info(f"{message}: {stored_count} campañas nuevas almacenadas de {len(campaigns)} total")
            
            return jsonify({
                'message': message,
                'total_campaigns': len(campaigns),
                'stored_campaigns': stored_count,
                'success': True,
                'timestamp': datetime.utcnow().isoformat(),
                'sources_processed': list(set(c.source for c in campaigns))
            })
            
        except Exception as e:
            logger.error(f"Error en scraping real: {e}")
            return jsonify({
                'message': f'Error ejecutando scraping: {str(e)}',
                'success': False,
                'timestamp': datetime.utcnow().isoformat()
            }), 500

    @app.route('/api/cves')
    def api_cves():
        """API para obtener CVEs recientes"""
        try:
            days_back = int(request.args.get('days', 7))
            severity = request.args.get('severity', '')
            limit = int(request.args.get('limit', 50))
            
            cves = cve_integration.fetch_recent_cves(days_back)
            
            # Aplicar filtros
            if severity:
                cves = [cve for cve in cves if cve.cvss_severity.lower() == severity.lower()]
            
            # Limitar resultados
            cves = cves[:limit]
            
            # Formatear respuesta
            formatted_cves = []
            for cve in cves:
                formatted_cve = {
                    'id': cve.id,
                    'description': cve.description,
                    'published_date': cve.published_date.isoformat(),
                    'last_modified': cve.last_modified.isoformat(),
                    'cvss_score': cve.cvss_score,
                    'cvss_severity': cve.cvss_severity,
                    'vector_string': cve.vector_string,
                    'source': cve.source,
                    'references': cve.references,
                    'cwe_ids': cve.cwe_ids,
                    'affected_products': cve.affected_products
                }
                formatted_cves.append(formatted_cve)
            
            return jsonify(formatted_cves)
            
        except Exception as e:
            logger.error(f"Error en API CVEs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/search_ioc', methods=['POST'])
    def api_search_ioc():
        """API para búsqueda manual de IOCs"""
        try:
            data = request.get_json()
            
            if not data or 'ioc' not in data or 'type' not in data:
                return jsonify({'error': 'Se requiere IOC y tipo'}), 400
            
            ioc_value = data['ioc'].strip()
            ioc_type = data['type'].strip()
            
            # Validar tipo de IOC
            valid_types = ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256']
            if ioc_type not in valid_types:
                return jsonify({'error': f'Tipo de IOC inválido. Tipos válidos: {valid_types}'}), 400
            
            # Realizar búsqueda
            results = ioc_search_engine.search_ioc(ioc_value, ioc_type)
            
            return jsonify(results)
            
        except Exception as e:
            logger.error(f"Error en búsqueda de IOC: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/malware_samples')
    def api_malware_samples():
        """API para obtener muestras de malware recientes de MalwareBazaar"""
        try:
            limit = int(request.args.get('limit', 20))
            family = request.args.get('family', '')
            country = request.args.get('country', '')
            
            # Obtener datos recientes de MalwareBazaar
            mb_campaigns = scraper._fetch_malwarebazaar_data()
            
            samples = []
            for campaign in mb_campaigns:
                for ioc in campaign.iocs:
                    if ioc.type == 'hash_sha256':
                        sample = {
                            'sha256': ioc.value,
                            'malware_family': ioc.malware_family,
                            'first_seen': ioc.first_seen.isoformat(),
                            'last_seen': ioc.last_seen.isoformat(),
                            'country': ioc.country,
                            'source': ioc.source,
                            'confidence': ioc.confidence,
                            'tags': ioc.tags,
                            'campaign_name': campaign.name
                        }
                        
                        # Aplicar filtros
                        if family and ioc.malware_family != family:
                            continue
                        if country and ioc.country != country:
                            continue
                            
                        samples.append(sample)
            
            # Ordenar por fecha de último avistamiento
            samples.sort(key=lambda x: x['last_seen'], reverse=True)
            
            return jsonify(samples[:limit])
            
        except Exception as e:
            logger.error(f"Error en API muestras de malware: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/otx_pulses')
    def api_otx_pulses():
        """API para obtener pulsos recientes de OTX AlienVault"""
        try:
            limit = int(request.args.get('limit', 20))
            
            # Obtener datos recientes de OTX
            otx_campaigns = scraper._fetch_otx_data()
            
            pulses = []
            for campaign in otx_campaigns:
                pulse = {
                    'id': campaign.id,
                    'name': campaign.name,
                    'description': campaign.description,
                    'author': campaign.threat_actor,
                    'created': campaign.first_seen.isoformat(),
                    'modified': campaign.last_seen.isoformat(),
                    'countries_affected': campaign.countries_affected,
                    'malware_families': campaign.malware_families,
                    'ioc_count': len(campaign.iocs),
                    'severity': campaign.severity,
                    'iocs': [
                        {
                            'value': ioc.value,
                            'type': ioc.type,
                            'confidence': ioc.confidence
                        } for ioc in campaign.iocs[:10]  # Limitar IOCs mostrados
                    ]
                }
                pulses.append(pulse)
            
            # Ordenar por fecha de modificación
            pulses.sort(key=lambda x: x['modified'], reverse=True)
            
            return jsonify(pulses[:limit])
            
        except Exception as e:
            logger.error(f"Error en API pulsos OTX: {e}")
            return jsonify({'error': str(e)}), 500

    return app

# =====================================================
# PUNTO DE ENTRADA PRINCIPAL
# =====================================================

def main():
    """Función principal del sistema"""
    print("=" * 60)
    print("AEGIS THREAT INTELLIGENCE LATAM - SISTEMA CORREGIDO")
    print("   Desarrollado por: Elisa Elias")
    print("   AEGIS Security Consulting")
    print("   Version: 3.0.1 - PRODUCCIÓN CORREGIDA")
    print("=" * 60)
    
    logger.info("Iniciando AEGIS Threat Intelligence System...")
    
    try:
        app = create_app()
        
        config = Config()
        storage = AegisStorage(config)
        scraper = ProfessionalThreatIntelligence(config)
        
        print("\nVerificando dependencias del sistema:")
        print(f"   - MongoDB disponible: {'✓' if MONGODB_AVAILABLE else '✗ (usando memoria)'}")
        print(f"   - Web scraping disponible: {'✓' if WEB_SCRAPING_AVAILABLE else '✗ (usando datos demo)'}")
        
        print("\nConectando a fuentes de Threat Intelligence:")
        print("   FUENTES PROFESIONALES:")
        print("   - VirusTotal API (URLs/archivos maliciosos)")
        print("   - IBM X-Force Exchange API (Inteligencia corporativa)")
        print("   - OTX AlienVault API (Indicadores colaborativos)")
        print("   - MalwareBazaar API (Muestras de malware)")
        print("   FUENTES COMPLEMENTARIAS:")
        print("   - OpenPhish (URLs de phishing)")
        print("   - PhishTank (URLs verificadas)")
        print("   - URLhaus (URLs de malware)")
        
        # Check API keys status
        api_config = ThreatIntelAPIs()
        print("\nEstado de configuración de APIs:")
        api_status = {
            'VirusTotal': api_config.VIRUSTOTAL_API_KEY is not None,
            'IBM X-Force': api_config.IBM_XFORCE_API_KEY is not None,
            'OTX AlienVault': api_config.OTX_API_KEY is not None
        }
        
        for api_name, configured in api_status.items():
            status = "✓ CONFIGURADA" if configured else "✗ MODO DEMO"
            print(f"   - {api_name}: {status}")
        
        if not any(api_status.values()):
            print("\n   NOTA: Sistema funcionando en modo DEMO con datos realistas")
            print("   Para datos reales, configura las API keys en variables de entorno:")
            print("   - VIRUSTOTAL_API_KEY")
            print("   - IBM_XFORCE_API_KEY + IBM_XFORCE_PASSWORD")
            print("   - OTX_API_KEY")
        
        # Generar datos iniciales
        initial_campaigns = scraper.scrape_all_sources()
        stored_count = 0
        
        for campaign in initial_campaigns:
            if storage.store_campaign(campaign):
                stored_count += 1
        
        stats = storage.get_statistics()
        
        print(f"\nSistema inicializado correctamente:")
        print(f"   Campañas detectadas: {stats['total_campaigns']}")
        print(f"   IOCs recolectados: {stats['total_iocs']}")
        print(f"   Países afectados: {len(stats.get('iocs_by_country', {}))}")
        print(f"   Alertas críticas: {stats['campaigns_by_severity'].get('critical', 0)}")
        
        if stats.get('malware_families'):
            families = list(stats['malware_families'].keys())[:3]
            print(f"   Familias de malware: {', '.join(families)}")
        
        print(f"\nDashboard disponible en: http://localhost:5000")
        print("   Sistema de monitoreo en tiempo real activado")
        print("   Fuentes actualizándose automáticamente")
        
        logger.info("Iniciando servidor web del sistema AEGIS...")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        print("\nSistema detenido por el usuario")
        logger.info("Sistema detenido por el usuario")
    except Exception as e:
        print(f"\nError crítico: {e}")
        logger.error(f"Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
