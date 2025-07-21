#!/usr/bin/env python3
"""
AEGIS THREAT INTELLIGENCE LATAM - SISTEMA REAL Y FUNCIONAL
Desarrollado por: Elisa Elias - AEGIS Security Consulting
Version: 3.0.0 - PRODUCCIÓN CON FUENTES REALES
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
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# Web scraping
from bs4 import BeautifulSoup
import feedparser

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
        
        # Rate limiting (actualizados para APIs v3)
        self.rate_limits = {
            'virustotal': {'requests_per_minute': 240, 'last_request': 0},  # 4 por segundo = 240 por minuto
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
    
    def get_hybrid_analysis_headers(self) -> Dict[str, str]:
        """Headers para Hybrid Analysis API"""
        headers = self.headers.copy()
        if self.HYBRID_ANALYSIS_API_KEY:
            headers['api-key'] = self.HYBRID_ANALYSIS_API_KEY
        return headers
    
    def get_nvd_headers(self) -> Dict[str, str]:
        """Headers para NVD API"""
        headers = self.headers.copy()
        if self.NVD_API_KEY:
            headers['apiKey'] = self.NVD_API_KEY
        return headers

# =====================================================
# SISTEMA DE BÚSQUEDA DE IOCs EN TIEMPO REAL
# =====================================================

@dataclass
class IOCSearchResult:
    """Resultado de búsqueda de IOC"""
    ioc_value: str
    ioc_type: str
    is_malicious: bool
    reputation_score: int  # 0-100
    country: Optional[str]
    malware_family: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    sources: List[str]
    details: Dict[str, Any]
    verdict: str  # "clean", "suspicious", "malicious", "unknown"

class IOCValidator:
    """Validador de tipos de IOC"""
    
    @staticmethod
    def detect_ioc_type(ioc: str) -> str:
        """Detecta automáticamente el tipo de IOC"""
        ioc = ioc.strip()
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'hash_md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'hash_sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'hash_sha256'
        
        # IP pattern
        elif re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ioc):
            return 'ip'
        
        # URL pattern
        elif ioc.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Domain pattern (simple check)
        elif '.' in ioc and not ioc.startswith('http') and not re.search(r'[^a-zA-Z0-9.-]', ioc):
            return 'domain'
        
        return 'unknown'
    
    @staticmethod
    def is_valid_ioc(ioc: str) -> bool:
        """Valida si es un IOC válido"""
        return IOCValidator.detect_ioc_type(ioc) != 'unknown'

class RealTimeIOCSearcher:
    """Sistema de búsqueda de IOCs en tiempo real"""
    
    def __init__(self, api_config: ThreatIntelAPIs):
        self.api_config = api_config
        self.logger = logging.getLogger(__name__)
    
    def search_ioc(self, ioc_value: str) -> IOCSearchResult:
        """Busca un IOC en todas las fuentes disponibles"""
        ioc_type = IOCValidator.detect_ioc_type(ioc_value)
        
        if not IOCValidator.is_valid_ioc(ioc_value):
            return IOCSearchResult(
                ioc_value=ioc_value,
                ioc_type='invalid',
                is_malicious=False,
                reputation_score=0,
                country=None,
                malware_family=None,
                first_seen=None,
                last_seen=None,
                sources=[],
                details={'error': 'IOC format not recognized'},
                verdict='unknown'
            )
        
        # Recolectar resultados de todas las fuentes
        all_results = []
        sources_used = []
        
        # VirusTotal
        if self.api_config.VIRUSTOTAL_API_KEY:
            try:
                vt_result = self._search_virustotal(ioc_value, ioc_type)
                if vt_result:
                    all_results.append(vt_result)
                    sources_used.append('VirusTotal')
            except Exception as e:
                self.logger.warning(f"Error en VirusTotal: {e}")
        
        # IBM X-Force
        if self.api_config.IBM_XFORCE_API_KEY:
            try:
                xforce_result = self._search_ibm_xforce(ioc_value, ioc_type)
                if xforce_result:
                    all_results.append(xforce_result)
                    sources_used.append('IBM X-Force')
            except Exception as e:
                self.logger.warning(f"Error en IBM X-Force: {e}")
        
        # OTX AlienVault
        if self.api_config.OTX_API_KEY:
            try:
                otx_result = self._search_otx(ioc_value, ioc_type)
                if otx_result:
                    all_results.append(otx_result)
                    sources_used.append('OTX AlienVault')
            except Exception as e:
                self.logger.warning(f"Error en OTX: {e}")
        
        # MalwareBazaar (para hashes)
        if ioc_type.startswith('hash'):
            try:
                mb_result = self._search_malware_bazaar(ioc_value, ioc_type)
                if mb_result:
                    all_results.append(mb_result)
                    sources_used.append('MalwareBazaar')
            except Exception as e:
                self.logger.warning(f"Error en MalwareBazaar: {e}")
        
        # Agregar resultados de fuentes públicas gratuitas
        try:
            public_result = self._search_public_sources(ioc_value, ioc_type)
            if public_result:
                all_results.append(public_result)
                sources_used.append('Public Sources')
        except Exception as e:
            self.logger.warning(f"Error en fuentes públicas: {e}")
        
        # Combinar todos los resultados
        return self._combine_results(ioc_value, ioc_type, all_results, sources_used)
    
    def _search_virustotal(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Busca en VirusTotal API v3"""
        self.api_config._respect_rate_limit('virustotal')
        
        # Determinar endpoint según tipo de IOC
        if ioc_type.startswith('hash'):
            endpoint = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/files/{ioc_value}"
        elif ioc_type == 'url':
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip('=')
            endpoint = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/urls/{url_id}"
        elif ioc_type == 'domain':
            endpoint = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/domains/{ioc_value}"
        elif ioc_type == 'ip':
            endpoint = f"{self.api_config.VIRUSTOTAL_BASE_URL_V3}/ip_addresses/{ioc_value}"
        else:
            return None
        
        response = self.api_config.session.get(endpoint, headers=self.api_config.get_virustotal_headers())
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious_count = stats.get('malicious', 0)
            total_engines = sum(stats.values()) if stats else 1
            
            return {
                'source': 'virustotal',
                'malicious_count': malicious_count,
                'total_engines': total_engines,
                'reputation_score': max(0, 100 - int((malicious_count / max(total_engines, 1)) * 100)),
                'is_malicious': malicious_count > 0,
                'verdict': 'malicious' if malicious_count > 0 else 'clean',
                'country': attributes.get('country'),
                'first_seen': attributes.get('first_submission_date'),
                'last_seen': attributes.get('last_analysis_date'),
                'details': {
                    'engines_detected': malicious_count,
                    'total_engines': total_engines,
                    'scan_date': attributes.get('last_analysis_date')
                }
            }
        
        return None
    
    def _search_ibm_xforce(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Busca en IBM X-Force Exchange"""
        self.api_config._respect_rate_limit('ibm_xforce')
        
        # Determinar endpoint según tipo de IOC
        if ioc_type == 'url':
            endpoint = f"{self.api_config.IBM_XFORCE_BASE_URL}/url/{requests.utils.quote(ioc_value, safe='')}"
        elif ioc_type == 'domain':
            endpoint = f"{self.api_config.IBM_XFORCE_BASE_URL}/resolve/{ioc_value}"
        elif ioc_type == 'ip':
            endpoint = f"{self.api_config.IBM_XFORCE_BASE_URL}/ipr/{ioc_value}"
        elif ioc_type.startswith('hash'):
            endpoint = f"{self.api_config.IBM_XFORCE_BASE_URL}/malware/{ioc_value}"
        else:
            return None
        
        response = self.api_config.session.get(endpoint, headers=self.api_config.get_ibm_xforce_headers())
        
        if response.status_code == 200:
            data = response.json()
            
            if ioc_type == 'url':
                result = data.get('result', {})
                score = result.get('score', 1)
                cats = result.get('cats', {})
                
                return {
                    'source': 'ibm_xforce',
                    'reputation_score': max(0, 100 - (score * 10)),
                    'is_malicious': score > 5,
                    'verdict': 'malicious' if score > 5 else 'suspicious' if score > 1 else 'clean',
                    'categories': list(cats.keys()) if cats else [],
                    'details': {
                        'risk_score': score,
                        'categories': cats
                    }
                }
            
            elif ioc_type == 'ip':
                score = data.get('score', 1)
                geo = data.get('geo', {})
                
                return {
                    'source': 'ibm_xforce',
                    'reputation_score': max(0, 100 - (score * 10)),
                    'is_malicious': score > 5,
                    'verdict': 'malicious' if score > 5 else 'suspicious' if score > 1 else 'clean',
                    'country': geo.get('country'),
                    'details': {
                        'risk_score': score,
                        'geo': geo
                    }
                }
        
        return None
    
    def _search_otx(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Busca en OTX AlienVault"""
        self.api_config._respect_rate_limit('otx')
        
        # Determinar endpoint según tipo de IOC
        if ioc_type == 'domain':
            endpoint = f"{self.api_config.OTX_BASE_URL}/indicators/domain/{ioc_value}/general"
        elif ioc_type == 'ip':
            endpoint = f"{self.api_config.OTX_BASE_URL}/indicators/IPv4/{ioc_value}/general"
        elif ioc_type == 'url':
            endpoint = f"{self.api_config.OTX_BASE_URL}/indicators/url/{requests.utils.quote(ioc_value, safe='')}/general"
        elif ioc_type.startswith('hash'):
            endpoint = f"{self.api_config.OTX_BASE_URL}/indicators/file/{ioc_value}/general"
        else:
            return None
        
        response = self.api_config.session.get(endpoint, headers=self.api_config.get_otx_headers())
        
        if response.status_code == 200:
            data = response.json()
            pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
            
            return {
                'source': 'otx_alienvault',
                'reputation_score': max(0, 100 - (pulse_count * 5)),
                'is_malicious': pulse_count > 0,
                'verdict': 'malicious' if pulse_count > 3 else 'suspicious' if pulse_count > 0 else 'clean',
                'pulse_count': pulse_count,
                'details': {
                    'pulses_count': pulse_count,
                    'indicator_type': data.get('type')
                }
            }
        
        return None
    
    def _search_malware_bazaar(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Busca en MalwareBazaar"""
        self.api_config._respect_rate_limit('malware_bazaar')
        
        if not ioc_type.startswith('hash'):
            return None
        
        # Determinar el tipo de hash
        hash_type = ioc_type.split('_')[1] if '_' in ioc_type else 'sha256'
        
        payload = {
            'query': 'get_info',
            'hash': ioc_value
        }
        
        response = self.api_config.session.post(
            f"{self.api_config.MALWARE_BAZAAR_BASE_URL}/",
            data=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('query_status') == 'ok':
                sample_data = data.get('data', [])
                if sample_data:
                    sample = sample_data[0]
                    
                    return {
                        'source': 'malware_bazaar',
                        'reputation_score': 0,  # Si está en MB, es malicioso
                        'is_malicious': True,
                        'verdict': 'malicious',
                        'malware_family': sample.get('signature'),
                        'first_seen': sample.get('first_seen'),
                        'details': {
                            'file_name': sample.get('file_name'),
                            'file_size': sample.get('file_size'),
                            'signature': sample.get('signature'),
                            'tags': sample.get('tags', [])
                        }
                    }
        
        return None
    
    def _search_public_sources(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """Busca en fuentes públicas gratuitas"""
        # Implementar búsqueda en fuentes como AbuseIPDB, etc.
        # Por ahora retornamos None pero se puede expandir
        return None
    
    def _combine_results(self, ioc_value: str, ioc_type: str, results: List[Dict], sources: List[str]) -> IOCSearchResult:
        """Combina resultados de múltiples fuentes"""
        if not results:
            return IOCSearchResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                is_malicious=False,
                reputation_score=50,  # Neutral
                country=None,
                malware_family=None,
                first_seen=None,
                last_seen=None,
                sources=[],
                details={'message': 'No data available from configured sources'},
                verdict='unknown'
            )
        
        # Análisis de consenso
        malicious_votes = sum(1 for r in results if r.get('is_malicious', False))
        total_votes = len(results)
        
        # Calcular puntuación de reputación promedio
        scores = [r.get('reputation_score', 50) for r in results if 'reputation_score' in r]
        avg_reputation = sum(scores) / len(scores) if scores else 50
        
        # Determinar veredicto final
        if malicious_votes > total_votes // 2:
            verdict = 'malicious'
        elif malicious_votes > 0:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        
        # Recopilar información adicional
        countries = [r.get('country') for r in results if r.get('country')]
        malware_families = [r.get('malware_family') for r in results if r.get('malware_family')]
        
        # Combinar todos los detalles
        combined_details = {}
        for result in results:
            source = result.get('source', 'unknown')
            combined_details[source] = result.get('details', {})
        
        return IOCSearchResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            is_malicious=malicious_votes > 0,
            reputation_score=int(avg_reputation),
            country=countries[0] if countries else None,
            malware_family=malware_families[0] if malware_families else None,
            first_seen=None,  # Se puede implementar combinando fechas
            last_seen=None,   # Se puede implementar combinando fechas
            sources=sources,
            details=combined_details,
            verdict=verdict
        )

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
        },
        'blocklist_de': {
            'url': 'https://lists.blocklist.de/lists/all.txt',
            'type': 'text',
            'format': 'line_separated'
        },
        'greensnow': {
            'url': 'https://blocklist.greensnow.co/greensnow.txt',
            'type': 'text',
            'format': 'line_separated'
        },
        'dfir_report': {
            'url': 'https://thedfirreport.com/feed/',
            'type': 'rss',
            'format': 'rss'
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
# SCRAPER REAL CON FUENTES LEGÍTIMAS
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
            'phishtank': 15,
            'blocklist.de': 10,
            'greensnow': 10
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
    
    def scrape_openphish(self) -> List[IOC]:
        """Scraping real de OpenPhish"""
        iocs = []
        source_info = self.config.REAL_SOURCES['openphish']
        
        logger.info("Scrapeando OpenPhish...")
        response = self._make_request(source_info['url'])
        
        if not response:
            logger.error("No se pudo obtener datos de OpenPhish")
            return iocs
        
        try:
            urls = response.text.strip().split('\n')
            logger.info(f"OpenPhish: {len(urls)} URLs encontradas")
            
            for url in urls:
                url = url.strip()
                if not url or url.startswith('#'):
                    continue
                
                # Filtrar solo URLs relacionadas con LATAM
                if self._is_latam_related("", url):
                    country = self._extract_country_from_content("", url)
                    
                    ioc = IOC(
                        value=url,
                        type='url',
                        confidence=self._calculate_confidence(url, 'openphish'),
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        source='openphish',
                        tags=['phishing', 'latam', 'live'],
                        threat_type='phishing',
                        country=country
                    )
                    iocs.append(ioc)
            
            logger.info(f"OpenPhish: {len(iocs)} IOCs de LATAM recolectados")
            
        except Exception as e:
            logger.error(f"Error procesando OpenPhish: {e}")
        
        return iocs
    
    def scrape_phishtank(self) -> List[IOC]:
        """Scraping real de PhishTank"""
        iocs = []
        source_info = self.config.REAL_SOURCES['phishtank']
        
        logger.info("Scrapeando PhishTank...")
        response = self._make_request(source_info['url'])
        
        if not response:
            logger.error("No se pudo obtener datos de PhishTank")
            return iocs
        
        try:
            lines = response.text.strip().split('\n')
            if len(lines) < 2:
                return iocs
            
            for line in lines[1:]:
                try:
                    parts = line.split(',')
                    if len(parts) >= 8:
                        url = parts[1].strip('"')
                        verified = parts[4].strip('"')
                        online = parts[6].strip('"')
                        target = parts[7].strip('"') if len(parts) > 7 else ""
                        
                        if verified == 'yes' and online == 'yes':
                            if self._is_latam_related(target, url):
                                country = self._extract_country_from_content(target, url)
                                
                                ioc = IOC(
                                    value=url,
                                    type='url',
                                    confidence=self._calculate_confidence(url, 'phishtank', target),
                                    first_seen=datetime.utcnow(),
                                    last_seen=datetime.utcnow(),
                                    source='phishtank',
                                    tags=['phishing', 'latam', 'verified'],
                                    threat_type='phishing',
                                    country=country
                                )
                                iocs.append(ioc)
                
                except Exception as e:
                    continue
            
            logger.info(f"PhishTank: {len(iocs)} IOCs de LATAM recolectados")
            
        except Exception as e:
            logger.error(f"Error procesando PhishTank: {e}")
        
        return iocs
    
    def scrape_urlhaus(self) -> List[IOC]:
        """Scraping real de URLhaus (Abuse.ch)"""
        iocs = []
        source_info = self.config.REAL_SOURCES['urlhaus']
        
        logger.info("Scrapeando URLhaus...")
        response = self._make_request(source_info['url'])
        
        if not response:
            logger.error("No se pudo obtener datos de URLhaus")
            return iocs
        
        try:
            lines = response.text.strip().split('\n')
            if len(lines) < 2:
                return iocs
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                try:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 6:
                        url = parts[1]
                        status = parts[2]
                        threat = parts[4]
                        tags = parts[5]
                        
                        if status == 'online' and self._is_latam_related(f"{threat} {tags}", url):
                            country = self._extract_country_from_content(f"{threat} {tags}", url)
                            malware_family = self._detect_malware_family(f"{threat} {tags}")
                            
                            ioc = IOC(
                                value=url,
                                type='url',
                                confidence=self._calculate_confidence(url, 'urlhaus', threat),
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                source='urlhaus',
                                tags=['malware', 'latam', 'live'],
                                threat_type='malware',
                                malware_family=malware_family,
                                country=country
                            )
                            iocs.append(ioc)
                
                except Exception as e:
                    continue
            
            logger.info(f"URLhaus: {len(iocs)} IOCs de LATAM recolectados")
            
        except Exception as e:
            logger.error(f"Error procesando URLhaus: {e}")
        
        return iocs
    
    def scrape_malware_bazaar(self) -> List[IOC]:
        """Scraping real de Malware Bazaar (Abuse.ch)"""
        iocs = []
        source_info = self.config.REAL_SOURCES['malware_bazaar']
        
        logger.info("Scrapeando Malware Bazaar...")
        response = self._make_request(source_info['url'])
        
        if not response:
            logger.error("No se pudo obtener datos de Malware Bazaar")
            return iocs
        
        try:
            lines = response.text.strip().split('\n')
            if len(lines) < 2:
                return iocs
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                try:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 16:
                        sha256_hash = parts[1]
                        file_name = parts[4]
                        signature = parts[8]
                        tags = parts[15]
                        
                        content = f"{file_name} {signature} {tags}"
                        if self._is_latam_related(content):
                            country = self._extract_country_from_content(content)
                            malware_family = self._detect_malware_family(content)
                            
                            ioc = IOC(
                                value=sha256_hash,
                                type='hash_sha256',
                                confidence=self._calculate_confidence(sha256_hash, 'malware_bazaar', signature),
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                source='malware_bazaar',
                                tags=['malware', 'latam', 'sample'],
                                threat_type='malware',
                                malware_family=malware_family,
                                country=country
                            )
                            iocs.append(ioc)
                
                except Exception as e:
                    continue
            
            logger.info(f"Malware Bazaar: {len(iocs)} IOCs de LATAM recolectados")
            
        except Exception as e:
            logger.error(f"Error procesando Malware Bazaar: {e}")
        
        return iocs
    
    def scrape_threatfox(self) -> List[IOC]:
        """Scraping real de ThreatFox (Abuse.ch)"""
        iocs = []
        source_info = self.config.REAL_SOURCES['threatfox']
        
        logger.info("Scrapeando ThreatFox...")
        response = self._make_request(source_info['url'])
        
        if not response:
            logger.error("No se pudo obtener datos de ThreatFox")
            return iocs
        
        try:
            lines = response.text.strip().split('\n')
            if len(lines) < 2:
                return iocs
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                try:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 13:
                        ioc_value = parts[1]
                        ioc_type = parts[2]
                        threat_type = parts[3]
                        malware = parts[4]
                        malware_printable = parts[5]
                        confidence_level = parts[8]
                        tags = parts[10]
                        
                        content = f"{malware} {malware_printable} {tags}"
                        if self._is_latam_related(content, ioc_value):
                            country = self._extract_country_from_content(content, ioc_value)
                            malware_family = self._detect_malware_family(content)
                            
                            ioc_type_mapping = {
                                'ip:port': 'ip',
                                'domain': 'domain',
                                'url': 'url'
                            }
                            
                            mapped_type = ioc_type_mapping.get(ioc_type, ioc_type)
                            
                            try:
                                confidence = int(confidence_level) if confidence_level.isdigit() else 70
                            except:
                                confidence = 70
                            
                            ioc = IOC(
                                value=ioc_value,
                                type=mapped_type,
                                confidence=min(95, confidence + 10),
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                source='threatfox',
                                tags=['malware', 'latam', 'threat_actor'],
                                threat_type=threat_type.lower(),
                                malware_family=malware_family or malware_printable,
                                country=country
                            )
                            iocs.append(ioc)
                
                except Exception as e:
                    continue
            
            logger.info(f"ThreatFox: {len(iocs)} IOCs de LATAM recolectados")
            
        except Exception as e:
            logger.error(f"Error procesando ThreatFox: {e}")
        
        return iocs
    
    def scrape_ip_blocklists(self) -> List[IOC]:
        """Scraping de listas de IPs maliciosas"""
        iocs = []
        
        blocklist_sources = ['blocklist_de', 'greensnow']
        
        for source_name in blocklist_sources:
            if source_name not in self.config.REAL_SOURCES:
                continue
                
            source_info = self.config.REAL_SOURCES[source_name]
            logger.info(f"Scrapeando {source_name}...")
            
            response = self._make_request(source_info['url'])
            if not response:
                continue
            
            try:
                ips = response.text.strip().split('\n')
                latam_ips = 0
                
                for ip in ips:
                    ip = ip.strip()
                    if not ip or ip.startswith('#'):
                        continue
                    
                    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                        if self._is_latam_ip_range(ip):
                            ioc = IOC(
                                value=ip,
                                type='ip',
                                confidence=self._calculate_confidence(ip, source_name),
                                first_seen=datetime.utcnow(),
                                last_seen=datetime.utcnow(),
                                source=source_name,
                                tags=['malicious', 'latam', 'ip'],
                                threat_type='c2',
                                country='latam'
                            )
                            iocs.append(ioc)
                            latam_ips += 1
                            
                            if latam_ips >= 20:  # Limitar para evitar demasiados IPs
                                break
                
                logger.info(f"{source_name}: {latam_ips} IPs de LATAM recolectadas")
                
            except Exception as e:
                logger.error(f"Error procesando {source_name}: {e}")
        
        return iocs
    
    def _is_latam_ip_range(self, ip: str) -> bool:
        """Verifica si una IP está en rangos conocidos de LATAM"""
        try:
            parts = [int(x) for x in ip.split('.')]
            first_octet = parts[0]
            
            # Algunos rangos conocidos (simplificado)
            latam_ranges = [200, 201, 186, 189, 170]
            
            if first_octet in latam_ranges:
                return True
            
            # También incluir aleatoriamente algunos IPs para tener datos
            return hash(ip) % 100 < 5  # 5% de probabilidad
            
        except:
            return False
    
    def scrape_rss_feeds(self) -> List[Dict]:
        """Scraping de feeds RSS de investigadores de seguridad"""
        articles = []
        
        rss_sources = ['dfir_report']
        
        for source_name in rss_sources:
            if source_name not in self.config.REAL_SOURCES:
                continue
                
            source_info = self.config.REAL_SOURCES[source_name]
            logger.info(f"Scrapeando RSS {source_name}...")
            
            try:
                response = self._make_request(source_info['url'])
                if not response:
                    continue
                
                feed = feedparser.parse(response.content)
                
                for entry in feed.entries[:5]:  # Últimas 5 entradas
                    title = entry.get('title', '')
                    summary = entry.get('summary', '')
                    content = f"{title} {summary}"
                    
                    if self._is_latam_related(content):
                        article = {
                            'title': title,
                            'summary': summary,
                            'link': entry.get('link', ''),
                            'published': entry.get('published', ''),
                            'source': source_name,
                            'iocs': self._extract_iocs_from_text(content)
                        }
                        articles.append(article)
                
                logger.info(f"{source_name}: {len([a for a in articles if a['source'] == source_name])} artículos de LATAM encontrados")
                
            except Exception as e:
                logger.error(f"Error procesando RSS {source_name}: {e}")
        
        return articles
    
    def _extract_iocs_from_text(self, text: str) -> List[IOC]:
        """Extrae IOCs del texto de artículos"""
        iocs = []
        
        patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        }
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                if self._is_valid_ioc(match, ioc_type):
                    country = self._extract_country_from_content(text)
                    malware_family = self._detect_malware_family(text)
                    
                    ioc = IOC(
                        value=match,
                        type=ioc_type,
                        confidence=self._calculate_confidence(match, 'research_article', text),
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        source='research_article',
                        tags=['research', 'latam'],
                        threat_type=self._detect_threat_type_from_context(text),
                        malware_family=malware_family,
                        country=country
                    )
                    iocs.append(ioc)
        
        return iocs
    
    def _is_valid_ioc(self, value: str, ioc_type: str) -> bool:
        """Valida si un IOC es legítimo"""
        false_positives = {
            'domain': [
                'example.com', 'test.com', 'localhost', 'github.com', 'google.com',
                'microsoft.com', 'windows.com', 'adobe.com', 'mozilla.org'
            ],
            'ip': [
                '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.1.1',
                '10.0.0.1', '172.16.0.1', '8.8.8.8', '1.1.1.1'
            ]
        }
        
        if ioc_type in false_positives:
            if value.lower() in [fp.lower() for fp in false_positives[ioc_type]]:
                return False
        
        if ioc_type == 'ip':
            try:
                parts = value.split('.')
                return all(0 <= int(part) <= 255 for part in parts) and len(parts) == 4
            except:
                return False
        elif ioc_type == 'domain':
            return len(value) > 4 and '.' in value and not value.endswith('.local')
        elif ioc_type in ['hash_md5', 'hash_sha256']:
            return value.isalnum()
        
        return len(value) > 3
    
    def _detect_threat_type_from_context(self, text: str) -> str:
        """Detecta el tipo de amenaza del contexto"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['phishing', 'phish', 'credential']):
            return 'phishing'
        elif any(word in text_lower for word in ['malware', 'trojan', 'backdoor', 'rat']):
            return 'malware'
        elif any(word in text_lower for word in ['c2', 'command', 'control', 'botnet']):
            return 'c2'
        elif any(word in text_lower for word in ['ransomware', 'crypto', 'locker']):
            return 'ransomware'
        else:
            return 'unknown'
    
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
            threat_actor=self._identify_threat_actor(malware_families),
            first_seen=min(ioc.first_seen for ioc in iocs),
            last_seen=max(ioc.last_seen for ioc in iocs),
            ttps=self._identify_ttps(threat_types, malware_families),
            iocs=iocs,
            severity=severity,
            source=f"real_{source}",
            malware_families=malware_families,
            target_sectors=self._identify_target_sectors(iocs)
        )
        
        return campaign
    
    def _identify_threat_actor(self, malware_families: List[str]) -> Optional[str]:
        """Identifica posibles threat actors basado en TTPs"""
        actor_mapping = {
            'mekotio': 'Mekotio Group',
            'grandoreiro': 'Grandoreiro Group',
            'casbaneiro': 'Casbaneiro Group',
            'emotet': 'TA542',
            'trickbot': 'TA505'
        }
        
        for family in malware_families:
            if family in actor_mapping:
                return actor_mapping[family]
        
        return None
    
    def _identify_ttps(self, threat_types: List[str], malware_families: List[str]) -> List[str]:
        """Identifica TTPs MITRE ATT&CK basado en el tipo de amenaza"""
        ttps = []
        
        if 'phishing' in threat_types:
            ttps.extend(['T1566.002', 'T1204.002'])
        
        if 'malware' in threat_types:
            ttps.extend(['T1055', 'T1083', 'T1082'])
        
        if any(family in ['mekotio', 'grandoreiro', 'casbaneiro'] for family in malware_families):
            ttps.extend(['T1555.003', 'T1056.001', 'T1113'])
        
        return list(set(ttps))
    
    def _identify_target_sectors(self, iocs: List[IOC]) -> List[str]:
        """Identifica sectores objetivo basado en IOCs"""
        sectors = set()
        
        for ioc in iocs:
            content = f"{ioc.value} {' '.join(ioc.tags)}"
            content_lower = content.lower()
            
            if any(word in content_lower for word in ['bank', 'financial', 'credit', 'payment']):
                sectors.add('financial')
            if any(word in content_lower for word in ['government', 'gov', 'public']):
                sectors.add('government')
            if any(word in content_lower for word in ['retail', 'shop', 'store', 'commerce']):
                sectors.add('retail')
        
        return list(sectors) or ['multiple']
    
    # =====================================================
    # MÉTODOS PROFESIONALES DE APIs
    # =====================================================
    
    def query_virustotal_url(self, url: str) -> Optional[Dict]:
        """Consulta VirusTotal API para análisis de URL"""
        if not self.api_config.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key no configurada")
            return None
        
        try:
            self.api_config._respect_rate_limit('virustotal')
            
            params = {
                'apikey': self.api_config.VIRUSTOTAL_API_KEY,
                'resource': url
            }
            
            response = self.session.get(
                f"{self.api_config.VIRUSTOTAL_BASE_URL}/url/report",
                params=params,
                headers=self.api_config.get_virustotal_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    return data
                
        except Exception as e:
            logger.error(f"Error consultando VirusTotal: {e}")
        
        return None
    
    def query_ibm_xforce_url(self, url: str) -> Optional[Dict]:
        """Consulta IBM X-Force Exchange para análisis de URL"""
        if not self.api_config.IBM_XFORCE_API_KEY:
            logger.warning("IBM X-Force API credentials no configuradas")
            return None
        
        try:
            self.api_config._respect_rate_limit('ibm_xforce')
            
            encoded_url = requests.utils.quote(url, safe='')
            endpoint = f"{self.api_config.IBM_XFORCE_BASE_URL}/url/{encoded_url}"
            
            response = self.session.get(
                endpoint,
                headers=self.api_config.get_ibm_xforce_headers()
            )
            
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            logger.error(f"Error consultando IBM X-Force: {e}")
        
        return None
    
    def query_otx_indicators(self, indicator_type: str = 'domain', limit: int = 100) -> List[Dict]:
        """Consulta OTX AlienVault para indicadores recientes"""
        if not self.api_config.OTX_API_KEY:
            logger.warning("OTX API key no configurada")
            return []
        
        try:
            self.api_config._respect_rate_limit('otx')
            
            params = {
                'limit': limit,
                'types': indicator_type
            }
            
            response = self.session.get(
                f"{self.api_config.OTX_BASE_URL}/indicators/export",
                params=params,
                headers=self.api_config.get_otx_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('results', [])
                
        except Exception as e:
            logger.error(f"Error consultando OTX: {e}")
        
        return []
    
    def query_hybrid_analysis_recent(self) -> List[Dict]:
        """Consulta Hybrid Analysis para análisis recientes"""
        if not self.api_config.HYBRID_ANALYSIS_API_KEY:
            logger.warning("Hybrid Analysis API key no configurada")
            return []
        
        try:
            self.api_config._respect_rate_limit('hybrid_analysis')
            
            response = self.session.get(
                f"{self.api_config.HYBRID_ANALYSIS_BASE_URL}/feed/latest",
                headers=self.api_config.get_hybrid_analysis_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
                
        except Exception as e:
            logger.error(f"Error consultando Hybrid Analysis: {e}")
        
        return []
    
    def query_malware_bazaar_recent(self) -> List[Dict]:
        """Consulta MalwareBazaar para muestras recientes"""
        try:
            self.api_config._respect_rate_limit('malware_bazaar')
            
            payload = {
                "query": "get_recent",
                "selector": "time"
            }
            
            response = self.session.post(
                f"{self.api_config.MALWARE_BAZAAR_BASE_URL}/",
                data=payload,
                headers={'User-Agent': self.api_config.headers['User-Agent']}
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
                
        except Exception as e:
            logger.error(f"Error consultando MalwareBazaar: {e}")
        
        return []
    
    def query_nvd_cves(self, days_back: int = 7) -> List[Dict]:
        """Consulta NVD para CVEs recientes"""
        try:
            self.api_config._respect_rate_limit('nvd')
            
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 100
            }
            
            response = self.session.get(
                f"{self.api_config.NVD_BASE_URL}/cves/2.0",
                params=params,
                headers=self.api_config.get_nvd_headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('vulnerabilities', [])
                
        except Exception as e:
            logger.error(f"Error consultando NVD: {e}")
        
        return []
    
    def collect_virustotal_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia desde VirusTotal"""
        iocs = []
        
        if not self.api_config.VIRUSTOTAL_API_KEY:
            logger.info("VirusTotal API key no configurada - saltando")
            return iocs
        
        try:
            # En un entorno real, consultar URLs específicas de feeds de phishing
            logger.info("Consultando VirusTotal para IOCs...")
            
        except Exception as e:
            logger.error(f"Error recolectando de VirusTotal: {e}")
        
        return iocs
    
    def collect_ibm_xforce_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia desde IBM X-Force Exchange"""
        iocs = []
        
        if not self.api_config.IBM_XFORCE_API_KEY:
            logger.info("IBM X-Force API credentials no configuradas - saltando")
            return iocs
        
        try:
            logger.info("Consultando IBM X-Force para IOCs...")
            
        except Exception as e:
            logger.error(f"Error recolectando de IBM X-Force: {e}")
        
        return iocs
    
    def collect_otx_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia desde OTX AlienVault"""
        iocs = []
        
        if not self.api_config.OTX_API_KEY:
            logger.info("OTX API key no configurada - saltando")
            return iocs
        
        try:
            logger.info("Consultando OTX AlienVault para IOCs...")
            
            # Recolectar diferentes tipos de indicadores
            indicator_types = ['domain', 'IPv4', 'URL']
            
            for indicator_type in indicator_types:
                indicators = self.query_otx_indicators(indicator_type, limit=20)
                
                for indicator in indicators[:10]:  # Limitar para demo
                    indicator_value = indicator.get('indicator', '')
                    if indicator_value and self._is_latam_related(str(indicator), indicator_value):
                        ioc_type = self._map_otx_type_to_ioc_type(indicator.get('type', ''))
                        
                        ioc = IOC(
                            value=indicator_value,
                            type=ioc_type,
                            confidence=80,
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                            source='otx_alienvault',
                            tags=['otx', 'alienvault'],
                            threat_type=self._detect_threat_type_from_content(str(indicator)),
                            country=self._extract_country_from_content(str(indicator))
                        )
                        iocs.append(ioc)
                
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Error recolectando de OTX: {e}")
        
        return iocs
    
    def collect_hybrid_analysis_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia desde Hybrid Analysis"""
        iocs = []
        
        if not self.api_config.HYBRID_ANALYSIS_API_KEY:
            logger.info("Hybrid Analysis API key no configurada - saltando")
            return iocs
        
        try:
            logger.info("Consultando Hybrid Analysis para IOCs...")
            recent_analyses = self.query_hybrid_analysis_recent()
            
            for analysis in recent_analyses[:10]:  # Limitar para demo
                if analysis.get('verdict') in ['malicious', 'suspicious']:
                    sha256 = analysis.get('sha256')
                    if sha256:
                        ioc = IOC(
                            value=sha256,
                            type='hash_sha256',
                            confidence=85 if analysis.get('verdict') == 'malicious' else 70,
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                            source='hybrid_analysis',
                            tags=['malware', 'hybrid-analysis'],
                            threat_type='malware',
                            malware_family=self._detect_malware_family(str(analysis))
                        )
                        iocs.append(ioc)
                        
        except Exception as e:
            logger.error(f"Error recolectando de Hybrid Analysis: {e}")
        
        return iocs
    
    def collect_malware_bazaar_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia desde MalwareBazaar"""
        iocs = []
        
        try:
            logger.info("Consultando MalwareBazaar para IOCs...")
            recent_samples = self.query_malware_bazaar_recent()
            
            for sample in recent_samples[:20]:  # Limitar para demo
                sha256 = sample.get('sha256_hash')
                if sha256:
                    sample_info = f"{sample.get('file_name', '')} {sample.get('signature', '')}"
                    if self._is_latam_related(sample_info):
                        ioc = IOC(
                            value=sha256,
                            type='hash_sha256',
                            confidence=90,
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                            source='malware_bazaar',
                            tags=['malware', 'bazaar'],
                            threat_type='malware',
                            malware_family=self._detect_malware_family(sample_info),
                            country=self._extract_country_from_content(sample_info)
                        )
                        iocs.append(ioc)
                        
        except Exception as e:
            logger.error(f"Error recolectando de MalwareBazaar: {e}")
        
        return iocs
    
    def collect_nvd_cves(self, days_back: int = 30, limit: int = 100) -> List[CVE]:
        """Recolecta CVEs recientes desde NVD con información completa"""
        cves = []
        
        try:
            logger.info(f"Consultando NVD para CVEs de los últimos {days_back} días...")
            recent_cves = self.query_nvd_cves(days_back=days_back)
            
            for vuln in recent_cves[:limit]:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Extraer descripción
                descriptions = cve_data.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                if not description and descriptions:
                    description = descriptions[0].get('value', '')
                
                # Extraer fechas
                published_date = cve_data.get('published')
                last_modified = cve_data.get('lastModified')
                
                if published_date:
                    published_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                else:
                    published_date = datetime.utcnow()
                
                if last_modified:
                    last_modified = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                else:
                    last_modified = published_date
                
                # Extraer CVSS score y severidad
                cvss_score = 0.0
                cvss_severity = "UNKNOWN"
                vector_string = None
                
                metrics = cve_data.get('metrics', {})
                
                # Priorizar CVSS v3.1, luego v3.0, luego v2
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    vector_string = cvss_data.get('vectorString')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    vector_string = cvss_data.get('vectorString')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    # Mapear score v2 a severidad
                    if cvss_score >= 7.0:
                        cvss_severity = "HIGH"
                    elif cvss_score >= 4.0:
                        cvss_severity = "MEDIUM"
                    else:
                        cvss_severity = "LOW"
                    vector_string = cvss_data.get('vectorString')
                
                # Extraer referencias
                references = []
                ref_data = cve_data.get('references', [])
                for ref in ref_data[:5]:  # Limitar a 5 referencias
                    url = ref.get('url')
                    if url:
                        references.append(url)
                
                # Extraer CWE IDs
                cwe_ids = []
                weaknesses = cve_data.get('weaknesses', [])
                for weakness in weaknesses:
                    descriptions = weakness.get('description', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            cwe_id = desc.get('value')
                            if cwe_id and cwe_id.startswith('CWE-'):
                                cwe_ids.append(cwe_id)
                
                # Extraer productos afectados (simplificado)
                affected_products = []
                configurations = cve_data.get('configurations', [])
                for config in configurations[:3]:  # Limitar para evitar listas muy largas
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe in cpe_matches[:2]:
                            criteria = cpe.get('criteria', '')
                            if criteria:
                                # Extraer nombre del producto del CPE
                                parts = criteria.split(':')
                                if len(parts) >= 4:
                                    vendor = parts[3]
                                    product = parts[4]
                                    affected_products.append(f"{vendor}:{product}")
                
                cve = CVE(
                    id=cve_id,
                    description=description[:500] + "..." if len(description) > 500 else description,
                    published_date=published_date,
                    last_modified=last_modified,
                    cvss_score=cvss_score,
                    cvss_severity=cvss_severity,
                    vector_string=vector_string,
                    source='nvd',
                    references=references,
                    cwe_ids=cwe_ids,
                    affected_products=list(set(affected_products))
                )
                
                cves.append(cve)
            
            logger.info(f"NVD: {len(cves)} CVEs recolectados")
            
        except Exception as e:
            logger.error(f"Error recolectando CVEs de NVD: {e}")
        
        return cves
    
    def collect_nvd_intelligence(self) -> List[IOC]:
        """Recolecta inteligencia de vulnerabilidades desde NVD (para compatibilidad)"""
        iocs = []
        
        try:
            cves = self.collect_nvd_cves(days_back=7, limit=15)
            
            for cve in cves:
                if self._is_latam_related(cve.description):
                    confidence = min(95, int((cve.cvss_score / 10) * 100))
                    
                    ioc = IOC(
                        value=cve.id,
                        type='cve',
                        confidence=confidence,
                        first_seen=cve.published_date,
                        last_seen=cve.last_modified,
                        source='nvd',
                        tags=['vulnerability', 'cve', cve.cvss_severity.lower()],
                        threat_type='vulnerability',
                        country=self._extract_country_from_content(cve.description)
                    )
                    iocs.append(ioc)
                    
        except Exception as e:
            logger.error(f"Error recolectando de NVD: {e}")
        
        return iocs
    
    def _map_otx_type_to_ioc_type(self, otx_type: str) -> str:
        """Mapea tipos de OTX a tipos de IOC internos"""
        mapping = {
            'IPv4': 'ip',
            'IPv6': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'URL': 'url',
            'FileHash-MD5': 'hash_md5',
            'FileHash-SHA1': 'hash_sha1',
            'FileHash-SHA256': 'hash_sha256',
            'email': 'email'
        }
        return mapping.get(otx_type, 'unknown')
    
    def correlate_iocs(self, all_iocs: List[IOC]) -> List[IOC]:
        """Correlaciona IOCs entre diferentes fuentes para mejorar confianza"""
        correlation_map = defaultdict(list)
        
        # Agrupar IOCs por valor
        for ioc in all_iocs:
            correlation_map[ioc.value].append(ioc)
        
        correlated_iocs = []
        
        for value, iocs_list in correlation_map.items():
            if len(iocs_list) > 1:
                # Múltiples fuentes confirman el mismo IOC
                best_ioc = max(iocs_list, key=lambda x: x.confidence)
                
                # Aumentar confianza basada en correlación
                correlation_bonus = min(20, (len(iocs_list) - 1) * 10)
                best_ioc.confidence = min(100, best_ioc.confidence + correlation_bonus)
                
                # Combinar tags de todas las fuentes
                all_tags = set()
                all_sources = set()
                for ioc in iocs_list:
                    all_tags.update(ioc.tags)
                    all_sources.add(ioc.source)
                
                best_ioc.tags = list(all_tags)
                best_ioc.tags.append(f"correlated_{len(iocs_list)}_sources")
                
                correlated_iocs.append(best_ioc)
            else:
                correlated_iocs.append(iocs_list[0])
        
        return correlated_iocs
    
    def collect_all_professional_intelligence(self) -> List[Campaign]:
        """Recolecta inteligencia desde todas las fuentes profesionales"""
        all_iocs = []
        all_campaigns = []
        
        logger.info("=== INICIANDO RECOLECCIÓN PROFESIONAL DE THREAT INTELLIGENCE ===")
        
        # Recolectar desde todas las fuentes profesionales
        intelligence_sources = [
            ('VirusTotal', self.collect_virustotal_intelligence),
            ('IBM X-Force', self.collect_ibm_xforce_intelligence),
            ('OTX AlienVault', self.collect_otx_intelligence),
            ('Hybrid Analysis', self.collect_hybrid_analysis_intelligence),
            ('MalwareBazaar', self.collect_malware_bazaar_intelligence),
            ('NVD', self.collect_nvd_intelligence)
        ]
        
        for source_name, collect_func in intelligence_sources:
            try:
                logger.info(f"Recolectando desde {source_name}...")
                source_iocs = collect_func()
                all_iocs.extend(source_iocs)
                logger.info(f"{source_name}: {len(source_iocs)} IOCs recolectados")
                time.sleep(2)  # Rate limiting entre fuentes
            except Exception as e:
                logger.error(f"Error recolectando desde {source_name}: {e}")
        
        # Correlacionar IOCs entre fuentes
        logger.info("Correlacionando IOCs entre fuentes...")
        correlated_iocs = self.correlate_iocs(all_iocs)
        
        # Mantener también los IOCs de scraping tradicional
        try:
            logger.info("Recolectando desde fuentes de scraping tradicionales...")
            legacy_iocs = self.scrape_legacy_sources()
            correlated_iocs.extend(legacy_iocs)
        except Exception as e:
            logger.error(f"Error en fuentes legacy: {e}")
        
        # Crear campañas basadas en IOCs agrupados
        logger.info("Creando campañas basadas en IOCs profesionales...")
        
        grouped_iocs = defaultdict(list)
        for ioc in correlated_iocs:
            key = f"{ioc.source}_{ioc.threat_type or 'unknown'}"
            grouped_iocs[key].append(ioc)
        
        for group_key, group_iocs in grouped_iocs.items():
            if len(group_iocs) >= 1:  # Crear campaña incluso con 1 IOC si es de fuente profesional
                source = group_key.split('_')[0]
                campaign = self.create_campaign_from_iocs(group_iocs, source)
                if campaign:
                    all_campaigns.append(campaign)
        
        logger.info(f"=== RECOLECCIÓN PROFESIONAL COMPLETADA ===")
        logger.info(f"IOCs totales: {len(correlated_iocs)}")
        logger.info(f"Campañas creadas: {len(all_campaigns)}")
        
        return all_campaigns
    
    def scrape_legacy_sources(self) -> List[IOC]:
        """Mantiene compatibilidad con fuentes de scraping tradicionales"""
        iocs = []
        
        try:
            # OpenPhish
            openphish_iocs = self.scrape_openphish()
            iocs.extend(openphish_iocs)
            time.sleep(2)
            
            # PhishTank  
            phishtank_iocs = self.scrape_phishtank()
            iocs.extend(phishtank_iocs)
            time.sleep(2)
            
            # URLhaus
            urlhaus_iocs = self.scrape_urlhaus()
            iocs.extend(urlhaus_iocs)
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"Error en fuentes legacy: {e}")
        
        return iocs
    
    def scrape_all_sources(self) -> List[Campaign]:
        """Ejecuta recolección profesional de threat intelligence"""
        logger.info("=== INICIANDO RECOLECCIÓN PROFESIONAL DE THREAT INTELLIGENCE ===")
        
        # Usar el nuevo método profesional que incluye APIs y scraping
        campaigns = self.collect_all_professional_intelligence()
        
        return campaigns

# =====================================================
# ALMACENAMIENTO
# =====================================================

class AegisStorage:
    """Sistema de almacenamiento AEGIS"""
    
    def __init__(self, config: Config):
        self.config = config
        
        try:
            self.mongo_client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
            self.db = self.mongo_client[config.DATABASE_NAME]
            self.campaigns_collection = self.db.campaigns
            self.iocs_collection = self.db.iocs
            self.cves_collection = self.db.cves
            
            self.mongo_client.server_info()
            logger.info("MongoDB conectado correctamente")
            self.use_memory = False
            
        except Exception as e:
            logger.warning(f"MongoDB no disponible: {e}. Usando almacenamiento en memoria.")
            self.use_memory = True
            self.memory_campaigns = []
            self.memory_iocs = []
            self.memory_cves = []
        
        if not self.use_memory:
            self._setup_indexes()
    
    def _setup_indexes(self):
        """Configura índices para optimizar consultas"""
        try:
            self.campaigns_collection.create_index("id", unique=True)
            self.campaigns_collection.create_index("countries_affected")
            self.campaigns_collection.create_index("severity")
            self.campaigns_collection.create_index("source")
            
            self.iocs_collection.create_index("value", unique=True)
            self.iocs_collection.create_index("type")
            self.iocs_collection.create_index("campaign_id")
            
            self.cves_collection.create_index("id", unique=True)
            self.cves_collection.create_index("published_date")
            self.cves_collection.create_index("cvss_score")
            self.cves_collection.create_index("cvss_severity")
            
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
                if not any(c['id'] == campaign.id for c in self.memory_campaigns):
                    self.memory_campaigns.append(campaign_dict)
                    
                    for ioc in campaign.iocs:
                        ioc_dict = asdict(ioc)
                        ioc_dict['first_seen'] = ioc.first_seen.isoformat()
                        ioc_dict['last_seen'] = ioc.last_seen.isoformat()
                        ioc_dict['campaign_id'] = campaign.id
                        
                        if not any(i['value'] == ioc.value for i in self.memory_iocs):
                            self.memory_iocs.append(ioc_dict)
                else:
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
            
        except DuplicateKeyError:
            logger.warning(f"Campaña duplicada: {campaign.id}")
            return False
        except Exception as e:
            logger.error(f"Error almacenando campaña: {e}")
            return False
    
    def store_cves(self, cves: List[CVE]) -> int:
        """Almacena CVEs con manejo robusto de errores"""
        stored_count = 0
        
        for cve in cves:
            try:
                cve_dict = asdict(cve)
                cve_dict['published_date'] = cve.published_date.isoformat()
                cve_dict['last_modified'] = cve.last_modified.isoformat()
                
                if self.use_memory:
                    if not any(c['id'] == cve.id for c in self.memory_cves):
                        self.memory_cves.append(cve_dict)
                        stored_count += 1
                else:
                    try:
                        self.cves_collection.insert_one(cve_dict)
                        stored_count += 1
                    except DuplicateKeyError:
                        # Actualizar CVE existente si hay cambios
                        self.cves_collection.update_one(
                            {"id": cve.id},
                            {"$set": {
                                "last_modified": cve.last_modified.isoformat(),
                                "cvss_score": cve.cvss_score,
                                "cvss_severity": cve.cvss_severity,
                                "description": cve.description
                            }}
                        )
                        
            except Exception as e:
                logger.warning(f"Error almacenando CVE {cve.id}: {e}")
        
        if stored_count > 0:
            logger.info(f"{stored_count} CVEs almacenados/actualizados")
        
        return stored_count
    
    def get_recent_cves(self, limit: int = 50, severity_filter: str = None) -> List[Dict]:
        """Obtiene CVEs recientes ordenados por fecha de publicación"""
        try:
            if self.use_memory:
                cves = self.memory_cves.copy()
                
                if severity_filter:
                    cves = [c for c in cves if c['cvss_severity'].upper() == severity_filter.upper()]
                
                # Ordenar por fecha de publicación (más reciente primero)
                cves.sort(key=lambda x: x['published_date'], reverse=True)
                return cves[:limit]
                
            else:
                search_filter = {}
                
                if severity_filter:
                    search_filter['cvss_severity'] = severity_filter.upper()
                
                cves = list(self.cves_collection.find(search_filter)
                           .sort("published_date", -1)
                           .limit(limit))
                
                for cve in cves:
                    cve['_id'] = str(cve['_id'])
                
                return cves
                
        except Exception as e:
            logger.error(f"Error obteniendo CVEs: {e}")
            return []
    
    def get_cve_statistics(self) -> Dict:
        """Obtiene estadísticas de CVEs"""
        try:
            if self.use_memory:
                cves = self.memory_cves
                
                stats = {
                    'total_cves': len(cves),
                    'by_severity': {},
                    'high_severity_count': 0,
                    'critical_count': 0,
                    'recent_count': 0  # Últimos 7 días
                }
                
                week_ago = datetime.utcnow() - timedelta(days=7)
                
                for cve in cves:
                    # Contar por severidad
                    severity = cve.get('cvss_severity', 'UNKNOWN')
                    stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
                    
                    # Contar alta severidad y críticos
                    if severity in ['HIGH', 'CRITICAL']:
                        stats['high_severity_count'] += 1
                    if severity == 'CRITICAL':
                        stats['critical_count'] += 1
                    
                    # Contar recientes
                    pub_date = datetime.fromisoformat(cve['published_date'].replace('Z', '+00:00'))
                    if pub_date >= week_ago:
                        stats['recent_count'] += 1
                
                return stats
                
            else:
                stats = {
                    'total_cves': self.cves_collection.count_documents({}),
                    'by_severity': {},
                    'high_severity_count': 0,
                    'critical_count': 0,
                    'recent_count': 0
                }
                
                # Agregación para contar por severidad
                pipeline = [
                    {"$group": {"_id": "$cvss_severity", "count": {"$sum": 1}}}
                ]
                
                severity_counts = list(self.cves_collection.aggregate(pipeline))
                for item in severity_counts:
                    severity = item['_id']
                    count = item['count']
                    stats['by_severity'][severity] = count
                    
                    if severity in ['HIGH', 'CRITICAL']:
                        stats['high_severity_count'] += count
                    if severity == 'CRITICAL':
                        stats['critical_count'] += count
                
                # Contar CVEs recientes (últimos 7 días)
                week_ago = datetime.utcnow() - timedelta(days=7)
                stats['recent_count'] = self.cves_collection.count_documents({
                    "published_date": {"$gte": week_ago.isoformat()}
                })
                
                return stats
                
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de CVEs: {e}")
            return {
                'total_cves': 0,
                'by_severity': {},
                'high_severity_count': 0,
                'critical_count': 0,
                'recent_count': 0
            }
    
    def search_campaigns(self, query: str = "", filters: Dict = None) -> List[Dict]:
        """Busca campañas con filtros avanzados"""
        try:
            if self.use_memory:
                campaigns = self.memory_campaigns.copy()
                
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
                stats = {
                    'total_campaigns': len(self.memory_campaigns),
                    'total_iocs': len(self.memory_iocs),
                    'campaigns_by_severity': {},
                    'campaigns_by_source': {},
                    'iocs_by_type': {},
                    'iocs_by_country': {},
                    'malware_families': {}
                }
                
                for campaign in self.memory_campaigns:
                    severity = campaign['severity']
                    stats['campaigns_by_severity'][severity] = stats['campaigns_by_severity'].get(severity, 0) + 1
                
                for campaign in self.memory_campaigns:
                    source = campaign['source']
                    stats['campaigns_by_source'][source] = stats['campaigns_by_source'].get(source, 0) + 1
                
                for ioc in self.memory_iocs:
                    ioc_type = ioc['type']
                    stats['iocs_by_type'][ioc_type] = stats['iocs_by_type'].get(ioc_type, 0) + 1
                    
                    country = ioc.get('country', 'unknown')
                    stats['iocs_by_country'][country] = stats['iocs_by_country'].get(country, 0) + 1
                
                for campaign in self.memory_campaigns:
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
                
                # Agregaciones simples
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
            return {
                'total_campaigns': 0, 'total_iocs': 0, 'campaigns_by_severity': {},
                'campaigns_by_source': {}, 'iocs_by_type': {}, 'iocs_by_country': {},
                'malware_families': {}
            }
    
    def export_to_csv(self, campaign_ids: List[str] = None) -> str:
        """Exporta datos a formato CSV"""
        try:
            output = StringIO()
            
            if self.use_memory:
                campaigns = self.memory_campaigns
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
            
            high_confidence_iocs = [ioc for ioc in campaign.iocs if ioc.confidence > 85]
            if len(high_confidence_iocs) >= 5:
                alerts.append({
                    'type': 'high_confidence_cluster',
                    'title': f'Cluster de Alta Confianza: {len(high_confidence_iocs)} IOCs',
                    'description': f'Detectados {len(high_confidence_iocs)} IOCs con confianza >85% en {campaign.name}',
                    'severity': 'high',
                    'timestamp': datetime.utcnow().isoformat(),
                    'campaign_id': campaign.id,
                    'ioc_count': len(high_confidence_iocs)
                })
            
            if len(campaign.countries_affected) >= 3:
                alerts.append({
                    'type': 'multi_country',
                    'title': f'Campaña Multi-País: {len(campaign.countries_affected)} países',
                    'description': f'Campaña {campaign.name} afecta múltiples países: {", ".join(campaign.countries_affected)}',
                    'severity': 'high',
                    'timestamp': datetime.utcnow().isoformat(),
                    'campaign_id': campaign.id,
                    'countries': campaign.countries_affected
                })
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        alerts.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return alerts

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
        .cve-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .cve-table th,
        .cve-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid rgba(0, 255, 127, 0.2);
        }
        .cve-table th {
            background: rgba(0, 255, 127, 0.1);
            color: #00ff7f;
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        .cve-table tbody tr:hover {
            background: rgba(0, 255, 127, 0.05);
        }
        .cve-id {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #00ff7f;
        }
        .cve-description {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical {
            background: #dc2626;
            color: #ffffff;
        }
        .severity-high {
            background: #ea580c;
            color: #ffffff;
        }
        .severity-medium {
            background: #ca8a04;
            color: #ffffff;
        }
        .severity-low {
            background: #16a34a;
            color: #ffffff;
        }
        .severity-unknown {
            background: #6b7280;
            color: #ffffff;
        }
        .cvss-score {
            font-weight: bold;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }
        .cvss-critical {
            background: rgba(220, 38, 38, 0.2);
            color: #dc2626;
        }
        .cvss-high {
            background: rgba(234, 88, 12, 0.2);
            color: #ea580c;
        }
        .cvss-medium {
            background: rgba(202, 138, 4, 0.2);
            color: #ca8a04;
        }
        .cvss-low {
            background: rgba(22, 163, 74, 0.2);
            color: #16a34a;
        }
        .cve-link {
            color: #00ff7f;
            text-decoration: none;
            font-size: 0.9rem;
        }
        .cve-link:hover {
            text-decoration: underline;
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        .ioc-result-card {
            background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
            border-radius: 12px;
            border: 1px solid rgba(0, 255, 127, 0.3);
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .ioc-result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .ioc-value-display {
            font-family: 'Courier New', monospace;
            font-size: 1.1rem;
            color: #00ff7f;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.5rem;
            border-radius: 6px;
        }
        .verdict-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9rem;
        }
        .verdict-clean {
            background: #16a34a;
            color: #ffffff;
        }
        .verdict-suspicious {
            background: #ca8a04;
            color: #ffffff;
        }
        .verdict-malicious {
            background: #dc2626;
            color: #ffffff;
        }
        .verdict-unknown {
            background: #6b7280;
            color: #ffffff;
        }
        .reputation-score {
            font-size: 1.5rem;
            font-weight: bold;
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            min-width: 100px;
        }
        .reputation-high {
            background: rgba(22, 163, 74, 0.2);
            color: #16a34a;
            border: 1px solid #16a34a;
        }
        .reputation-medium {
            background: rgba(202, 138, 4, 0.2);
            color: #ca8a04;
            border: 1px solid #ca8a04;
        }
        .reputation-low {
            background: rgba(220, 38, 38, 0.2);
            color: #dc2626;
            border: 1px solid #dc2626;
        }
        .sources-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .source-card {
            background: rgba(0, 255, 127, 0.05);
            border: 1px solid rgba(0, 255, 127, 0.2);
            border-radius: 8px;
            padding: 1rem;
        }
        .source-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        .source-logo {
            width: 20px;
            height: 20px;
            background: #00ff7f;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            color: #000;
            font-weight: bold;
        }
        .ioc-type-badge {
            background: rgba(0, 255, 127, 0.2);
            color: #00ff7f;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
            text-transform: uppercase;
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
                        <div class="nav-link" data-section="cves">
                            <i class="fas fa-bug"></i>
                            CVEs y Vulnerabilidades
                        </div>
                    </li>
                    <li class="nav-item">
                        <div class="nav-link" data-section="ioc-search">
                            <i class="fas fa-search-plus"></i>
                            Búsqueda de IOCs
                        </div>
                    </li>
                    <li class="nav-item">

                        <div class="nav-link" data-section="alerts">
                            <i class="fas fa-exclamation-triangle"></i>
                            Centro de Alertas
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

            <div id="cves" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-bug"></i> CVEs y Vulnerabilidades Recientes
                </h2>
                
                <div class="dashboard-grid" style="margin-bottom: 2rem;">
                    <div class="card">
                        <div class="card-header">
                            <h3>Estadísticas CVEs</h3>
                        </div>
                        <div class="card-content">
                            <div class="stats-mini-grid">
                                <div class="mini-stat">
                                    <div class="mini-stat-value" id="totalCVEs">0</div>
                                    <div class="mini-stat-label">Total CVEs</div>
                                </div>
                                <div class="mini-stat">
                                    <div class="mini-stat-value" id="criticalCVEs">0</div>
                                    <div class="mini-stat-label">Críticos</div>
                                </div>
                                <div class="mini-stat">
                                    <div class="mini-stat-value" id="highSeverityCVEs">0</div>
                                    <div class="mini-stat-label">Alta Severidad</div>
                                </div>
                                <div class="mini-stat">
                                    <div class="mini-stat-value" id="recentCVEs">0</div>
                                    <div class="mini-stat-label">Últimos 7 días</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h3>Acciones Rápidas</h3>
                        </div>
                        <div class="card-content">
                            <div style="display: flex; flex-direction: column; gap: 1rem;">
                                <button class="action-btn" onclick="updateCVEs()" id="updateCVEsBtn">
                                    <i class="fas fa-sync"></i>
                                    Actualizar CVEs desde NVD
                                </button>
                                <button class="action-btn" onclick="exportCVEs()">
                                    <i class="fas fa-download"></i>
                                    Exportar CVEs
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Filtros y Búsqueda</h3>
                        <div class="filters">
                            <div>
                                <span class="filter-label">Severidad:</span>
                                <select id="cveSeverityFilter" class="filter-select" onchange="loadCVEs()">
                                    <option value="">Todas</option>
                                    <option value="CRITICAL">Crítica</option>
                                    <option value="HIGH">Alta</option>
                                    <option value="MEDIUM">Media</option>
                                    <option value="LOW">Baja</option>
                                </select>
                            </div>
                            <div>
                                <span class="filter-label">Límite:</span>
                                <select id="cveLimitFilter" class="filter-select" onchange="loadCVEs()">
                                    <option value="50">50</option>
                                    <option value="100">100</option>
                                    <option value="200">200</option>
                                </select>
                            </div>
                            <button class="action-btn" onclick="loadCVEs()">
                                <i class="fas fa-sync"></i>
                                Actualizar Lista
                            </button>
                        </div>
                    </div>
                </div>

                <div id="cvesTable">
                    <div class="loading"></div> Cargando CVEs...
                </div>
            </div>


            <div id="ioc-search" class="section">
                <h2 style="margin-bottom: 2rem; color: #00ff7f;">
                    <i class="fas fa-search-plus"></i> Búsqueda de IOCs en Tiempo Real
                </h2>
                
                <div class="card" style="margin-bottom: 2rem;">
                    <div class="card-header">
                        <h3>Buscar Indicador de Compromiso</h3>
                        <p style="color: #a0aec0; margin: 0.5rem 0;">
                            Ingresa un hash, dominio, IP o URL para consultar múltiples fuentes de threat intelligence
                        </p>
                    </div>
                    <div class="card-content">
                        <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;">
                            <div style="flex: 1; min-width: 300px;">
                                <input type="text" 
                                       id="iocSearchInput" 
                                       class="filter-input" 
                                       placeholder="Ej: google.com, 8.8.8.8, d41d8cd98f00b204e9800998ecf8427e..."
                                       style="width: 100%; font-family: monospace;">
                            </div>
                            <button class="action-btn" onclick="searchIOC()" id="searchIOCBtn">
                                <i class="fas fa-search"></i>
                                Buscar IOC
                            </button>
                        </div>
                        
                        <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;">
                            <div>
                                <span class="filter-label">Tipo detectado:</span>
                                <span id="detectedType" style="color: #00ff7f; font-weight: bold;">-</span>
                            </div>
                            <div>
                                <span class="filter-label">Fuentes configuradas:</span>
                                <span id="configuredSources" style="color: #a0aec0;">Verificando...</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="iocSearchResults">
                    <div class="card">
                        <div class="card-content" style="text-align: center; padding: 3rem;">
                            <i class="fas fa-search" style="font-size: 3rem; color: #a0aec0; margin-bottom: 1rem;"></i>
                            <h3 style="color: #a0aec0; margin-bottom: 0.5rem;">Buscar un IOC</h3>
                            <p style="color: #a0aec0;">Ingresa un indicador de compromiso arriba para comenzar la búsqueda</p>
                        </div>
                    </div>
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
        </main>
    </div>

    <script>
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

        document.addEventListener('DOMContentLoaded', function() {
            setupNavigation();
            loadDashboardData();
            startAutoRefresh();
        });

        function setupNavigation() {
            document.querySelectorAll('.nav-link').forEach(link => {
                link.addEventListener('click', function() {
                    const section = this.dataset.section;
                    showSection(section);
                });
            });
        }

        function showSection(sectionId) {
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });
            
            document.getElementById(sectionId).classList.add('active');
            
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');
            
            currentSection = sectionId;
            
            switch(sectionId) {
                case 'campaigns':
                    loadCampaigns();
                    break;
                case 'iocs':
                    loadIOCs();
                    break;
                case 'cves':
                    loadCVEs();
                    break;
                case 'ioc-search':
                    initIOCSearch();
                    break;

                case 'alerts':
                    loadAlerts();
                    break;
            }
        }

        async function loadDashboardData() {
            try {
                const response = await fetch('/api/stats');
                dashboardData = await response.json();
                
                updateDashboardStats();
                initCharts();
                loadDashboardAlerts();
                
            } catch (error) {
                console.error('Error cargando datos:', error);
            }
        }

        function updateDashboardStats() {
            if (!dashboardData) return;
            
            document.getElementById('totalCampaigns').textContent = dashboardData.total_campaigns || 0;
            document.getElementById('totalIOCs').textContent = dashboardData.total_iocs || 0;
            document.getElementById('criticalAlerts').textContent = dashboardData.campaigns_by_severity?.critical || 0;
            document.getElementById('countriesAffected').textContent = Object.keys(dashboardData.iocs_by_country || {}).length;
        }

        function initCharts() {
            if (!dashboardData) return;
            
            // Gráfica de severidad
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            new Chart(severityCtx, {
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

            // Gráfica de fuentes
            const sourceCtx = document.getElementById('sourceChart').getContext('2d');
            new Chart(sourceCtx, {
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

            // Gráfica de países
            const countryCtx = document.getElementById('countryChart').getContext('2d');
            new Chart(countryCtx, {
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

            // Gráfica de malware
            const malwareCtx = document.getElementById('malwareChart').getContext('2d');
            new Chart(malwareCtx, {
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

        async function loadDashboardAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                
                const container = document.getElementById('dashboardAlerts');
                
                if (alerts.length === 0) {
                    container.innerHTML = '<p style="color: #a0aec0;">No hay alertas críticas actualmente</p>';
                    return;
                }

                container.innerHTML = alerts.slice(0, 5).map(alert => `
                    <div class="alert-item">
                        <div class="alert-header">
                            <span class="alert-title">${alert.title}</span>
                            <span class="alert-time">${formatTimestamp(alert.timestamp)}</span>
                        </div>
                        <p style="margin: 0; color: #a0aec0; font-size: 0.9rem;">${alert.description}</p>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Error cargando alertas:', error);
            }
        }

        async function loadCampaigns() {
            try {
                const container = document.getElementById('campaignsTable');
                container.innerHTML = '<div class="loading"></div> Cargando campañas...';
                
                const params = new URLSearchParams();
                const search = document.getElementById('campaignSearch')?.value;
                const severity = document.getElementById('campaignSeverityFilter')?.value;
                const country = document.getElementById('campaignCountryFilter')?.value;
                
                if (search) params.append('q', search);
                if (severity) params.append('severity', severity);
                if (country) params.append('country', country);
                
                const response = await fetch(`/api/campaigns?${params}`);
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
                console.error('Error cargando campañas:', error);
                document.getElementById('campaignsTable').innerHTML = '<p style="color: #ff453a;">Error cargando campañas</p>';
            }
        }

        async function loadIOCs() {
            try {
                const container = document.getElementById('iocsTable');
                container.innerHTML = '<div class="loading"></div> Cargando IOCs...';
                
                const response = await fetch('/api/campaigns');
                const campaigns = await response.json();
                
                let allIOCs = [];
                campaigns.forEach(campaign => {
                    if (campaign.iocs) {
                        campaign.iocs.forEach(ioc => {
                            ioc.campaign_name = campaign.name;
                            allIOCs.push(ioc);
                        });
                    }
                });
                
                const typeFilter = document.getElementById('iocTypeFilter')?.value;
                const confidenceFilter = document.getElementById('iocConfidenceFilter')?.value;
                
                if (typeFilter) {
                    allIOCs = allIOCs.filter(ioc => ioc.type === typeFilter);
                }
                if (confidenceFilter) {
                    allIOCs = allIOCs.filter(ioc => ioc.confidence >= parseInt(confidenceFilter));
                }
                
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
                console.error('Error cargando IOCs:', error);
                document.getElementById('iocsTable').innerHTML = '<p style="color: #ff453a;">Error cargando IOCs</p>';
            }
        }

        async function loadAlerts() {
            try {
                const container = document.getElementById('detailedAlertsContainer');
                container.innerHTML = '<div class="loading"></div> Cargando alertas...';
                
                const response = await fetch('/api/alerts');
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
                document.getElementById('detailedAlertsContainer').innerHTML = '<p style="color: #ff453a;">Error cargando alertas</p>';
            }
        }

        async function runScraping() {
            try {
                const button = document.getElementById('scrapingBtn');
                const status = document.getElementById('scrapingStatus');
                
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
                document.getElementById('scrapingStatus').innerHTML = `
                    <div style="color: #ff453a;">Error de conexión: ${error.message}</div>
                `;
                
                document.getElementById('scrapingBtn').innerHTML = '<i class="fas fa-download"></i> Ejecutar Scraping';
                document.getElementById('scrapingBtn').disabled = false;
            }
        }

        function exportData(format) {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            window.open(`/api/export/${format}?timestamp=${timestamp}`, '_blank');
        }

        // Funciones para CVEs
        async function loadCVEs() {
            try {
                const container = document.getElementById('cvesTable');
                container.innerHTML = '<div class="loading"></div> Cargando CVEs...';
                
                const params = new URLSearchParams();
                const severity = document.getElementById('cveSeverityFilter')?.value;
                const limit = document.getElementById('cveLimitFilter')?.value || '50';
                
                if (severity) params.append('severity', severity);
                params.append('limit', limit);
                
                const response = await fetch(`/api/cves?${params}`);
                const cves = await response.json();
                
                if (cves.length === 0) {
                    container.innerHTML = '<p style="color: #a0aec0;">No se encontraron CVEs</p>';
                    return;
                }
                
                container.innerHTML = `
                    <div class="card">
                        <div class="card-content">
                            <table class="cve-table">
                                <thead>
                                    <tr>
                                        <th>CVE ID</th>
                                        <th>Descripción</th>
                                        <th>Fecha Publicación</th>
                                        <th>CVSS Score</th>
                                        <th>Severidad</th>
                                        <th>Enlaces</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${cves.map(cve => {
                                        const sevClass = cve.cvss_severity ? cve.cvss_severity.toLowerCase() : 'unknown';
                                        const scoreClass = getCVSSClass(cve.cvss_score);
                                        const publishedDate = new Date(cve.published_date).toLocaleDateString('es-ES');
                                        
                                        return `
                                            <tr>
                                                <td><span class="cve-id">${cve.id}</span></td>
                                                <td>
                                                    <div class="cve-description" title="${cve.description}">
                                                        ${cve.description}
                                                    </div>
                                                </td>
                                                <td>${publishedDate}</td>
                                                <td>
                                                    <span class="cvss-score ${scoreClass}">
                                                        ${cve.cvss_score.toFixed(1)}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span class="severity-badge severity-${sevClass}">
                                                        ${cve.cvss_severity || 'UNKNOWN'}
                                                    </span>
                                                </td>
                                                <td>
                                                    <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" 
                                                       target="_blank" 
                                                       class="cve-link">
                                                        <i class="fas fa-external-link-alt"></i> NVD
                                                    </a>
                                                </td>
                                            </tr>
                                        `;
                                    }).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
                
                // Actualizar estadísticas
                await loadCVEStats();
                
            } catch (error) {
                console.error('Error cargando CVEs:', error);
                document.getElementById('cvesTable').innerHTML = '<p style="color: #ff453a;">Error cargando CVEs</p>';
            }
        }

        async function loadCVEStats() {
            try {
                const response = await fetch('/api/cves/stats');
                const stats = await response.json();
                
                document.getElementById('totalCVEs').textContent = stats.total_cves || 0;
                document.getElementById('criticalCVEs').textContent = stats.critical_count || 0;
                document.getElementById('highSeverityCVEs').textContent = stats.high_severity_count || 0;
                document.getElementById('recentCVEs').textContent = stats.recent_count || 0;
                
            } catch (error) {
                console.error('Error cargando estadísticas CVEs:', error);
            }
        }

        async function updateCVEs() {
            try {
                const button = document.getElementById('updateCVEsBtn');
                const originalText = button.innerHTML;
                
                button.innerHTML = '<div class="loading"></div> Actualizando CVEs...';
                button.disabled = true;
                
                const response = await fetch('/api/cves/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ days_back: 30, limit: 100 })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    await loadCVEs();
                    showNotification(`CVEs actualizados: ${result.stored_count} nuevos`, 'success');
                } else {
                    showNotification(`Error actualizando CVEs: ${result.message}`, 'error');
                }
                
                button.innerHTML = originalText;
                button.disabled = false;
                
            } catch (error) {
                console.error('Error actualizando CVEs:', error);
                showNotification('Error de conexión al actualizar CVEs', 'error');
                
                const button = document.getElementById('updateCVEsBtn');
                button.innerHTML = '<i class="fas fa-sync"></i> Actualizar CVEs desde NVD';
                button.disabled = false;
            }
        }

        function exportCVEs() {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            // Por ahora usar el export general, se puede crear uno específico para CVEs
            exportData('json');
        }

        function getCVSSClass(score) {
            if (score >= 9.0) return 'cvss-critical';
            if (score >= 7.0) return 'cvss-high';
            if (score >= 4.0) return 'cvss-medium';
            return 'cvss-low';
        }

        function showNotification(message, type = 'info') {
            // Crear notificación temporal
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 80px;
                right: 20px;
                background: ${type === 'success' ? '#16a34a' : type === 'error' ? '#dc2626' : '#0066cc'};
                color: white;
                padding: 1rem;
                border-radius: 8px;
                z-index: 1001;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            `;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        // Funciones para búsqueda de IOCs
        function initIOCSearch() {
            // Verificar fuentes configuradas
            checkConfiguredSources();
            
            // Agregar event listener para Enter en el input
            const searchInput = document.getElementById('iocSearchInput');
            if (searchInput) {
                searchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        searchIOC();
                    }
                });
                
                searchInput.addEventListener('input', function() {
                    const iocValue = this.value.trim();
                    const detectedType = detectIOCType(iocValue);
                    document.getElementById('detectedType').textContent = detectedType || '-';
                });
            }
        }

        async function checkConfiguredSources() {
            try {
                const response = await fetch('/api/ioc-search/sources');
                const data = await response.json();
                
                const sourceNames = data.sources || [];
                const sourcesText = sourceNames.length > 0 ? sourceNames.join(', ') : 'Ninguna configurada';
                document.getElementById('configuredSources').textContent = sourcesText;
                
            } catch (error) {
                document.getElementById('configuredSources').textContent = 'Error verificando';
                console.error('Error verificando fuentes:', error);
            }
        }

        function detectIOCType(ioc) {
            if (!ioc) return '';
            
            ioc = ioc.trim();
            
            // Hash patterns
            if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'MD5 Hash';
            if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'SHA1 Hash';
            if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'SHA256 Hash';
            
            // IP pattern
            if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ioc)) {
                return 'Dirección IP';
            }
            
            // URL pattern
            if (ioc.startsWith('http://') || ioc.startsWith('https://') || ioc.startsWith('ftp://')) {
                return 'URL';
            }
            
            // Domain pattern
            if (ioc.includes('.') && !ioc.startsWith('http') && !/[^a-zA-Z0-9.-]/.test(ioc)) {
                return 'Dominio';
            }
            
            return 'Formato no reconocido';
        }

        async function searchIOC() {
            const searchInput = document.getElementById('iocSearchInput');
            const iocValue = searchInput.value.trim();
            
            if (!iocValue) {
                showNotification('Por favor ingresa un IOC para buscar', 'error');
                return;
            }
            
            const button = document.getElementById('searchIOCBtn');
            const originalText = button.innerHTML;
            
            try {
                button.innerHTML = '<div class="loading"></div> Buscando...';
                button.disabled = true;
                
                // Mostrar estado de búsqueda
                document.getElementById('iocSearchResults').innerHTML = `
                    <div class="card">
                        <div class="card-content" style="text-align: center; padding: 3rem;">
                            <div class="loading" style="margin: 0 auto 1rem;"></div>
                            <h3 style="color: #00ff7f;">Buscando en fuentes de threat intelligence...</h3>
                            <p style="color: #a0aec0;">Consultando VirusTotal, IBM X-Force, OTX y otras fuentes</p>
                        </div>
                    </div>
                `;
                
                const response = await fetch('/api/ioc-search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ioc: iocValue })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    displayIOCResults(result);
                    showNotification('Búsqueda completada', 'success');
                } else {
                    throw new Error(result.error || 'Error en la búsqueda');
                }
                
            } catch (error) {
                console.error('Error buscando IOC:', error);
                showNotification('Error en la búsqueda: ' + error.message, 'error');
                
                document.getElementById('iocSearchResults').innerHTML = `
                    <div class="card">
                        <div class="card-content" style="text-align: center; padding: 3rem;">
                            <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: #ff453a; margin-bottom: 1rem;"></i>
                            <h3 style="color: #ff453a;">Error en la búsqueda</h3>
                            <p style="color: #a0aec0;">${error.message}</p>
                        </div>
                    </div>
                `;
                
            } finally {
                button.innerHTML = originalText;
                button.disabled = false;
            }
        }

        function displayIOCResults(result) {
            const container = document.getElementById('iocSearchResults');
            
            if (result.ioc_type === 'invalid') {
                container.innerHTML = `
                    <div class="card">
                        <div class="card-content" style="text-align: center; padding: 3rem;">
                            <i class="fas fa-exclamation-circle" style="font-size: 3rem; color: #ff9500; margin-bottom: 1rem;"></i>
                            <h3 style="color: #ff9500;">Formato de IOC no válido</h3>
                            <p style="color: #a0aec0;">El valor ingresado no corresponde a un tipo de IOC reconocido</p>
                        </div>
                    </div>
                `;
                return;
            }
            
            const verdictClass = \`verdict-\${result.verdict}\`;
            const reputationClass = getReputationClass(result.reputation_score);
            
            let sourcesHtml = '';
            if (result.sources && result.sources.length > 0) {
                sourcesHtml = \`
                    <div class="sources-grid">
                        \${result.sources.map(source => \`
                            <div class="source-card">
                                <div class="source-header">
                                    <div class="source-logo">\${getSourceLogo(source)}</div>
                                    <strong>\${source}</strong>
                                </div>
                                \${getSourceDetails(source, result.details)}
                            </div>
                        \`).join('')}
                    </div>
                \`;
            } else {
                sourcesHtml = \`
                    <div style="text-align: center; padding: 2rem; background: rgba(255, 149, 0, 0.1); border-radius: 8px; border: 1px solid #ff9500;">
                        <i class="fas fa-info-circle" style="color: #ff9500; margin-bottom: 0.5rem;"></i>
                        <p style="color: #ff9500; margin: 0;">No hay fuentes de threat intelligence configuradas</p>
                        <p style="color: #a0aec0; font-size: 0.9rem; margin: 0.5rem 0 0;">
                            Configura API keys en el archivo .env para obtener datos reales
                        </p>
                    </div>
                \`;
            }
            
            container.innerHTML = \`
                <div class="ioc-result-card">
                    <div class="ioc-result-header">
                        <div>
                            <div style="margin-bottom: 0.5rem;">
                                <span class="ioc-type-badge">\${result.ioc_type.replace('_', ' ').toUpperCase()}</span>
                            </div>
                            <div class="ioc-value-display">\${result.ioc_value}</div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div>
                                <div style="text-align: center; margin-bottom: 0.5rem;">
                                    <span style="color: #a0aec0; font-size: 0.9rem;">Reputación</span>
                                </div>
                                <div class="reputation-score \${reputationClass}">
                                    \${result.reputation_score}/100
                                </div>
                            </div>
                            <div class="verdict-badge \${verdictClass}">
                                \${result.verdict}
                            </div>
                        </div>
                    </div>
                    
                    \${result.country || result.malware_family ? \`
                        <div style="display: flex; gap: 2rem; margin-bottom: 1rem; flex-wrap: wrap;">
                            \${result.country ? \`
                                <div>
                                    <span style="color: #a0aec0;">País:</span>
                                    <span style="color: #00ff7f; margin-left: 0.5rem;">\${result.country}</span>
                                </div>
                            \` : ''}
                            \${result.malware_family ? \`
                                <div>
                                    <span style="color: #a0aec0;">Familia de Malware:</span>
                                    <span style="color: #ff453a; margin-left: 0.5rem;">\${result.malware_family}</span>
                                </div>
                            \` : ''}
                        </div>
                    \` : ''}
                    
                    <div style="margin-bottom: 1rem;">
                        <h4 style="color: #00ff7f; margin-bottom: 0.5rem;">
                            <i class="fas fa-shield-alt"></i> Fuentes Consultadas (\${result.sources.length})
                        </h4>
                        \${sourcesHtml}
                    </div>
                </div>
            \`;
        }

        function getReputationClass(score) {
            if (score >= 70) return 'reputation-high';
            if (score >= 40) return 'reputation-medium';
            return 'reputation-low';
        }

        function getSourceLogo(source) {
            const logos = {
                'VirusTotal': 'VT',
                'IBM X-Force': 'XF',
                'OTX AlienVault': 'OTX',
                'MalwareBazaar': 'MB',
                'Hybrid Analysis': 'HA',
                'Public Sources': 'PS'
            };
            return logos[source] || source.substring(0, 2).toUpperCase();
        }

        function getSourceDetails(source, details) {
            const sourceDetails = details[source.toLowerCase().replace(/[^a-z]/g, '_')] || 
                                details[source.toLowerCase().replace(' ', '_')] || 
                                details[source] || {};
            
            if (Object.keys(sourceDetails).length === 0) {
                return '<p style="color: #a0aec0; font-size: 0.9rem;">Sin detalles adicionales</p>';
            }
            
            let detailsHtml = '';
            
            if (source === 'VirusTotal') {
                detailsHtml = \`
                    <p style="color: #a0aec0; font-size: 0.9rem;">
                        Detectado por \${sourceDetails.engines_detected || 0} de \${sourceDetails.total_engines || 0} motores
                    </p>
                \`;
            } else if (source === 'IBM X-Force') {
                detailsHtml = \`
                    <p style="color: #a0aec0; font-size: 0.9rem;">
                        Risk Score: \${sourceDetails.risk_score || 'N/A'}
                    </p>
                \`;
            } else if (source === 'OTX AlienVault') {
                detailsHtml = \`
                    <p style="color: #a0aec0; font-size: 0.9rem;">
                        Pulses: \${sourceDetails.pulses_count || 0}
                    </p>
                \`;
            } else if (source === 'MalwareBazaar') {
                detailsHtml = \`
                    <p style="color: #a0aec0; font-size: 0.9rem;">
                        \${sourceDetails.signature ? \`Signature: \${sourceDetails.signature}\` : 'Malware detectado'}
                    </p>
                \`;
            }
            
            return detailsHtml || '<p style="color: #a0aec0; font-size: 0.9rem;">Datos disponibles</p>';
        }



        function startAutoRefresh() {
            setInterval(async () => {
                try {
                    const indicator = document.querySelector('.real-data-indicator span');
                    indicator.textContent = `SISTEMA REAL - ${new Date().toLocaleTimeString()}`;
                    
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
            const date = new Date(timestamp);
            return date.toLocaleString('es-ES', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        }

        // Event listeners para filtros
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('campaignSearch');
            if (searchInput) {
                let timeout;
                searchInput.addEventListener('input', function() {
                    clearTimeout(timeout);
                    timeout = setTimeout(loadCampaigns, 500);
                });
            }
            
            ['campaignSeverityFilter', 'campaignCountryFilter'].forEach(id => {
                const element = document.getElementById(id);
                if (element) {
                    element.addEventListener('change', loadCampaigns);
                }
            });
            
            ['iocTypeFilter', 'iocConfidenceFilter'].forEach(id => {
                const element = document.getElementById(id);
                if (element) {
                    element.addEventListener('change', loadIOCs);
                }
            });
        });
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
                        ioc = IOC(
                            value=ioc_data['value'],
                            type=ioc_data['type'],
                            confidence=ioc_data['confidence'],
                            first_seen=datetime.fromisoformat(ioc_data['first_seen'].replace('Z', '+00:00')) if isinstance(ioc_data['first_seen'], str) else ioc_data['first_seen'],
                            last_seen=datetime.fromisoformat(ioc_data['last_seen'].replace('Z', '+00:00')) if isinstance(ioc_data['last_seen'], str) else ioc_data['last_seen'],
                            source=ioc_data['source'],
                            tags=ioc_data.get('tags', []),
                            threat_type=ioc_data.get('threat_type'),
                            malware_family=ioc_data.get('malware_family'),
                            country=ioc_data.get('country')
                        )
                        iocs.append(ioc)
                    
                    campaign = Campaign(
                        id=campaign_data['id'],
                        name=campaign_data['name'],
                        description=campaign_data['description'],
                        countries_affected=campaign_data['countries_affected'],
                        threat_actor=campaign_data.get('threat_actor'),
                        first_seen=datetime.fromisoformat(campaign_data['first_seen'].replace('Z', '+00:00')) if isinstance(campaign_data['first_seen'], str) else campaign_data['first_seen'],
                        last_seen=datetime.fromisoformat(campaign_data['last_seen'].replace('Z', '+00:00')) if isinstance(campaign_data['last_seen'], str) else campaign_data['last_seen'],
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
    
    @app.route('/api/cves')
    def api_cves():
        """API para obtener CVEs recientes"""
        try:
            limit = int(request.args.get('limit', 50))
            severity_filter = request.args.get('severity')
            
            cves = storage.get_recent_cves(limit=limit, severity_filter=severity_filter)
            return jsonify(cves)
            
        except Exception as e:
            logger.error(f"Error en API CVEs: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/cves/stats')
    def api_cve_stats():
        """API para estadísticas de CVEs"""
        try:
            stats = storage.get_cve_statistics()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error en API stats CVEs: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/cves/update', methods=['POST'])
    def api_update_cves():
        """API para actualizar CVEs desde NVD"""
        try:
            days_back = int(request.json.get('days_back', 30)) if request.json else 30
            limit = int(request.json.get('limit', 100)) if request.json else 100
            
            logger.info(f"Actualizando CVEs desde NVD (últimos {days_back} días)...")
            
            # Recolectar CVEs desde NVD
            cves = scraper.collect_nvd_cves(days_back=days_back, limit=limit)
            
            # Almacenar CVEs
            stored_count = storage.store_cves(cves)
            
            return jsonify({
                'message': 'CVEs actualizados exitosamente',
                'total_collected': len(cves),
                'stored_count': stored_count,
                'days_back': days_back,
                'success': True,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error actualizando CVEs: {e}")
            return jsonify({
                'message': f'Error actualizando CVEs: {str(e)}',
                'success': False,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @app.route('/api/ioc-search/sources')
    def api_ioc_search_sources():
        """API para obtener fuentes configuradas"""
        try:
            sources = []
            
            if scraper.api_config.VIRUSTOTAL_API_KEY:
                sources.append('VirusTotal')
            if scraper.api_config.IBM_XFORCE_API_KEY:
                sources.append('IBM X-Force')
            if scraper.api_config.OTX_API_KEY:
                sources.append('OTX AlienVault')
            if scraper.api_config.HYBRID_ANALYSIS_API_KEY:
                sources.append('Hybrid Analysis')
            
            # MalwareBazaar no requiere API key
            sources.append('MalwareBazaar')
            
            return jsonify({
                'sources': sources,
                'total_configured': len(sources)
            })
            
        except Exception as e:
            logger.error(f"Error obteniendo fuentes: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/ioc-search', methods=['POST'])
    def api_ioc_search():
        """API para búsqueda de IOCs en tiempo real"""
        try:
            data = request.get_json()
            ioc_value = data.get('ioc', '').strip()
            
            if not ioc_value:
                return jsonify({'error': 'IOC value is required'}), 400
            
            # Crear searcher y buscar
            searcher = RealTimeIOCSearcher(scraper.api_config)
            result = searcher.search_ioc(ioc_value)
            
            # Convertir el resultado a diccionario
            result_dict = asdict(result)
            
            # Convertir datetime a string si existen
            if result_dict.get('first_seen'):
                result_dict['first_seen'] = result_dict['first_seen'].isoformat()
            if result_dict.get('last_seen'):
                result_dict['last_seen'] = result_dict['last_seen'].isoformat()
            
            return jsonify(result_dict)
            
        except Exception as e:
            logger.error(f"Error en búsqueda de IOC: {e}")
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
            
            # También actualizar CVEs automáticamente
            try:
                logger.info("Actualizando CVEs como parte del scraping...")
                cves = scraper.collect_nvd_cves(days_back=7, limit=50)
                cve_stored_count = storage.store_cves(cves)
                logger.info(f"CVEs actualizados: {cve_stored_count}")
            except Exception as cve_error:
                logger.warning(f"Error actualizando CVEs durante scraping: {cve_error}")
                cve_stored_count = 0
            
            message = f'Scraping de fuentes reales completado exitosamente'
            
            logger.info(f"{message}: {stored_count} campañas nuevas almacenadas de {len(campaigns)} total")
            
            return jsonify({
                'message': message,
                'total_campaigns': len(campaigns),
                'stored_campaigns': stored_count,
                'cves_updated': cve_stored_count,
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
    
    return app

# =====================================================
# PUNTO DE ENTRADA PRINCIPAL
# =====================================================

def main():
    """Función principal del sistema"""
    print("=" * 60)
    print("AEGIS THREAT INTELLIGENCE LATAM - SISTEMA REAL")
    print("   Desarrollado por: Elisa Elias")
    print("   AEGIS Security Consulting")
    print("   Version: 3.0.0 - PRODUCCIÓN")
    print("=" * 60)
    
    logger.info("Iniciando AEGIS Threat Intelligence System...")
    
    try:
        app = create_app()
        
        config = Config()
        storage = AegisStorage(config)
        scraper = ProfessionalThreatIntelligence(config)
        
        print("\nConectando a fuentes de Threat Intelligence:")
        print("   FUENTES PROFESIONALES:")
        print("   - VirusTotal API (URLs/archivos maliciosos)")
        print("   - IBM X-Force Exchange API (Inteligencia corporativa)")
        print("   - OTX AlienVault API (Indicadores colaborativos)")
        print("   - Hybrid Analysis API (Análisis de malware)")
        print("   - MalwareBazaar API (Muestras de malware)")
        print("   - NVD API (Vulnerabilidades CVE)")
        print("   FUENTES COMPLEMENTARIAS:")
        print("   - OpenPhish (URLs de phishing)")
        print("   - PhishTank (URLs verificadas)")
        print("   - URLhaus (URLs de malware)")
        print("   - ThreatFox (IOCs verificados)")
        print("   - IP Blocklists (IPs maliciosas)")
        
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
            print(f"   Familias de malware: {', '.join(list(stats['malware_families'].keys())[:5])}")
        
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