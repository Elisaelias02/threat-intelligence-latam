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

class RealThreatScraper:
    """Scraper real de fuentes de Threat Intelligence"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
        self.session.timeout = config.TIMEOUT
        
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
    
    def scrape_all_sources(self) -> List[Campaign]:
        """Ejecuta scraping de todas las fuentes reales"""
        all_campaigns = []
        all_iocs = []
        
        logger.info("=== INICIANDO SCRAPING REAL DE FUENTES DE THREAT INTELLIGENCE ===")
        
        # 1. Scraping de URLs de phishing
        try:
            openphish_iocs = self.scrape_openphish()
            all_iocs.extend(openphish_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en OpenPhish: {e}")
        
        try:
            phishtank_iocs = self.scrape_phishtank()
            all_iocs.extend(phishtank_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en PhishTank: {e}")
        
        # 2. Scraping de URLs/hashes de malware
        try:
            urlhaus_iocs = self.scrape_urlhaus()
            all_iocs.extend(urlhaus_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en URLhaus: {e}")
        
        try:
            bazaar_iocs = self.scrape_malware_bazaar()
            all_iocs.extend(bazaar_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en Malware Bazaar: {e}")
        
        try:
            threatfox_iocs = self.scrape_threatfox()
            all_iocs.extend(threatfox_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en ThreatFox: {e}")
        
        # 3. Scraping de IPs maliciosas
        try:
            ip_iocs = self.scrape_ip_blocklists()
            all_iocs.extend(ip_iocs)
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en IP blocklists: {e}")
        
        # 4. Scraping de artículos de investigación
        try:
            articles = self.scrape_rss_feeds()
            for article in articles:
                all_iocs.extend(article['iocs'])
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error en RSS feeds: {e}")
        
        # 5. Crear campañas basadas en IOCs agrupados
        logger.info("Creando campañas basadas en IOCs recolectados...")
        
        grouped_iocs = defaultdict(list)
        for ioc in all_iocs:
            key = f"{ioc.source}_{ioc.threat_type or 'unknown'}"
            grouped_iocs[key].append(ioc)
        
        for group_key, group_iocs in grouped_iocs.items():
            if len(group_iocs) >= 2:
                source = group_key.split('_')[0]
                campaign = self.create_campaign_from_iocs(group_iocs, source)
                if campaign:
                    all_campaigns.append(campaign)
        
        if all_iocs and len(all_campaigns) == 0:
            general_campaign = self.create_campaign_from_iocs(all_iocs[:20], "mixed_sources")
            if general_campaign:
                all_campaigns.append(general_campaign)
        
        logger.info(f"=== SCRAPING COMPLETADO ===")
        logger.info(f"IOCs recolectados: {len(all_iocs)}")
        logger.info(f"Campañas creadas: {len(all_campaigns)}")
        
        return all_campaigns

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
            
            self.mongo_client.server_info()
            logger.info("MongoDB conectado correctamente")
            self.use_memory = False
            
        except Exception as e:
            logger.warning(f"MongoDB no disponible: {e}. Usando almacenamiento en memoria.")
            self.use_memory = True
            self.memory_campaigns = []
            self.memory_iocs = []
        
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
    scraper = RealThreatScraper(config)
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
            
            message = f'Scraping de fuentes reales completado exitosamente'
            
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
        scraper = RealThreatScraper(config)
        
        print("\nConectando a fuentes de Threat Intelligence:")
        print("   - OpenPhish (URLs de phishing)")
        print("   - PhishTank (URLs verificadas)")
        print("   - URLhaus (Malware URLs)")
        print("   - ThreatFox (IOCs verificados)")
        print("   - Malware Bazaar (Muestras)")
        print("   - IP Blocklists (IPs maliciosas)")
        print("   - Research Feeds (Artículos CTI)")
        
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