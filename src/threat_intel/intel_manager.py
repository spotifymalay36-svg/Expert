"""
Threat Intelligence Manager
Integrates with external threat feeds and STIX/TAXII standards
"""

import logging
import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import ipaddress
import re

import stix2
from taxii2_client.v20 import Collection, Server
import redis.asyncio as redis

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

class IOCType(str, Enum):
    IP_ADDRESS = "ip-addr"
    DOMAIN = "domain-name"
    URL = "url"
    FILE_HASH = "file"
    EMAIL = "email-addr"
    MUTEX = "mutex"
    REGISTRY_KEY = "windows-registry-key"

class ThreatCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "command-and-control"
    BOTNET = "botnet"
    APT = "apt"
    RANSOMWARE = "ransomware"
    EXPLOIT = "exploit"
    SUSPICIOUS = "suspicious"

@dataclass
class IOC:
    """Indicator of Compromise"""
    id: str
    type: IOCType
    value: str
    threat_category: ThreatCategory
    confidence: float
    severity: ThreatLevel
    first_seen: datetime
    last_seen: datetime
    source: str
    description: Optional[str] = None
    tags: List[str] = None
    ttl: Optional[int] = None  # Time to live in seconds

@dataclass
class ThreatIntelResult:
    """Threat intelligence lookup result"""
    is_malicious: bool
    ioc_type: IOCType
    description: str
    confidence: float
    severity: ThreatLevel
    sources: List[str]
    categories: List[ThreatCategory]
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

class ThreatIntelManager:
    """Threat Intelligence Manager with STIX/TAXII support"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Redis client for caching IOCs
        self.redis_client: Optional[redis.Redis] = None
        
        # In-memory IOC storage for fast lookup
        self.ioc_cache: Dict[str, IOC] = {}
        
        # Threat intelligence feeds
        self.threat_feeds = {
            'malware_domains': {
                'url': 'https://mirror1.malwaredomains.com/files/justdomains',
                'type': 'domain_list',
                'category': ThreatCategory.MALWARE,
                'update_interval': 3600  # 1 hour
            },
            'abuse_ch': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'type': 'ip_list',
                'category': ThreatCategory.C2,
                'update_interval': 1800  # 30 minutes
            },
            'phishtank': {
                'url': 'http://data.phishtank.com/data/online-valid.json',
                'type': 'phishing_urls',
                'category': ThreatCategory.PHISHING,
                'update_interval': 3600
            }
        }
        
        # TAXII servers
        self.taxii_servers = []
        
        # Feed update tasks
        self.feed_tasks: List[asyncio.Task] = []
        
        # Statistics
        self.stats = {
            'total_iocs': 0,
            'iocs_by_type': {},
            'iocs_by_category': {},
            'last_update': None,
            'feeds_status': {}
        }
        
        self.logger.info("Threat Intelligence Manager initialized")
    
    async def initialize(self):
        """Initialize threat intelligence manager"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.settings.redis_url)
            await self.redis_client.ping()
            
            # Load cached IOCs from Redis
            await self._load_cached_iocs()
            
            # Initialize TAXII connections
            await self._initialize_taxii_connections()
            
            # Start feed update tasks
            await self._start_feed_updates()
            
            self.logger.info("Threat Intelligence Manager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Threat Intelligence Manager: {e}")
            raise
    
    async def check_indicators(self, packet_info) -> ThreatIntelResult:
        """Check packet information against threat intelligence"""
        try:
            results = []
            
            # Check source IP
            if packet_info.src_ip:
                ip_result = await self._check_ip(packet_info.src_ip)
                if ip_result.is_malicious:
                    results.append(ip_result)
            
            # Check destination IP
            if packet_info.dst_ip:
                ip_result = await self._check_ip(packet_info.dst_ip)
                if ip_result.is_malicious:
                    results.append(ip_result)
            
            # Extract and check domains/URLs from payload
            if packet_info.payload:
                domains, urls = self._extract_network_indicators(packet_info.payload)
                
                for domain in domains:
                    domain_result = await self._check_domain(domain)
                    if domain_result.is_malicious:
                        results.append(domain_result)
                
                for url in urls:
                    url_result = await self._check_url(url)
                    if url_result.is_malicious:
                        results.append(url_result)
            
            # Return highest severity result
            if results:
                return max(results, key=lambda x: self._severity_to_int(x.severity))
            
            return ThreatIntelResult(
                is_malicious=False,
                ioc_type=IOCType.IP_ADDRESS,
                description="No threat intelligence matches",
                confidence=0.0,
                severity=ThreatLevel.LOW,
                sources=[],
                categories=[]
            )
            
        except Exception as e:
            self.logger.error(f"Error checking threat intelligence: {e}")
            return ThreatIntelResult(
                is_malicious=False,
                ioc_type=IOCType.IP_ADDRESS,
                description=f"Threat intelligence check error: {e}",
                confidence=0.0,
                severity=ThreatLevel.LOW,
                sources=[],
                categories=[]
            )
    
    async def _check_ip(self, ip_address: str) -> ThreatIntelResult:
        """Check IP address against threat intelligence"""
        try:
            # Normalize IP address
            try:
                ip = ipaddress.ip_address(ip_address)
                normalized_ip = str(ip)
            except ValueError:
                return self._create_clean_result(IOCType.IP_ADDRESS)
            
            # Check in cache first
            ioc = await self._get_ioc_from_cache(IOCType.IP_ADDRESS, normalized_ip)
            
            if ioc:
                return ThreatIntelResult(
                    is_malicious=True,
                    ioc_type=IOCType.IP_ADDRESS,
                    description=f"Malicious IP detected: {ioc.description or 'Known threat'}",
                    confidence=ioc.confidence,
                    severity=ioc.severity,
                    sources=[ioc.source],
                    categories=[ioc.threat_category],
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen
                )
            
            # Check against IP ranges (for efficiency, this could be optimized with IP trees)
            for cached_ioc in self.ioc_cache.values():
                if cached_ioc.type == IOCType.IP_ADDRESS:
                    try:
                        # Check if it's a CIDR range
                        if '/' in cached_ioc.value:
                            network = ipaddress.ip_network(cached_ioc.value, strict=False)
                            if ip in network:
                                return ThreatIntelResult(
                                    is_malicious=True,
                                    ioc_type=IOCType.IP_ADDRESS,
                                    description=f"IP in malicious range {cached_ioc.value}",
                                    confidence=cached_ioc.confidence,
                                    severity=cached_ioc.severity,
                                    sources=[cached_ioc.source],
                                    categories=[cached_ioc.threat_category]
                                )
                    except ValueError:
                        continue
            
            return self._create_clean_result(IOCType.IP_ADDRESS)
            
        except Exception as e:
            self.logger.error(f"Error checking IP {ip_address}: {e}")
            return self._create_clean_result(IOCType.IP_ADDRESS)
    
    async def _check_domain(self, domain: str) -> ThreatIntelResult:
        """Check domain against threat intelligence"""
        try:
            # Normalize domain
            normalized_domain = domain.lower().strip()
            
            # Check exact match
            ioc = await self._get_ioc_from_cache(IOCType.DOMAIN, normalized_domain)
            
            if ioc:
                return ThreatIntelResult(
                    is_malicious=True,
                    ioc_type=IOCType.DOMAIN,
                    description=f"Malicious domain detected: {ioc.description or 'Known threat'}",
                    confidence=ioc.confidence,
                    severity=ioc.severity,
                    sources=[ioc.source],
                    categories=[ioc.threat_category],
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen
                )
            
            # Check subdomain matches
            domain_parts = normalized_domain.split('.')
            for i in range(len(domain_parts)):
                parent_domain = '.'.join(domain_parts[i:])
                parent_ioc = await self._get_ioc_from_cache(IOCType.DOMAIN, parent_domain)
                
                if parent_ioc:
                    return ThreatIntelResult(
                        is_malicious=True,
                        ioc_type=IOCType.DOMAIN,
                        description=f"Subdomain of malicious domain {parent_domain}",
                        confidence=parent_ioc.confidence * 0.8,  # Slightly lower confidence
                        severity=parent_ioc.severity,
                        sources=[parent_ioc.source],
                        categories=[parent_ioc.threat_category]
                    )
            
            return self._create_clean_result(IOCType.DOMAIN)
            
        except Exception as e:
            self.logger.error(f"Error checking domain {domain}: {e}")
            return self._create_clean_result(IOCType.DOMAIN)
    
    async def _check_url(self, url: str) -> ThreatIntelResult:
        """Check URL against threat intelligence"""
        try:
            # Normalize URL
            normalized_url = url.lower().strip()
            
            # Check exact match
            ioc = await self._get_ioc_from_cache(IOCType.URL, normalized_url)
            
            if ioc:
                return ThreatIntelResult(
                    is_malicious=True,
                    ioc_type=IOCType.URL,
                    description=f"Malicious URL detected: {ioc.description or 'Known threat'}",
                    confidence=ioc.confidence,
                    severity=ioc.severity,
                    sources=[ioc.source],
                    categories=[ioc.threat_category],
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen
                )
            
            # Check URL patterns and partial matches
            for cached_ioc in self.ioc_cache.values():
                if cached_ioc.type == IOCType.URL:
                    # Check if current URL contains the malicious URL pattern
                    if cached_ioc.value in normalized_url:
                        return ThreatIntelResult(
                            is_malicious=True,
                            ioc_type=IOCType.URL,
                            description=f"URL contains malicious pattern: {cached_ioc.value}",
                            confidence=cached_ioc.confidence * 0.7,
                            severity=cached_ioc.severity,
                            sources=[cached_ioc.source],
                            categories=[cached_ioc.threat_category]
                        )
            
            return self._create_clean_result(IOCType.URL)
            
        except Exception as e:
            self.logger.error(f"Error checking URL {url}: {e}")
            return self._create_clean_result(IOCType.URL)
    
    def _extract_network_indicators(self, payload: bytes) -> tuple[List[str], List[str]]:
        """Extract domains and URLs from packet payload"""
        try:
            # Convert payload to string
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Extract domains using regex
            domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
            domains = re.findall(domain_pattern, payload_str)
            
            # Extract URLs using regex
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|ftp://[^\s<>"\']+'
            urls = re.findall(url_pattern, payload_str)
            
            # Clean and deduplicate
            domains = list(set([d.lower() for d in domains if len(d) > 3]))
            urls = list(set([u.lower() for u in urls if len(u) > 7]))
            
            return domains, urls
            
        except Exception as e:
            self.logger.error(f"Error extracting network indicators: {e}")
            return [], []
    
    async def _get_ioc_from_cache(self, ioc_type: IOCType, value: str) -> Optional[IOC]:
        """Get IOC from cache"""
        try:
            # Check in-memory cache first
            cache_key = f"{ioc_type.value}:{value}"
            
            if cache_key in self.ioc_cache:
                ioc = self.ioc_cache[cache_key]
                
                # Check if IOC has expired
                if ioc.ttl and ioc.last_seen:
                    expiry_time = ioc.last_seen + timedelta(seconds=ioc.ttl)
                    if datetime.now() > expiry_time:
                        # IOC expired, remove from cache
                        del self.ioc_cache[cache_key]
                        await self.redis_client.delete(f"ioc:{cache_key}")
                        return None
                
                return ioc
            
            # Check Redis cache
            redis_key = f"ioc:{cache_key}"
            cached_data = await self.redis_client.get(redis_key)
            
            if cached_data:
                ioc_data = json.loads(cached_data)
                ioc = IOC(**ioc_data)
                
                # Add to in-memory cache
                self.ioc_cache[cache_key] = ioc
                return ioc
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting IOC from cache: {e}")
            return None
    
    async def _store_ioc(self, ioc: IOC):
        """Store IOC in cache"""
        try:
            cache_key = f"{ioc.type.value}:{ioc.value}"
            
            # Store in memory
            self.ioc_cache[cache_key] = ioc
            
            # Store in Redis
            redis_key = f"ioc:{cache_key}"
            ioc_data = {
                'id': ioc.id,
                'type': ioc.type.value,
                'value': ioc.value,
                'threat_category': ioc.threat_category.value,
                'confidence': ioc.confidence,
                'severity': ioc.severity.value,
                'first_seen': ioc.first_seen.isoformat(),
                'last_seen': ioc.last_seen.isoformat(),
                'source': ioc.source,
                'description': ioc.description,
                'tags': ioc.tags or [],
                'ttl': ioc.ttl
            }
            
            # Set TTL in Redis
            ttl = ioc.ttl or 86400  # Default 24 hours
            await self.redis_client.setex(redis_key, ttl, json.dumps(ioc_data))
            
            # Update statistics
            self.stats['total_iocs'] += 1
            self.stats['iocs_by_type'][ioc.type.value] = self.stats['iocs_by_type'].get(ioc.type.value, 0) + 1
            self.stats['iocs_by_category'][ioc.threat_category.value] = self.stats['iocs_by_category'].get(ioc.threat_category.value, 0) + 1
            
        except Exception as e:
            self.logger.error(f"Error storing IOC: {e}")
    
    async def _load_cached_iocs(self):
        """Load IOCs from Redis cache"""
        try:
            # Get all IOC keys from Redis
            keys = await self.redis_client.keys("ioc:*")
            
            loaded_count = 0
            for key in keys:
                try:
                    cached_data = await self.redis_client.get(key)
                    if cached_data:
                        ioc_data = json.loads(cached_data)
                        
                        # Convert back to IOC object
                        ioc_data['type'] = IOCType(ioc_data['type'])
                        ioc_data['threat_category'] = ThreatCategory(ioc_data['threat_category'])
                        ioc_data['severity'] = ThreatLevel(ioc_data['severity'])
                        ioc_data['first_seen'] = datetime.fromisoformat(ioc_data['first_seen'])
                        ioc_data['last_seen'] = datetime.fromisoformat(ioc_data['last_seen'])
                        
                        ioc = IOC(**ioc_data)
                        
                        # Add to in-memory cache
                        cache_key = f"{ioc.type.value}:{ioc.value}"
                        self.ioc_cache[cache_key] = ioc
                        loaded_count += 1
                        
                except Exception as e:
                    self.logger.error(f"Error loading IOC from key {key}: {e}")
            
            self.logger.info(f"Loaded {loaded_count} IOCs from cache")
            
        except Exception as e:
            self.logger.error(f"Error loading cached IOCs: {e}")
    
    async def _initialize_taxii_connections(self):
        """Initialize TAXII server connections"""
        try:
            # Example TAXII server configuration
            # In production, these would come from configuration
            taxii_configs = [
                {
                    'name': 'MISP TAXII',
                    'url': 'https://misp.example.com/taxii2/',
                    'username': None,
                    'password': None
                }
            ]
            
            for config in taxii_configs:
                try:
                    server = Server(config['url'], user=config.get('username'), password=config.get('password'))
                    
                    # Test connection
                    api_root = server.api_roots[0] if server.api_roots else None
                    if api_root:
                        collections = api_root.collections
                        self.taxii_servers.append({
                            'name': config['name'],
                            'server': server,
                            'api_root': api_root,
                            'collections': collections
                        })
                        
                        self.logger.info(f"Connected to TAXII server: {config['name']}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to connect to TAXII server {config['name']}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error initializing TAXII connections: {e}")
    
    async def _start_feed_updates(self):
        """Start background tasks for feed updates"""
        try:
            for feed_name, feed_config in self.threat_feeds.items():
                task = asyncio.create_task(
                    self._update_feed_loop(feed_name, feed_config)
                )
                self.feed_tasks.append(task)
                
            # Start TAXII feed updates
            for taxii_server in self.taxii_servers:
                task = asyncio.create_task(
                    self._update_taxii_feed_loop(taxii_server)
                )
                self.feed_tasks.append(task)
            
            self.logger.info(f"Started {len(self.feed_tasks)} feed update tasks")
            
        except Exception as e:
            self.logger.error(f"Error starting feed updates: {e}")
    
    async def _update_feed_loop(self, feed_name: str, feed_config: Dict):
        """Update feed in a loop"""
        while True:
            try:
                await self._update_feed(feed_name, feed_config)
                self.stats['feeds_status'][feed_name] = {
                    'last_update': datetime.now().isoformat(),
                    'status': 'success'
                }
                
                # Wait for next update
                await asyncio.sleep(feed_config['update_interval'])
                
            except Exception as e:
                self.logger.error(f"Error updating feed {feed_name}: {e}")
                self.stats['feeds_status'][feed_name] = {
                    'last_update': datetime.now().isoformat(),
                    'status': f'error: {e}'
                }
                
                # Wait before retry
                await asyncio.sleep(300)  # 5 minutes
    
    async def _update_feed(self, feed_name: str, feed_config: Dict):
        """Update single threat intelligence feed"""
        try:
            self.logger.info(f"Updating threat feed: {feed_name}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_config['url']) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if feed_config['type'] == 'domain_list':
                            await self._process_domain_list(content, feed_config, feed_name)
                        elif feed_config['type'] == 'ip_list':
                            await self._process_ip_list(content, feed_config, feed_name)
                        elif feed_config['type'] == 'phishing_urls':
                            await self._process_phishing_urls(content, feed_config, feed_name)
                        
                        self.logger.info(f"Successfully updated feed: {feed_name}")
                    else:
                        self.logger.error(f"Failed to fetch feed {feed_name}: HTTP {response.status}")
            
        except Exception as e:
            self.logger.error(f"Error updating feed {feed_name}: {e}")
            raise
    
    async def _process_domain_list(self, content: str, feed_config: Dict, source: str):
        """Process domain list feed"""
        try:
            domains = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
            
            for domain in domains:
                if self._is_valid_domain(domain):
                    ioc = IOC(
                        id=hashlib.md5(f"{source}:{domain}".encode()).hexdigest(),
                        type=IOCType.DOMAIN,
                        value=domain.lower(),
                        threat_category=feed_config['category'],
                        confidence=0.8,
                        severity=ThreatLevel.MEDIUM,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source,
                        description=f"Malicious domain from {source}",
                        ttl=feed_config['update_interval'] * 2
                    )
                    
                    await self._store_ioc(ioc)
            
            self.logger.info(f"Processed {len(domains)} domains from {source}")
            
        except Exception as e:
            self.logger.error(f"Error processing domain list from {source}: {e}")
    
    async def _process_ip_list(self, content: str, feed_config: Dict, source: str):
        """Process IP list feed"""
        try:
            ips = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
            
            for ip in ips:
                if self._is_valid_ip(ip):
                    ioc = IOC(
                        id=hashlib.md5(f"{source}:{ip}".encode()).hexdigest(),
                        type=IOCType.IP_ADDRESS,
                        value=ip,
                        threat_category=feed_config['category'],
                        confidence=0.9,
                        severity=ThreatLevel.HIGH,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source,
                        description=f"Malicious IP from {source}",
                        ttl=feed_config['update_interval'] * 2
                    )
                    
                    await self._store_ioc(ioc)
            
            self.logger.info(f"Processed {len(ips)} IPs from {source}")
            
        except Exception as e:
            self.logger.error(f"Error processing IP list from {source}: {e}")
    
    async def _process_phishing_urls(self, content: str, feed_config: Dict, source: str):
        """Process phishing URLs feed"""
        try:
            # Assuming JSON format for phishing URLs
            data = json.loads(content)
            
            urls_processed = 0
            for entry in data:
                if isinstance(entry, dict) and 'url' in entry:
                    url = entry['url']
                    
                    ioc = IOC(
                        id=hashlib.md5(f"{source}:{url}".encode()).hexdigest(),
                        type=IOCType.URL,
                        value=url.lower(),
                        threat_category=ThreatCategory.PHISHING,
                        confidence=0.9,
                        severity=ThreatLevel.HIGH,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source,
                        description=f"Phishing URL from {source}",
                        ttl=feed_config['update_interval'] * 2
                    )
                    
                    await self._store_ioc(ioc)
                    urls_processed += 1
            
            self.logger.info(f"Processed {urls_processed} phishing URLs from {source}")
            
        except Exception as e:
            self.logger.error(f"Error processing phishing URLs from {source}: {e}")
    
    async def _update_taxii_feed_loop(self, taxii_server: Dict):
        """Update TAXII feed in a loop"""
        while True:
            try:
                await self._update_taxii_feed(taxii_server)
                
                # Wait 1 hour between TAXII updates
                await asyncio.sleep(3600)
                
            except Exception as e:
                self.logger.error(f"Error updating TAXII feed {taxii_server['name']}: {e}")
                await asyncio.sleep(1800)  # 30 minutes retry
    
    async def _update_taxii_feed(self, taxii_server: Dict):
        """Update TAXII feed"""
        try:
            self.logger.info(f"Updating TAXII feed: {taxii_server['name']}")
            
            for collection in taxii_server['collections']:
                # Get objects from the last 24 hours
                filter_kwargs = {
                    'added_after': datetime.now() - timedelta(hours=24)
                }
                
                objects = collection.get_objects(**filter_kwargs)
                
                for obj in objects['objects']:
                    await self._process_stix_object(obj, taxii_server['name'])
            
            self.logger.info(f"Successfully updated TAXII feed: {taxii_server['name']}")
            
        except Exception as e:
            self.logger.error(f"Error updating TAXII feed {taxii_server['name']}: {e}")
    
    async def _process_stix_object(self, stix_obj: Dict, source: str):
        """Process STIX object and extract IOCs"""
        try:
            obj_type = stix_obj.get('type')
            
            if obj_type == 'indicator':
                pattern = stix_obj.get('pattern', '')
                labels = stix_obj.get('labels', [])
                
                # Extract IOCs from STIX pattern
                iocs = self._extract_iocs_from_stix_pattern(pattern)
                
                for ioc_type, ioc_value in iocs:
                    # Determine threat category from labels
                    threat_category = ThreatCategory.SUSPICIOUS
                    if 'malicious-activity' in labels:
                        threat_category = ThreatCategory.MALWARE
                    elif 'phishing' in labels:
                        threat_category = ThreatCategory.PHISHING
                    
                    ioc = IOC(
                        id=stix_obj.get('id', hashlib.md5(f"{source}:{ioc_value}".encode()).hexdigest()),
                        type=ioc_type,
                        value=ioc_value,
                        threat_category=threat_category,
                        confidence=0.8,
                        severity=ThreatLevel.MEDIUM,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source,
                        description=f"STIX indicator from {source}",
                        ttl=86400  # 24 hours
                    )
                    
                    await self._store_ioc(ioc)
            
        except Exception as e:
            self.logger.error(f"Error processing STIX object: {e}")
    
    def _extract_iocs_from_stix_pattern(self, pattern: str) -> List[Tuple[IOCType, str]]:
        """Extract IOCs from STIX pattern"""
        iocs = []
        
        try:
            # Simple pattern matching for common IOC types
            # This is a simplified implementation
            
            # IP addresses
            ip_matches = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
            for ip in ip_matches:
                if self._is_valid_ip(ip):
                    iocs.append((IOCType.IP_ADDRESS, ip))
            
            # Domain names
            domain_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            for domain in domain_matches:
                if self._is_valid_domain(domain):
                    iocs.append((IOCType.DOMAIN, domain))
            
            # URLs
            url_matches = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
            for url in url_matches:
                iocs.append((IOCType.URL, url))
            
            # File hashes
            hash_matches = re.findall(r"file:hashes\.(?:MD5|SHA-1|SHA-256)\s*=\s*'([^']+)'", pattern)
            for hash_val in hash_matches:
                iocs.append((IOCType.FILE_HASH, hash_val))
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs from STIX pattern: {e}")
        
        return iocs
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        try:
            # Basic domain validation
            if not domain or len(domain) > 253:
                return False
            
            # Check for valid characters and structure
            domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            return bool(re.match(domain_pattern, domain))
            
        except Exception:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            # Check if it's a CIDR range
            try:
                ipaddress.ip_network(ip, strict=False)
                return True
            except ValueError:
                return False
    
    def _create_clean_result(self, ioc_type: IOCType) -> ThreatIntelResult:
        """Create clean result for non-malicious indicators"""
        return ThreatIntelResult(
            is_malicious=False,
            ioc_type=ioc_type,
            description="No threat intelligence match",
            confidence=0.0,
            severity=ThreatLevel.LOW,
            sources=[],
            categories=[]
        )
    
    def _severity_to_int(self, severity: ThreatLevel) -> int:
        """Convert severity to integer for comparison"""
        severity_map = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        return severity_map.get(severity, 0)
    
    async def get_threat_intelligence_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        try:
            self.stats['last_update'] = datetime.now().isoformat()
            return self.stats.copy()
            
        except Exception as e:
            self.logger.error(f"Error getting threat intelligence stats: {e}")
            return {}
    
    async def add_custom_ioc(self, ioc_type: IOCType, value: str, 
                           threat_category: ThreatCategory, confidence: float = 0.9,
                           severity: ThreatLevel = ThreatLevel.MEDIUM, 
                           description: str = None) -> bool:
        """Add custom IOC"""
        try:
            ioc = IOC(
                id=hashlib.md5(f"custom:{value}".encode()).hexdigest(),
                type=ioc_type,
                value=value.lower(),
                threat_category=threat_category,
                confidence=confidence,
                severity=severity,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source="custom",
                description=description or f"Custom {ioc_type.value} indicator",
                ttl=86400 * 7  # 7 days
            )
            
            await self._store_ioc(ioc)
            self.logger.info(f"Added custom IOC: {ioc_type.value}:{value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding custom IOC: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown threat intelligence manager"""
        try:
            # Cancel all feed update tasks
            for task in self.feed_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            if self.feed_tasks:
                await asyncio.gather(*self.feed_tasks, return_exceptions=True)
            
            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()
            
            self.logger.info("Threat Intelligence Manager shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")