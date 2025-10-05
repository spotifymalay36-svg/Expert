"""
SSL/TLS Traffic Inspection and Analysis
Advanced encrypted traffic analysis with minimal performance impact
"""

import logging
import ssl
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import base64
import re
import asyncio

import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import dpkt

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class SSLInspectionResult:
    """SSL inspection result"""
    is_suspicious: bool
    description: str
    severity: ThreatLevel
    confidence: float
    certificate_info: Optional[Dict] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    anomalies: List[str] = None

@dataclass
class CertificateInfo:
    """SSL Certificate information"""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    san_domains: List[str]
    is_self_signed: bool
    is_expired: bool
    fingerprint_sha256: str

class SSLInspector:
    """Advanced SSL/TLS traffic inspector"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Certificate cache for performance
        self.cert_cache = {}
        
        # Known malicious certificate indicators
        self.malicious_indicators = {
            'suspicious_subjects': [
                'localhost',
                'test',
                'example.com',
                'badssl.com'
            ],
            'suspicious_issuers': [
                'fake ca',
                'test ca',
                'malware ca'
            ],
            'weak_key_sizes': [512, 1024],  # Weak RSA key sizes
            'weak_algorithms': [
                'md5',
                'sha1',
                'md2'
            ]
        }
        
        # TLS version security ratings
        self.tls_security_ratings = {
            'SSLv2': 'CRITICAL',
            'SSLv3': 'HIGH',
            'TLSv1.0': 'HIGH',
            'TLSv1.1': 'MEDIUM',
            'TLSv1.2': 'LOW',
            'TLSv1.3': 'LOW'
        }
        
        # Cipher suite security ratings
        self.cipher_security_ratings = {
            'NULL': 'CRITICAL',
            'EXPORT': 'CRITICAL',
            'DES': 'HIGH',
            '3DES': 'HIGH',
            'RC4': 'HIGH',
            'AES128': 'MEDIUM',
            'AES256': 'LOW',
            'CHACHA20': 'LOW'
        }
        
        self.logger.info("SSL Inspector initialized")
    
    async def inspect_ssl_traffic(self, packet_info) -> SSLInspectionResult:
        """Main SSL traffic inspection method"""
        try:
            # Check if this is SSL/TLS traffic
            if not self._is_ssl_traffic(packet_info):
                return SSLInspectionResult(
                    is_suspicious=False,
                    description="Not SSL/TLS traffic",
                    severity=ThreatLevel.LOW,
                    confidence=0.0
                )
            
            # Parse SSL/TLS handshake if present
            ssl_info = await self._parse_ssl_handshake(packet_info.payload)
            
            if not ssl_info:
                return SSLInspectionResult(
                    is_suspicious=False,
                    description="Could not parse SSL handshake",
                    severity=ThreatLevel.LOW,
                    confidence=0.0
                )
            
            # Analyze SSL/TLS configuration
            anomalies = []
            max_severity = ThreatLevel.LOW
            
            # Check TLS version
            tls_anomaly, tls_severity = self._check_tls_version(ssl_info.get('tls_version'))
            if tls_anomaly:
                anomalies.append(tls_anomaly)
                max_severity = max(max_severity, tls_severity, key=self._severity_to_int)
            
            # Check cipher suite
            cipher_anomaly, cipher_severity = self._check_cipher_suite(ssl_info.get('cipher_suite'))
            if cipher_anomaly:
                anomalies.append(cipher_anomaly)
                max_severity = max(max_severity, cipher_severity, key=self._severity_to_int)
            
            # Analyze certificate if present
            if 'certificate' in ssl_info:
                cert_result = await self._analyze_certificate(ssl_info['certificate'], packet_info.dst_ip)
                if cert_result.is_suspicious:
                    anomalies.extend(cert_result.anomalies or [cert_result.description])
                    max_severity = max(max_severity, cert_result.severity, key=self._severity_to_int)
            
            # Check for SSL/TLS attacks
            attack_anomalies = await self._detect_ssl_attacks(packet_info, ssl_info)
            if attack_anomalies:
                anomalies.extend(attack_anomalies)
                max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
            
            # Check for certificate pinning bypass attempts
            pinning_anomalies = self._check_certificate_pinning_bypass(ssl_info)
            if pinning_anomalies:
                anomalies.extend(pinning_anomalies)
                max_severity = max(max_severity, ThreatLevel.MEDIUM, key=self._severity_to_int)
            
            if anomalies:
                confidence = min(0.9, len(anomalies) * 0.2 + 0.3)
                
                return SSLInspectionResult(
                    is_suspicious=True,
                    description="; ".join(anomalies),
                    severity=max_severity,
                    confidence=confidence,
                    certificate_info=ssl_info.get('certificate_info'),
                    tls_version=ssl_info.get('tls_version'),
                    cipher_suite=ssl_info.get('cipher_suite'),
                    anomalies=anomalies
                )
            
            return SSLInspectionResult(
                is_suspicious=False,
                description="SSL/TLS traffic appears normal",
                severity=ThreatLevel.LOW,
                confidence=0.8,
                tls_version=ssl_info.get('tls_version'),
                cipher_suite=ssl_info.get('cipher_suite')
            )
            
        except Exception as e:
            self.logger.error(f"Error in SSL inspection: {e}")
            return SSLInspectionResult(
                is_suspicious=False,
                description=f"SSL inspection error: {e}",
                severity=ThreatLevel.LOW,
                confidence=0.0
            )
    
    def _is_ssl_traffic(self, packet_info) -> bool:
        """Determine if packet contains SSL/TLS traffic"""
        # Check common SSL/TLS ports
        ssl_ports = [443, 8443, 993, 995, 465, 587, 636, 989, 990]
        
        if packet_info.dst_port in ssl_ports or packet_info.src_port in ssl_ports:
            return True
        
        # Check for SSL/TLS handshake patterns in payload
        if packet_info.payload and len(packet_info.payload) > 5:
            # TLS handshake starts with content type (0x16) and version
            if (packet_info.payload[0] == 0x16 and 
                packet_info.payload[1] == 0x03):  # TLS version major
                return True
            
            # Check for SSL/TLS record header patterns
            if (packet_info.payload[0] in [0x14, 0x15, 0x16, 0x17] and  # Content types
                packet_info.payload[1] == 0x03):  # Version major
                return True
        
        return False
    
    async def _parse_ssl_handshake(self, payload: bytes) -> Optional[Dict]:
        """Parse SSL/TLS handshake information"""
        try:
            if not payload or len(payload) < 5:
                return None
            
            ssl_info = {}
            
            # Parse TLS record header
            content_type = payload[0]
            version_major = payload[1]
            version_minor = payload[2]
            length = (payload[3] << 8) | payload[4]
            
            # Map version to string
            version_map = {
                (3, 0): 'SSLv3',
                (3, 1): 'TLSv1.0',
                (3, 2): 'TLSv1.1',
                (3, 3): 'TLSv1.2',
                (3, 4): 'TLSv1.3'
            }
            
            tls_version = version_map.get((version_major, version_minor), f'Unknown({version_major}.{version_minor})')
            ssl_info['tls_version'] = tls_version
            
            # Parse handshake messages if this is a handshake record
            if content_type == 0x16 and len(payload) > 5:  # Handshake
                handshake_data = payload[5:]
                
                # Parse handshake message
                if len(handshake_data) >= 4:
                    handshake_type = handshake_data[0]
                    handshake_length = (handshake_data[1] << 16) | (handshake_data[2] << 8) | handshake_data[3]
                    
                    if handshake_type == 0x01:  # Client Hello
                        client_hello_info = self._parse_client_hello(handshake_data[4:])
                        ssl_info.update(client_hello_info)
                    
                    elif handshake_type == 0x02:  # Server Hello
                        server_hello_info = self._parse_server_hello(handshake_data[4:])
                        ssl_info.update(server_hello_info)
                    
                    elif handshake_type == 0x0b:  # Certificate
                        cert_info = self._parse_certificate_message(handshake_data[4:])
                        if cert_info:
                            ssl_info['certificate'] = cert_info
            
            return ssl_info
            
        except Exception as e:
            self.logger.error(f"Error parsing SSL handshake: {e}")
            return None
    
    def _parse_client_hello(self, data: bytes) -> Dict:
        """Parse Client Hello message"""
        try:
            info = {}
            
            if len(data) < 34:
                return info
            
            # Skip version (2 bytes) and random (32 bytes)
            offset = 34
            
            # Parse session ID
            if offset < len(data):
                session_id_length = data[offset]
                offset += 1 + session_id_length
            
            # Parse cipher suites
            if offset + 2 <= len(data):
                cipher_suites_length = (data[offset] << 8) | data[offset + 1]
                offset += 2
                
                if offset + cipher_suites_length <= len(data):
                    cipher_suites = []
                    for i in range(0, cipher_suites_length, 2):
                        if offset + i + 1 < len(data):
                            cipher_suite = (data[offset + i] << 8) | data[offset + i + 1]
                            cipher_suites.append(cipher_suite)
                    
                    info['cipher_suites'] = cipher_suites
                    offset += cipher_suites_length
            
            # Parse extensions (simplified)
            if offset + 2 <= len(data):
                extensions_length = (data[offset] << 8) | data[offset + 1]
                offset += 2
                
                if offset + extensions_length <= len(data):
                    extensions = self._parse_extensions(data[offset:offset + extensions_length])
                    info['extensions'] = extensions
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error parsing Client Hello: {e}")
            return {}
    
    def _parse_server_hello(self, data: bytes) -> Dict:
        """Parse Server Hello message"""
        try:
            info = {}
            
            if len(data) < 34:
                return info
            
            # Skip version (2 bytes) and random (32 bytes)
            offset = 34
            
            # Parse session ID
            if offset < len(data):
                session_id_length = data[offset]
                offset += 1 + session_id_length
            
            # Parse selected cipher suite
            if offset + 2 <= len(data):
                cipher_suite = (data[offset] << 8) | data[offset + 1]
                info['selected_cipher_suite'] = cipher_suite
                info['cipher_suite'] = self._cipher_suite_to_string(cipher_suite)
                offset += 2
            
            # Parse compression method
            if offset < len(data):
                compression_method = data[offset]
                info['compression_method'] = compression_method
                offset += 1
            
            return info
            
        except Exception as e:
            self.logger.error(f"Error parsing Server Hello: {e}")
            return {}
    
    def _parse_certificate_message(self, data: bytes) -> Optional[bytes]:
        """Parse Certificate message and extract first certificate"""
        try:
            if len(data) < 3:
                return None
            
            # Parse certificates length
            certs_length = (data[0] << 16) | (data[1] << 8) | data[2]
            offset = 3
            
            if offset + certs_length > len(data):
                return None
            
            # Parse first certificate
            if offset + 3 <= len(data):
                cert_length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
                offset += 3
                
                if offset + cert_length <= len(data):
                    certificate = data[offset:offset + cert_length]
                    return certificate
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error parsing certificate message: {e}")
            return None
    
    def _parse_extensions(self, data: bytes) -> Dict:
        """Parse TLS extensions"""
        try:
            extensions = {}
            offset = 0
            
            while offset + 4 <= len(data):
                ext_type = (data[offset] << 8) | data[offset + 1]
                ext_length = (data[offset + 2] << 8) | data[offset + 3]
                offset += 4
                
                if offset + ext_length > len(data):
                    break
                
                ext_data = data[offset:offset + ext_length]
                
                # Parse specific extensions
                if ext_type == 0x0000:  # Server Name Indication
                    sni = self._parse_sni_extension(ext_data)
                    if sni:
                        extensions['sni'] = sni
                
                elif ext_type == 0x000a:  # Supported Groups
                    groups = self._parse_supported_groups(ext_data)
                    if groups:
                        extensions['supported_groups'] = groups
                
                offset += ext_length
            
            return extensions
            
        except Exception as e:
            self.logger.error(f"Error parsing extensions: {e}")
            return {}
    
    def _parse_sni_extension(self, data: bytes) -> Optional[str]:
        """Parse Server Name Indication extension"""
        try:
            if len(data) < 5:
                return None
            
            # Skip server name list length (2 bytes)
            offset = 2
            
            # Parse server name
            if offset + 3 <= len(data):
                name_type = data[offset]
                name_length = (data[offset + 1] << 8) | data[offset + 2]
                offset += 3
                
                if name_type == 0 and offset + name_length <= len(data):  # hostname
                    hostname = data[offset:offset + name_length].decode('utf-8', errors='ignore')
                    return hostname
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error parsing SNI extension: {e}")
            return None
    
    def _parse_supported_groups(self, data: bytes) -> List[int]:
        """Parse Supported Groups extension"""
        try:
            if len(data) < 2:
                return []
            
            groups_length = (data[0] << 8) | data[1]
            offset = 2
            
            groups = []
            for i in range(0, groups_length, 2):
                if offset + i + 1 < len(data):
                    group = (data[offset + i] << 8) | data[offset + i + 1]
                    groups.append(group)
            
            return groups
            
        except Exception as e:
            self.logger.error(f"Error parsing supported groups: {e}")
            return []
    
    def _cipher_suite_to_string(self, cipher_suite: int) -> str:
        """Convert cipher suite number to string"""
        # Common cipher suites (simplified mapping)
        cipher_map = {
            0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
            0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
            0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
            0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
            0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
            0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
            0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
            0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
            0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
            0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
            0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            0x1301: 'TLS_AES_128_GCM_SHA256',
            0x1302: 'TLS_AES_256_GCM_SHA384',
            0x1303: 'TLS_CHACHA20_POLY1305_SHA256'
        }
        
        return cipher_map.get(cipher_suite, f'Unknown(0x{cipher_suite:04X})')
    
    async def _analyze_certificate(self, cert_data: bytes, expected_hostname: str) -> SSLInspectionResult:
        """Analyze SSL certificate for security issues"""
        try:
            # Parse certificate
            cert_info = self._parse_certificate(cert_data)
            if not cert_info:
                return SSLInspectionResult(
                    is_suspicious=True,
                    description="Could not parse certificate",
                    severity=ThreatLevel.MEDIUM,
                    confidence=0.7
                )
            
            anomalies = []
            max_severity = ThreatLevel.LOW
            
            # Check certificate validity
            if cert_info.is_expired:
                anomalies.append("Certificate is expired")
                max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
            
            # Check if certificate is self-signed
            if cert_info.is_self_signed:
                anomalies.append("Self-signed certificate")
                max_severity = max(max_severity, ThreatLevel.MEDIUM, key=self._severity_to_int)
            
            # Check key size
            if cert_info.key_size in self.malicious_indicators['weak_key_sizes']:
                anomalies.append(f"Weak key size: {cert_info.key_size} bits")
                max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
            
            # Check signature algorithm
            sig_alg_lower = cert_info.signature_algorithm.lower()
            for weak_alg in self.malicious_indicators['weak_algorithms']:
                if weak_alg in sig_alg_lower:
                    anomalies.append(f"Weak signature algorithm: {cert_info.signature_algorithm}")
                    max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
                    break
            
            # Check subject for suspicious patterns
            subject_lower = cert_info.subject.lower()
            for suspicious_subject in self.malicious_indicators['suspicious_subjects']:
                if suspicious_subject in subject_lower:
                    anomalies.append(f"Suspicious certificate subject: {cert_info.subject}")
                    max_severity = max(max_severity, ThreatLevel.MEDIUM, key=self._severity_to_int)
                    break
            
            # Check issuer for suspicious patterns
            issuer_lower = cert_info.issuer.lower()
            for suspicious_issuer in self.malicious_indicators['suspicious_issuers']:
                if suspicious_issuer in issuer_lower:
                    anomalies.append(f"Suspicious certificate issuer: {cert_info.issuer}")
                    max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
                    break
            
            # Check hostname validation (simplified)
            if expected_hostname and not self._validate_hostname(cert_info, expected_hostname):
                anomalies.append(f"Certificate hostname mismatch: expected {expected_hostname}")
                max_severity = max(max_severity, ThreatLevel.HIGH, key=self._severity_to_int)
            
            # Check certificate chain (if available)
            # This would require additional certificate chain parsing
            
            if anomalies:
                return SSLInspectionResult(
                    is_suspicious=True,
                    description="; ".join(anomalies),
                    severity=max_severity,
                    confidence=0.8,
                    certificate_info=cert_info.__dict__,
                    anomalies=anomalies
                )
            
            return SSLInspectionResult(
                is_suspicious=False,
                description="Certificate appears valid",
                severity=ThreatLevel.LOW,
                confidence=0.9,
                certificate_info=cert_info.__dict__
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing certificate: {e}")
            return SSLInspectionResult(
                is_suspicious=True,
                description=f"Certificate analysis error: {e}",
                severity=ThreatLevel.MEDIUM,
                confidence=0.5
            )
    
    def _parse_certificate(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse X.509 certificate"""
        try:
            # Parse using cryptography library
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            signature_algorithm = cert.signature_algorithm_oid._name
            
            # Extract public key info
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                public_key_algorithm = type(public_key).__name__
            else:
                key_size = 0
                public_key_algorithm = "Unknown"
            
            # Extract SAN domains
            san_domains = []
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_extension.value:
                    if isinstance(name, x509.DNSName):
                        san_domains.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Check if self-signed
            is_self_signed = subject == issuer
            
            # Check if expired
            now = datetime.now()
            is_expired = now < not_before or now > not_after
            
            # Calculate fingerprint
            fingerprint_sha256 = hashlib.sha256(cert_data).hexdigest()
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                key_size=key_size,
                san_domains=san_domains,
                is_self_signed=is_self_signed,
                is_expired=is_expired,
                fingerprint_sha256=fingerprint_sha256
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing certificate: {e}")
            return None
    
    def _validate_hostname(self, cert_info: CertificateInfo, hostname: str) -> bool:
        """Validate hostname against certificate"""
        try:
            # Check subject CN (simplified)
            if f"CN={hostname}" in cert_info.subject:
                return True
            
            # Check SAN domains
            for san_domain in cert_info.san_domains:
                if san_domain == hostname:
                    return True
                
                # Check wildcard domains
                if san_domain.startswith('*.'):
                    wildcard_domain = san_domain[2:]
                    if hostname.endswith(wildcard_domain):
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating hostname: {e}")
            return False
    
    def _check_tls_version(self, tls_version: str) -> Tuple[Optional[str], ThreatLevel]:
        """Check TLS version for security issues"""
        if not tls_version:
            return None, ThreatLevel.LOW
        
        if tls_version in ['SSLv2', 'SSLv3']:
            return f"Insecure TLS version: {tls_version}", ThreatLevel.CRITICAL
        elif tls_version in ['TLSv1.0', 'TLSv1.1']:
            return f"Deprecated TLS version: {tls_version}", ThreatLevel.HIGH
        elif tls_version == 'TLSv1.2':
            return None, ThreatLevel.LOW  # Acceptable
        elif tls_version == 'TLSv1.3':
            return None, ThreatLevel.LOW  # Good
        else:
            return f"Unknown TLS version: {tls_version}", ThreatLevel.MEDIUM
    
    def _check_cipher_suite(self, cipher_suite: str) -> Tuple[Optional[str], ThreatLevel]:
        """Check cipher suite for security issues"""
        if not cipher_suite:
            return None, ThreatLevel.LOW
        
        cipher_lower = cipher_suite.lower()
        
        # Check for critical weaknesses
        if any(weak in cipher_lower for weak in ['null', 'export', 'anon']):
            return f"Critical cipher weakness: {cipher_suite}", ThreatLevel.CRITICAL
        
        # Check for high severity issues
        if any(weak in cipher_lower for weak in ['des', 'rc4', 'md5']):
            return f"Weak cipher suite: {cipher_suite}", ThreatLevel.HIGH
        
        # Check for medium severity issues
        if '3des' in cipher_lower or 'sha1' in cipher_lower:
            return f"Deprecated cipher suite: {cipher_suite}", ThreatLevel.MEDIUM
        
        return None, ThreatLevel.LOW
    
    async def _detect_ssl_attacks(self, packet_info, ssl_info: Dict) -> List[str]:
        """Detect SSL/TLS specific attacks"""
        attacks = []
        
        try:
            # Check for SSL stripping indicators
            if packet_info.dst_port == 80 and 'https://' in str(packet_info.payload):
                attacks.append("Potential SSL stripping attack")
            
            # Check for certificate transparency log poisoning
            if 'extensions' in ssl_info and 'sni' in ssl_info['extensions']:
                sni = ssl_info['extensions']['sni']
                if len(sni) > 253:  # Max domain name length
                    attacks.append("Oversized SNI extension")
            
            # Check for downgrade attacks
            if ssl_info.get('tls_version') in ['TLSv1.0', 'TLSv1.1']:
                if 'cipher_suites' in ssl_info:
                    # If client supports modern ciphers but negotiated old TLS
                    modern_ciphers = [cs for cs in ssl_info['cipher_suites'] 
                                    if cs in [0x1301, 0x1302, 0x1303]]  # TLS 1.3 ciphers
                    if modern_ciphers:
                        attacks.append("Potential TLS downgrade attack")
            
            # Check for heartbleed-like oversized messages
            payload_len = len(packet_info.payload) if packet_info.payload else 0
            if payload_len > 16384:  # Max TLS record size
                attacks.append("Oversized TLS record")
            
        except Exception as e:
            self.logger.error(f"Error detecting SSL attacks: {e}")
        
        return attacks
    
    def _check_certificate_pinning_bypass(self, ssl_info: Dict) -> List[str]:
        """Check for certificate pinning bypass attempts"""
        bypass_indicators = []
        
        try:
            # Check for suspicious certificate chains
            # This would require more detailed certificate chain analysis
            
            # Check for known bypass tools in extensions or other indicators
            if 'extensions' in ssl_info:
                # Look for unusual extensions that might indicate bypass tools
                extensions = ssl_info['extensions']
                
                # Check for excessive number of extensions
                if len(extensions) > 10:
                    bypass_indicators.append("Excessive TLS extensions")
        
        except Exception as e:
            self.logger.error(f"Error checking certificate pinning bypass: {e}")
        
        return bypass_indicators
    
    def _severity_to_int(self, severity: ThreatLevel) -> int:
        """Convert severity to integer for comparison"""
        severity_map = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        return severity_map.get(severity, 0)