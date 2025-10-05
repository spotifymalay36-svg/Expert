"""
Deep Packet Inspection (DPI) Engine
Advanced pattern matching and protocol analysis
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import base64
import urllib.parse

from ..core.config import Settings, WAFRules, ThreatLevel, MITREAttackTechniques
from ..utils.logger import get_logger

@dataclass
class DPIResult:
    """DPI analysis result"""
    is_threat: bool
    threat_type: str
    description: str
    severity: ThreatLevel
    confidence: float
    mitre_technique: Optional[str] = None
    matched_patterns: List[str] = None
    raw_data: Optional[str] = None

class DPIEngine:
    """Deep Packet Inspection Engine with advanced pattern matching"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
        # Initialize protocol analyzers
        self._init_protocol_analyzers()
        
        self.logger.info("DPI Engine initialized")
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.sql_patterns = [re.compile(pattern, re.IGNORECASE) 
                           for pattern in WAFRules.SQL_INJECTION_PATTERNS]
        
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE) 
                           for pattern in WAFRules.XSS_PATTERNS]
        
        self.cmd_patterns = [re.compile(pattern, re.IGNORECASE) 
                           for pattern in WAFRules.COMMAND_INJECTION_PATTERNS]
        
        self.path_patterns = [re.compile(pattern, re.IGNORECASE) 
                            for pattern in WAFRules.PATH_TRAVERSAL_PATTERNS]
    
    def _init_protocol_analyzers(self):
        """Initialize protocol-specific analyzers"""
        self.protocol_analyzers = {
            "HTTP": self._analyze_http,
            "HTTPS": self._analyze_https,
            "DNS": self._analyze_dns,
            "FTP": self._analyze_ftp,
            "SMTP": self._analyze_smtp,
            "SSH": self._analyze_ssh
        }
    
    async def inspect_packet(self, packet_info) -> DPIResult:
        """Main packet inspection method"""
        try:
            # Extract payload as string for analysis
            payload_str = self._extract_payload_string(packet_info.payload)
            
            if not payload_str:
                return DPIResult(
                    is_threat=False,
                    threat_type="NONE",
                    description="No payload to analyze",
                    severity=ThreatLevel.LOW,
                    confidence=0.0
                )
            
            # Check for various attack patterns
            results = []
            
            # 1. SQL Injection Detection
            sql_result = self._detect_sql_injection(payload_str, packet_info)
            if sql_result.is_threat:
                results.append(sql_result)
            
            # 2. XSS Detection
            xss_result = self._detect_xss(payload_str, packet_info)
            if xss_result.is_threat:
                results.append(xss_result)
            
            # 3. Command Injection Detection
            cmd_result = self._detect_command_injection(payload_str, packet_info)
            if cmd_result.is_threat:
                results.append(cmd_result)
            
            # 4. Path Traversal Detection
            path_result = self._detect_path_traversal(payload_str, packet_info)
            if path_result.is_threat:
                results.append(path_result)
            
            # 5. Protocol-specific analysis
            protocol_result = await self._analyze_protocol(packet_info, payload_str)
            if protocol_result and protocol_result.is_threat:
                results.append(protocol_result)
            
            # 6. Suspicious patterns
            suspicious_result = self._detect_suspicious_patterns(payload_str, packet_info)
            if suspicious_result.is_threat:
                results.append(suspicious_result)
            
            # Return highest severity result
            if results:
                return max(results, key=lambda x: self._severity_score(x.severity))
            
            return DPIResult(
                is_threat=False,
                threat_type="CLEAN",
                description="No threats detected",
                severity=ThreatLevel.LOW,
                confidence=0.0
            )
            
        except Exception as e:
            self.logger.error(f"Error in DPI inspection: {e}")
            return DPIResult(
                is_threat=False,
                threat_type="ERROR",
                description=f"DPI analysis error: {e}",
                severity=ThreatLevel.LOW,
                confidence=0.0
            )
    
    def _extract_payload_string(self, payload: bytes) -> str:
        """Extract string from payload with multiple encoding attempts"""
        if not payload:
            return ""
        
        # Try different encodings
        encodings = ['utf-8', 'ascii', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                return payload.decode(encoding, errors='ignore')
            except:
                continue
        
        # If all fail, return hex representation
        return payload.hex()
    
    def _detect_sql_injection(self, payload: str, packet_info) -> DPIResult:
        """Detect SQL injection attacks"""
        matched_patterns = []
        
        # URL decode the payload
        decoded_payload = urllib.parse.unquote_plus(payload)
        
        # Check against SQL injection patterns
        for i, pattern in enumerate(self.sql_patterns):
            if pattern.search(decoded_payload):
                matched_patterns.append(WAFRules.SQL_INJECTION_PATTERNS[i])
        
        if matched_patterns:
            confidence = min(0.9, 0.3 + (len(matched_patterns) * 0.2))
            
            return DPIResult(
                is_threat=True,
                threat_type="SQL_INJECTION",
                description=f"SQL injection attempt detected from {packet_info.src_ip}",
                severity=ThreatLevel.HIGH,
                confidence=confidence,
                mitre_technique="T1190",  # Exploit Public-Facing Application
                matched_patterns=matched_patterns,
                raw_data=decoded_payload[:500]  # First 500 chars
            )
        
        return DPIResult(is_threat=False, threat_type="NONE", description="", severity=ThreatLevel.LOW, confidence=0.0)
    
    def _detect_xss(self, payload: str, packet_info) -> DPIResult:
        """Detect Cross-Site Scripting (XSS) attacks"""
        matched_patterns = []
        
        # URL decode and HTML decode
        decoded_payload = urllib.parse.unquote_plus(payload)
        
        # Check against XSS patterns
        for i, pattern in enumerate(self.xss_patterns):
            if pattern.search(decoded_payload):
                matched_patterns.append(WAFRules.XSS_PATTERNS[i])
        
        if matched_patterns:
            confidence = min(0.9, 0.4 + (len(matched_patterns) * 0.15))
            
            return DPIResult(
                is_threat=True,
                threat_type="XSS",
                description=f"Cross-site scripting attempt detected from {packet_info.src_ip}",
                severity=ThreatLevel.HIGH,
                confidence=confidence,
                mitre_technique="T1190",
                matched_patterns=matched_patterns,
                raw_data=decoded_payload[:500]
            )
        
        return DPIResult(is_threat=False, threat_type="NONE", description="", severity=ThreatLevel.LOW, confidence=0.0)
    
    def _detect_command_injection(self, payload: str, packet_info) -> DPIResult:
        """Detect command injection attacks"""
        matched_patterns = []
        
        decoded_payload = urllib.parse.unquote_plus(payload)
        
        # Check against command injection patterns
        for i, pattern in enumerate(self.cmd_patterns):
            if pattern.search(decoded_payload):
                matched_patterns.append(WAFRules.COMMAND_INJECTION_PATTERNS[i])
        
        if matched_patterns:
            confidence = min(0.95, 0.5 + (len(matched_patterns) * 0.2))
            
            return DPIResult(
                is_threat=True,
                threat_type="COMMAND_INJECTION",
                description=f"Command injection attempt detected from {packet_info.src_ip}",
                severity=ThreatLevel.CRITICAL,
                confidence=confidence,
                mitre_technique="T1059",  # Command and Scripting Interpreter
                matched_patterns=matched_patterns,
                raw_data=decoded_payload[:500]
            )
        
        return DPIResult(is_threat=False, threat_type="NONE", description="", severity=ThreatLevel.LOW, confidence=0.0)
    
    def _detect_path_traversal(self, payload: str, packet_info) -> DPIResult:
        """Detect path traversal attacks"""
        matched_patterns = []
        
        decoded_payload = urllib.parse.unquote_plus(payload)
        
        # Check against path traversal patterns
        for i, pattern in enumerate(self.path_patterns):
            if pattern.search(decoded_payload):
                matched_patterns.append(WAFRules.PATH_TRAVERSAL_PATTERNS[i])
        
        if matched_patterns:
            confidence = min(0.9, 0.4 + (len(matched_patterns) * 0.2))
            
            return DPIResult(
                is_threat=True,
                threat_type="PATH_TRAVERSAL",
                description=f"Path traversal attempt detected from {packet_info.src_ip}",
                severity=ThreatLevel.HIGH,
                confidence=confidence,
                mitre_technique="T1083",  # File and Directory Discovery
                matched_patterns=matched_patterns,
                raw_data=decoded_payload[:500]
            )
        
        return DPIResult(is_threat=False, threat_type="NONE", description="", severity=ThreatLevel.LOW, confidence=0.0)
    
    def _detect_suspicious_patterns(self, payload: str, packet_info) -> DPIResult:
        """Detect other suspicious patterns"""
        suspicious_indicators = []
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'eval(', 'exec(', 'system(', 'shell_exec(',
            'passthru(', 'file_get_contents(', 'fopen(',
            'curl_exec(', 'wget ', 'nc ', 'netcat',
            'powershell', 'cmd.exe', '/bin/sh', '/bin/bash'
        ]
        
        payload_lower = payload.lower()
        for keyword in suspicious_keywords:
            if keyword in payload_lower:
                suspicious_indicators.append(keyword)
        
        # Check for encoded payloads
        if self._detect_encoded_payload(payload):
            suspicious_indicators.append("encoded_payload")
        
        # Check for excessive special characters
        if self._detect_excessive_special_chars(payload):
            suspicious_indicators.append("excessive_special_chars")
        
        if suspicious_indicators:
            confidence = min(0.7, 0.2 + (len(suspicious_indicators) * 0.1))
            
            return DPIResult(
                is_threat=True,
                threat_type="SUSPICIOUS_PATTERN",
                description=f"Suspicious patterns detected: {', '.join(suspicious_indicators)}",
                severity=ThreatLevel.MEDIUM,
                confidence=confidence,
                matched_patterns=suspicious_indicators,
                raw_data=payload[:500]
            )
        
        return DPIResult(is_threat=False, threat_type="NONE", description="", severity=ThreatLevel.LOW, confidence=0.0)
    
    def _detect_encoded_payload(self, payload: str) -> bool:
        """Detect potentially encoded malicious payloads"""
        # Check for base64 encoding
        try:
            if len(payload) > 20 and len(payload) % 4 == 0:
                decoded = base64.b64decode(payload, validate=True)
                decoded_str = decoded.decode('utf-8', errors='ignore')
                
                # Check if decoded content contains suspicious patterns
                suspicious_in_decoded = any(
                    keyword in decoded_str.lower() 
                    for keyword in ['script', 'eval', 'exec', 'system', 'shell']
                )
                
                if suspicious_in_decoded:
                    return True
        except:
            pass
        
        # Check for URL encoding patterns
        url_encoded_patterns = ['%3c', '%3e', '%22', '%27', '%3b']
        payload_lower = payload.lower()
        encoded_count = sum(1 for pattern in url_encoded_patterns if pattern in payload_lower)
        
        return encoded_count >= 3
    
    def _detect_excessive_special_chars(self, payload: str) -> bool:
        """Detect excessive special characters that might indicate obfuscation"""
        special_chars = set('!@#$%^&*(){}[]|\\:";\'<>?,./')
        special_count = sum(1 for char in payload if char in special_chars)
        
        if len(payload) > 0:
            special_ratio = special_count / len(payload)
            return special_ratio > 0.3  # More than 30% special characters
        
        return False
    
    async def _analyze_protocol(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze protocol-specific patterns"""
        try:
            # Determine protocol based on port and content
            protocol = self._identify_protocol(packet_info, payload)
            
            if protocol in self.protocol_analyzers:
                return await self.protocol_analyzers[protocol](packet_info, payload)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in protocol analysis: {e}")
            return None
    
    def _identify_protocol(self, packet_info, payload: str) -> str:
        """Identify application protocol"""
        # HTTP/HTTPS detection
        if (packet_info.dst_port in [80, 8080, 8000] or 
            payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD '))):
            return "HTTP"
        
        if packet_info.dst_port in [443, 8443]:
            return "HTTPS"
        
        # DNS detection
        if packet_info.dst_port == 53:
            return "DNS"
        
        # FTP detection
        if packet_info.dst_port in [21, 20]:
            return "FTP"
        
        # SMTP detection
        if packet_info.dst_port in [25, 587, 465]:
            return "SMTP"
        
        # SSH detection
        if packet_info.dst_port == 22:
            return "SSH"
        
        return "UNKNOWN"
    
    async def _analyze_http(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze HTTP traffic for threats"""
        # Check for HTTP method anomalies
        if payload.startswith(('TRACE ', 'CONNECT ', 'OPTIONS ')):
            return DPIResult(
                is_threat=True,
                threat_type="HTTP_METHOD_ANOMALY",
                description=f"Suspicious HTTP method detected from {packet_info.src_ip}",
                severity=ThreatLevel.MEDIUM,
                confidence=0.6
            )
        
        # Check for oversized headers
        if len(payload) > 8192:  # 8KB limit for headers
            return DPIResult(
                is_threat=True,
                threat_type="HTTP_OVERSIZED_HEADER",
                description=f"Oversized HTTP header from {packet_info.src_ip}",
                severity=ThreatLevel.MEDIUM,
                confidence=0.7
            )
        
        return None
    
    async def _analyze_https(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze HTTPS traffic (limited due to encryption)"""
        # Can only analyze metadata and connection patterns
        # This would be enhanced with SSL inspection
        return None
    
    async def _analyze_dns(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze DNS traffic for threats"""
        # Check for DNS tunneling patterns
        if len(payload) > 512:  # Unusually large DNS query
            return DPIResult(
                is_threat=True,
                threat_type="DNS_TUNNELING",
                description=f"Potential DNS tunneling from {packet_info.src_ip}",
                severity=ThreatLevel.HIGH,
                confidence=0.6
            )
        
        return None
    
    async def _analyze_ftp(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze FTP traffic for threats"""
        # Check for FTP bounce attacks
        if 'PORT ' in payload.upper():
            return DPIResult(
                is_threat=True,
                threat_type="FTP_BOUNCE",
                description=f"Potential FTP bounce attack from {packet_info.src_ip}",
                severity=ThreatLevel.MEDIUM,
                confidence=0.5
            )
        
        return None
    
    async def _analyze_smtp(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze SMTP traffic for threats"""
        # Check for SMTP relay abuse
        if 'RCPT TO:' in payload.upper() and payload.count('@') > 10:
            return DPIResult(
                is_threat=True,
                threat_type="SMTP_RELAY_ABUSE",
                description=f"Potential SMTP relay abuse from {packet_info.src_ip}",
                severity=ThreatLevel.MEDIUM,
                confidence=0.6
            )
        
        return None
    
    async def _analyze_ssh(self, packet_info, payload: str) -> Optional[DPIResult]:
        """Analyze SSH traffic for threats"""
        # SSH traffic is encrypted, limited analysis possible
        # Could detect brute force attempts by connection frequency
        return None
    
    def _severity_score(self, severity: ThreatLevel) -> int:
        """Convert severity to numeric score for comparison"""
        severity_scores = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        return severity_scores.get(severity, 0)