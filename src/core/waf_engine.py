"""
Core WAF Engine with AI-driven threat detection
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
import numpy as np
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from .config import Settings, WAFRules, ThreatLevel
from ..ml.threat_detector import ThreatDetector
from ..ml.anomaly_detector import AnomalyDetector
from ..security.dpi_engine import DPIEngine
from ..security.ssl_inspector import SSLInspector
from ..zero_trust.auth_manager import AuthManager
from ..threat_intel.intel_manager import ThreatIntelManager
from ..monitoring.metrics import MetricsCollector
from ..utils.logger import get_logger

@dataclass
class PacketInfo:
    """Packet information structure"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    size: int
    flags: Dict[str, Any]

@dataclass
class ThreatAlert:
    """Threat alert structure"""
    id: str
    timestamp: datetime
    threat_type: str
    severity: ThreatLevel
    source_ip: str
    target_ip: str
    description: str
    mitre_technique: Optional[str]
    confidence: float
    action_taken: str
    packet_info: PacketInfo

class WAFEngine:
    """Main WAF Engine with AI-driven capabilities"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        self.is_running = False
        
        # Core components
        self.threat_detector: Optional[ThreatDetector] = None
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.dpi_engine: Optional[DPIEngine] = None
        self.ssl_inspector: Optional[SSLInspector] = None
        self.auth_manager: Optional[AuthManager] = None
        self.threat_intel: Optional[ThreatIntelManager] = None
        self.metrics: Optional[MetricsCollector] = None
        
        # Storage
        self.redis_client: Optional[redis.Redis] = None
        self.db_engine = None
        self.db_session = None
        
        # Processing queues
        self.packet_queue = asyncio.Queue(maxsize=settings.packet_buffer_size)
        self.alert_queue = asyncio.Queue(maxsize=10000)
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "threats_detected": 0,
            "alerts_generated": 0,
            "blocked_requests": 0,
            "start_time": None
        }
        
        # Thread pool for CPU-intensive tasks
        self.executor = ThreadPoolExecutor(max_workers=settings.processing_threads)
        
    async def initialize(self):
        """Initialize all WAF components"""
        self.logger.info("Initializing WAF Engine...")
        
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.settings.redis_url)
            await self.redis_client.ping()
            self.logger.info("Redis connection established")
            
            # Initialize database
            self.db_engine = create_async_engine(self.settings.postgres_url)
            self.db_session = sessionmaker(
                self.db_engine, class_=AsyncSession, expire_on_commit=False
            )
            self.logger.info("Database connection established")
            
            # Initialize AI/ML components
            self.threat_detector = ThreatDetector(self.settings)
            await self.threat_detector.initialize()
            
            self.anomaly_detector = AnomalyDetector(self.settings)
            await self.anomaly_detector.initialize()
            
            # Initialize security components
            self.dpi_engine = DPIEngine(self.settings)
            self.ssl_inspector = SSLInspector(self.settings)
            
            # Initialize Zero Trust
            self.auth_manager = AuthManager(self.settings)
            
            # Initialize threat intelligence
            self.threat_intel = ThreatIntelManager(self.settings)
            await self.threat_intel.initialize()
            
            # Initialize metrics
            self.metrics = MetricsCollector(self.settings)
            
            self.stats["start_time"] = time.time()
            self.is_running = True
            
            self.logger.info("WAF Engine initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize WAF Engine: {e}")
            raise
    
    async def start_packet_capture(self):
        """Start packet capture and processing"""
        self.logger.info("Starting packet capture...")
        
        def packet_handler(packet):
            """Handle captured packets"""
            try:
                if self.packet_queue.full():
                    self.logger.warning("Packet queue full, dropping packet")
                    return
                
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    asyncio.create_task(self.packet_queue.put(packet_info))
                    
            except Exception as e:
                self.logger.error(f"Error handling packet: {e}")
        
        # Start packet capture in a separate thread
        def capture_packets():
            try:
                scapy.sniff(
                    iface=self.settings.interface,
                    prn=packet_handler,
                    filter=self.settings.capture_filter,
                    store=False
                )
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
        
        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
        
        self.logger.info(f"Packet capture started on interface {self.settings.interface}")
    
    async def start_threat_analysis(self):
        """Start threat analysis processing"""
        self.logger.info("Starting threat analysis...")
        
        while self.is_running:
            try:
                # Get packet from queue with timeout
                try:
                    packet_info = await asyncio.wait_for(
                        self.packet_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process packet for threats
                await self._analyze_packet(packet_info)
                
                # Update statistics
                self.stats["packets_processed"] += 1
                
                # Update metrics
                if self.metrics:
                    self.metrics.increment_counter("packets_processed_total")
                
            except Exception as e:
                self.logger.error(f"Error in threat analysis: {e}")
                await asyncio.sleep(0.1)
    
    async def _analyze_packet(self, packet_info: PacketInfo):
        """Analyze packet for threats"""
        try:
            threats_detected = []
            
            # 1. Deep Packet Inspection
            if self.settings.enable_dpi and self.dpi_engine:
                dpi_result = await self.dpi_engine.inspect_packet(packet_info)
                if dpi_result.is_threat:
                    threats_detected.append({
                        "type": "DPI",
                        "description": dpi_result.description,
                        "severity": dpi_result.severity,
                        "mitre_technique": dpi_result.mitre_technique
                    })
            
            # 2. AI/ML Threat Detection
            if self.threat_detector:
                ml_result = await self.threat_detector.analyze_packet(packet_info)
                if ml_result.is_threat:
                    threats_detected.append({
                        "type": "ML_DETECTION",
                        "description": ml_result.description,
                        "severity": ml_result.severity,
                        "confidence": ml_result.confidence
                    })
            
            # 3. Anomaly Detection
            if self.settings.enable_anomaly_detection and self.anomaly_detector:
                anomaly_result = await self.anomaly_detector.detect_anomaly(packet_info)
                if anomaly_result.is_anomaly:
                    threats_detected.append({
                        "type": "ANOMALY",
                        "description": anomaly_result.description,
                        "severity": ThreatLevel.MEDIUM,
                        "score": anomaly_result.anomaly_score
                    })
            
            # 4. Threat Intelligence Check
            if self.threat_intel:
                intel_result = await self.threat_intel.check_indicators(packet_info)
                if intel_result.is_malicious:
                    threats_detected.append({
                        "type": "THREAT_INTEL",
                        "description": intel_result.description,
                        "severity": ThreatLevel.HIGH,
                        "ioc_type": intel_result.ioc_type
                    })
            
            # 5. SSL/TLS Inspection
            if self.settings.enable_ssl_inspection and self.ssl_inspector:
                ssl_result = await self.ssl_inspector.inspect_ssl_traffic(packet_info)
                if ssl_result.is_suspicious:
                    threats_detected.append({
                        "type": "SSL_INSPECTION",
                        "description": ssl_result.description,
                        "severity": ssl_result.severity
                    })
            
            # Process detected threats
            if threats_detected:
                await self._handle_threats(packet_info, threats_detected)
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
    
    async def _handle_threats(self, packet_info: PacketInfo, threats: List[Dict]):
        """Handle detected threats"""
        try:
            for threat in threats:
                # Create threat alert
                alert = ThreatAlert(
                    id=f"alert_{int(time.time() * 1000000)}",
                    timestamp=datetime.now(),
                    threat_type=threat["type"],
                    severity=threat.get("severity", ThreatLevel.MEDIUM),
                    source_ip=packet_info.src_ip,
                    target_ip=packet_info.dst_ip,
                    description=threat["description"],
                    mitre_technique=threat.get("mitre_technique"),
                    confidence=threat.get("confidence", 0.8),
                    action_taken="LOGGED",
                    packet_info=packet_info
                )
                
                # Determine action based on severity
                action = await self._determine_action(alert)
                alert.action_taken = action
                
                # Execute action
                await self._execute_action(alert, action)
                
                # Store alert
                await self._store_alert(alert)
                
                # Update statistics
                self.stats["threats_detected"] += 1
                self.stats["alerts_generated"] += 1
                
                if action == "BLOCKED":
                    self.stats["blocked_requests"] += 1
                
                # Update metrics
                if self.metrics:
                    self.metrics.increment_counter("threats_detected_total")
                    self.metrics.increment_counter(f"threats_{threat['type'].lower()}_total")
                
                self.logger.warning(f"Threat detected: {alert.description} from {alert.source_ip}")
                
        except Exception as e:
            self.logger.error(f"Error handling threats: {e}")
    
    async def _determine_action(self, alert: ThreatAlert) -> str:
        """Determine action based on threat severity and policies"""
        try:
            # High/Critical threats are blocked by default
            if alert.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                return "BLOCKED"
            
            # Medium threats are logged and rate limited
            elif alert.severity == ThreatLevel.MEDIUM:
                # Check if source IP has too many recent alerts
                recent_alerts = await self._get_recent_alerts(alert.source_ip, minutes=5)
                if len(recent_alerts) > 10:
                    return "BLOCKED"
                return "LOGGED"
            
            # Low threats are just logged
            else:
                return "LOGGED"
                
        except Exception as e:
            self.logger.error(f"Error determining action: {e}")
            return "LOGGED"
    
    async def _execute_action(self, alert: ThreatAlert, action: str):
        """Execute the determined action"""
        try:
            if action == "BLOCKED":
                # Add IP to block list (Redis with TTL)
                await self.redis_client.setex(
                    f"blocked_ip:{alert.source_ip}",
                    3600,  # 1 hour TTL
                    json.dumps({
                        "reason": alert.description,
                        "timestamp": alert.timestamp.isoformat(),
                        "alert_id": alert.id
                    })
                )
                
                # TODO: Implement iptables rules or network blocking
                self.logger.info(f"Blocked IP {alert.source_ip} due to {alert.description}")
            
            elif action == "QUARANTINE":
                # Move to quarantine network segment
                # TODO: Implement network quarantine
                pass
                
        except Exception as e:
            self.logger.error(f"Error executing action {action}: {e}")
    
    async def _store_alert(self, alert: ThreatAlert):
        """Store alert in database and cache"""
        try:
            # Store in Redis for quick access
            alert_data = {
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "threat_type": alert.threat_type,
                "severity": alert.severity.value,
                "source_ip": alert.source_ip,
                "target_ip": alert.target_ip,
                "description": alert.description,
                "confidence": alert.confidence,
                "action_taken": alert.action_taken
            }
            
            await self.redis_client.lpush("recent_alerts", json.dumps(alert_data))
            await self.redis_client.ltrim("recent_alerts", 0, 1000)  # Keep last 1000 alerts
            
            # TODO: Store in PostgreSQL for long-term storage
            
        except Exception as e:
            self.logger.error(f"Error storing alert: {e}")
    
    async def _get_recent_alerts(self, source_ip: str, minutes: int = 5) -> List[Dict]:
        """Get recent alerts for a source IP"""
        try:
            alerts = []
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            
            # Get from Redis
            recent_alerts = await self.redis_client.lrange("recent_alerts", 0, -1)
            
            for alert_json in recent_alerts:
                alert_data = json.loads(alert_json)
                alert_time = datetime.fromisoformat(alert_data["timestamp"])
                
                if (alert_data["source_ip"] == source_ip and 
                    alert_time > cutoff_time):
                    alerts.append(alert_data)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract packet information from Scapy packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # Extract basic info
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            src_port = dst_port = 0
            payload = b""
            
            # Extract transport layer info
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                
                # Extract payload
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
            
            return PacketInfo(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                payload=payload,
                size=len(packet),
                flags={}
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        uptime = time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "packets_per_second": self.stats["packets_processed"] / max(uptime, 1),
            "is_running": self.is_running
        }
    
    async def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent threat alerts"""
        try:
            alerts_json = await self.redis_client.lrange("recent_alerts", 0, limit - 1)
            return [json.loads(alert) for alert in alerts_json]
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
    
    async def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            return await self.redis_client.exists(f"blocked_ip:{ip}")
        except Exception as e:
            self.logger.error(f"Error checking blocked IP: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown WAF engine"""
        self.logger.info("Shutting down WAF Engine...")
        
        self.is_running = False
        
        # Close connections
        if self.redis_client:
            await self.redis_client.close()
        
        if self.db_engine:
            await self.db_engine.dispose()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("WAF Engine shutdown complete")