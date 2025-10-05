"""
Metrics Collection and Monitoring
Prometheus-compatible metrics for WAF monitoring
"""

import time
import threading
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import asyncio

from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
from prometheus_client.core import CollectorRegistry

from ..core.config import Settings
from ..utils.logger import get_logger, performance_logger

class MetricsCollector:
    """Prometheus metrics collector for WAF"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Create custom registry
        self.registry = CollectorRegistry()
        
        # Packet processing metrics
        self.packets_processed_total = Counter(
            'waf_packets_processed_total',
            'Total number of packets processed',
            ['interface', 'protocol'],
            registry=self.registry
        )
        
        self.packets_dropped_total = Counter(
            'waf_packets_dropped_total',
            'Total number of packets dropped',
            ['reason'],
            registry=self.registry
        )
        
        self.packet_processing_duration = Histogram(
            'waf_packet_processing_duration_seconds',
            'Time spent processing packets',
            ['component'],
            registry=self.registry
        )
        
        # Threat detection metrics
        self.threats_detected_total = Counter(
            'waf_threats_detected_total',
            'Total number of threats detected',
            ['threat_type', 'severity', 'source'],
            registry=self.registry
        )
        
        self.threat_detection_latency = Histogram(
            'waf_threat_detection_latency_seconds',
            'Latency of threat detection',
            ['detector_type'],
            registry=self.registry
        )
        
        # Authentication metrics
        self.authentication_attempts_total = Counter(
            'waf_authentication_attempts_total',
            'Total authentication attempts',
            ['result', 'method'],
            registry=self.registry
        )
        
        self.authentication_duration = Histogram(
            'waf_authentication_duration_seconds',
            'Authentication processing time',
            registry=self.registry
        )
        
        # Session metrics
        self.active_sessions = Gauge(
            'waf_active_sessions',
            'Number of active user sessions',
            registry=self.registry
        )
        
        self.session_duration = Histogram(
            'waf_session_duration_seconds',
            'Duration of user sessions',
            registry=self.registry
        )
        
        # ML Model metrics
        self.ml_model_predictions_total = Counter(
            'waf_ml_model_predictions_total',
            'Total ML model predictions',
            ['model_name', 'prediction'],
            registry=self.registry
        )
        
        self.ml_model_accuracy = Gauge(
            'waf_ml_model_accuracy',
            'ML model accuracy',
            ['model_name'],
            registry=self.registry
        )
        
        self.ml_inference_duration = Histogram(
            'waf_ml_inference_duration_seconds',
            'ML model inference time',
            ['model_name'],
            registry=self.registry
        )
        
        # Anomaly detection metrics
        self.anomalies_detected_total = Counter(
            'waf_anomalies_detected_total',
            'Total anomalies detected',
            ['anomaly_type', 'method'],
            registry=self.registry
        )
        
        self.anomaly_score = Histogram(
            'waf_anomaly_score',
            'Anomaly detection scores',
            ['detector'],
            registry=self.registry
        )
        
        # SSL/TLS metrics
        self.ssl_connections_total = Counter(
            'waf_ssl_connections_total',
            'Total SSL/TLS connections',
            ['version', 'cipher_suite'],
            registry=self.registry
        )
        
        self.ssl_certificate_issues_total = Counter(
            'waf_ssl_certificate_issues_total',
            'SSL certificate issues detected',
            ['issue_type'],
            registry=self.registry
        )
        
        # Threat intelligence metrics
        self.threat_intel_lookups_total = Counter(
            'waf_threat_intel_lookups_total',
            'Total threat intelligence lookups',
            ['ioc_type', 'result'],
            registry=self.registry
        )
        
        self.threat_intel_iocs_total = Gauge(
            'waf_threat_intel_iocs_total',
            'Total IOCs in threat intelligence',
            ['ioc_type', 'source'],
            registry=self.registry
        )
        
        # System performance metrics
        self.cpu_usage_percent = Gauge(
            'waf_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage_bytes = Gauge(
            'waf_memory_usage_bytes',
            'Memory usage in bytes',
            ['type'],
            registry=self.registry
        )
        
        self.network_throughput_bytes = Gauge(
            'waf_network_throughput_bytes_per_second',
            'Network throughput in bytes per second',
            ['direction'],
            registry=self.registry
        )
        
        # Error metrics
        self.errors_total = Counter(
            'waf_errors_total',
            'Total errors',
            ['component', 'error_type'],
            registry=self.registry
        )
        
        # WAF info
        self.waf_info = Info(
            'waf_info',
            'WAF version and configuration info',
            registry=self.registry
        )
        
        # Set WAF info
        self.waf_info.info({
            'version': '1.0.0',
            'build_date': datetime.now().isoformat(),
            'features': 'dpi,ml,zero_trust,threat_intel'
        })
        
        # Internal metrics storage for dashboard
        self.metrics_history = {
            'packets_per_second': deque(maxlen=3600),  # 1 hour of data
            'threats_per_minute': deque(maxlen=1440),  # 24 hours of data
            'response_times': deque(maxlen=1000),
            'error_rates': deque(maxlen=1440)
        }
        
        # Background metrics collection
        self.metrics_task: Optional[asyncio.Task] = None
        self.is_collecting = False
        
        self.logger.info("Metrics collector initialized")
    
    def start_metrics_server(self, port: int = 9090):
        """Start Prometheus metrics server"""
        try:
            start_http_server(port, registry=self.registry)
            self.logger.info(f"Metrics server started on port {port}")
        except Exception as e:
            self.logger.error(f"Failed to start metrics server: {e}")
    
    def start_background_collection(self):
        """Start background metrics collection"""
        if not self.is_collecting:
            self.is_collecting = True
            self.metrics_task = asyncio.create_task(self._collect_system_metrics())
            self.logger.info("Background metrics collection started")
    
    def stop_background_collection(self):
        """Stop background metrics collection"""
        self.is_collecting = False
        if self.metrics_task:
            self.metrics_task.cancel()
            self.logger.info("Background metrics collection stopped")
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            import psutil
            
            while self.is_collecting:
                try:
                    # CPU metrics
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.cpu_usage_percent.set(cpu_percent)
                    
                    # Memory metrics
                    memory = psutil.virtual_memory()
                    self.memory_usage_bytes.labels(type='used').set(memory.used)
                    self.memory_usage_bytes.labels(type='available').set(memory.available)
                    self.memory_usage_bytes.labels(type='total').set(memory.total)
                    
                    # Network metrics (simplified)
                    net_io = psutil.net_io_counters()
                    self.network_throughput_bytes.labels(direction='sent').set(net_io.bytes_sent)
                    self.network_throughput_bytes.labels(direction='recv').set(net_io.bytes_recv)
                    
                    # Log performance metrics
                    performance_logger.log_performance_metric(
                        "cpu_usage", cpu_percent, "percent", "system"
                    )
                    performance_logger.log_performance_metric(
                        "memory_usage", memory.percent, "percent", "system"
                    )
                    
                    await asyncio.sleep(10)  # Collect every 10 seconds
                    
                except Exception as e:
                    self.logger.error(f"Error collecting system metrics: {e}")
                    await asyncio.sleep(30)  # Wait longer on error
                    
        except ImportError:
            self.logger.warning("psutil not available, system metrics disabled")
        except Exception as e:
            self.logger.error(f"System metrics collection error: {e}")
    
    # Convenience methods for incrementing counters
    def increment_counter(self, metric_name: str, labels: Dict[str, str] = None, value: float = 1):
        """Increment a counter metric"""
        try:
            metric = getattr(self, metric_name, None)
            if metric:
                if labels:
                    metric.labels(**labels).inc(value)
                else:
                    metric.inc(value)
        except Exception as e:
            self.logger.error(f"Error incrementing counter {metric_name}: {e}")
    
    def set_gauge(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric value"""
        try:
            metric = getattr(self, metric_name, None)
            if metric:
                if labels:
                    metric.labels(**labels).set(value)
                else:
                    metric.set(value)
        except Exception as e:
            self.logger.error(f"Error setting gauge {metric_name}: {e}")
    
    def observe_histogram(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Observe a histogram metric"""
        try:
            metric = getattr(self, metric_name, None)
            if metric:
                if labels:
                    metric.labels(**labels).observe(value)
                else:
                    metric.observe(value)
        except Exception as e:
            self.logger.error(f"Error observing histogram {metric_name}: {e}")
    
    # High-level metric recording methods
    def record_packet_processed(self, interface: str, protocol: str, processing_time: float):
        """Record packet processing metrics"""
        self.packets_processed_total.labels(interface=interface, protocol=protocol).inc()
        self.packet_processing_duration.labels(component='main').observe(processing_time)
        
        # Update history for dashboard
        current_time = time.time()
        self.metrics_history['packets_per_second'].append((current_time, 1))
    
    def record_threat_detected(self, threat_type: str, severity: str, source: str, detection_time: float):
        """Record threat detection metrics"""
        self.threats_detected_total.labels(
            threat_type=threat_type,
            severity=severity,
            source=source
        ).inc()
        
        self.threat_detection_latency.labels(detector_type=source).observe(detection_time)
        
        # Update history
        current_time = time.time()
        self.metrics_history['threats_per_minute'].append((current_time, 1))
    
    def record_authentication_attempt(self, result: str, method: str, duration: float):
        """Record authentication metrics"""
        self.authentication_attempts_total.labels(result=result, method=method).inc()
        self.authentication_duration.observe(duration)
    
    def record_ml_prediction(self, model_name: str, prediction: str, inference_time: float):
        """Record ML model metrics"""
        self.ml_model_predictions_total.labels(
            model_name=model_name,
            prediction=prediction
        ).inc()
        
        self.ml_inference_duration.labels(model_name=model_name).observe(inference_time)
    
    def record_anomaly_detected(self, anomaly_type: str, method: str, score: float):
        """Record anomaly detection metrics"""
        self.anomalies_detected_total.labels(
            anomaly_type=anomaly_type,
            method=method
        ).inc()
        
        self.anomaly_score.labels(detector=method).observe(score)
    
    def record_ssl_connection(self, version: str, cipher_suite: str):
        """Record SSL/TLS connection metrics"""
        self.ssl_connections_total.labels(
            version=version,
            cipher_suite=cipher_suite
        ).inc()
    
    def record_ssl_certificate_issue(self, issue_type: str):
        """Record SSL certificate issue"""
        self.ssl_certificate_issues_total.labels(issue_type=issue_type).inc()
    
    def record_threat_intel_lookup(self, ioc_type: str, result: str):
        """Record threat intelligence lookup"""
        self.threat_intel_lookups_total.labels(
            ioc_type=ioc_type,
            result=result
        ).inc()
    
    def record_error(self, component: str, error_type: str):
        """Record error metrics"""
        self.errors_total.labels(component=component, error_type=error_type).inc()
        
        # Update error rate history
        current_time = time.time()
        self.metrics_history['error_rates'].append((current_time, 1))
    
    def update_active_sessions(self, count: int):
        """Update active sessions count"""
        self.active_sessions.set(count)
    
    def update_threat_intel_iocs(self, ioc_type: str, source: str, count: int):
        """Update threat intelligence IOC count"""
        self.threat_intel_iocs_total.labels(ioc_type=ioc_type, source=source).set(count)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary for dashboard"""
        try:
            current_time = time.time()
            
            # Calculate packets per second (last minute)
            recent_packets = [
                count for timestamp, count in self.metrics_history['packets_per_second']
                if current_time - timestamp <= 60
            ]
            packets_per_second = sum(recent_packets) / 60 if recent_packets else 0
            
            # Calculate threats per minute (last hour)
            recent_threats = [
                count for timestamp, count in self.metrics_history['threats_per_minute']
                if current_time - timestamp <= 3600
            ]
            threats_per_hour = sum(recent_threats)
            
            # Calculate error rate (last hour)
            recent_errors = [
                count for timestamp, count in self.metrics_history['error_rates']
                if current_time - timestamp <= 3600
            ]
            errors_per_hour = sum(recent_errors)
            
            # Average response time (last 1000 requests)
            avg_response_time = (
                sum(self.metrics_history['response_times']) / len(self.metrics_history['response_times'])
                if self.metrics_history['response_times'] else 0
            )
            
            return {
                "packets_per_second": packets_per_second,
                "threats_per_hour": threats_per_hour,
                "errors_per_hour": errors_per_hour,
                "average_response_time_ms": avg_response_time * 1000,
                "active_sessions": self.active_sessions._value._value,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting metrics summary: {e}")
            return {}
    
    def get_time_series_data(self, metric_name: str, duration_minutes: int = 60) -> List[Dict]:
        """Get time series data for dashboard charts"""
        try:
            if metric_name not in self.metrics_history:
                return []
            
            current_time = time.time()
            cutoff_time = current_time - (duration_minutes * 60)
            
            # Filter data by time range
            filtered_data = [
                {"timestamp": timestamp, "value": value}
                for timestamp, value in self.metrics_history[metric_name]
                if timestamp >= cutoff_time
            ]
            
            return filtered_data
            
        except Exception as e:
            self.logger.error(f"Error getting time series data for {metric_name}: {e}")
            return []

def setup_metrics(settings: Settings) -> MetricsCollector:
    """Setup metrics collection"""
    collector = MetricsCollector(settings)
    
    if settings.enable_metrics:
        collector.start_metrics_server(settings.metrics_port)
        collector.start_background_collection()
    
    return collector