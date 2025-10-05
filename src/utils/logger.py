"""
Logging configuration for AI-Driven WAF
Structured logging with security event correlation
"""

import logging
import logging.handlers
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import structlog
from structlog.stdlib import LoggerFactory

# Create logs directory
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

def setup_logging(log_level: str = "INFO", log_to_file: bool = True):
    """Setup structured logging configuration"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )
    
    # Setup file handlers if requested
    if log_to_file:
        # Main application log
        app_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "waf.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        app_handler.setLevel(logging.INFO)
        
        # Security events log
        security_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "security.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        )
        security_handler.setLevel(logging.WARNING)
        
        # Error log
        error_handler = logging.handlers.RotatingFileHandler(
            LOG_DIR / "error.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        
        # Add handlers to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(app_handler)
        root_logger.addHandler(security_handler)
        root_logger.addHandler(error_handler)

def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance"""
    return structlog.get_logger(name)

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self):
        self.logger = get_logger("security")
    
    def log_authentication_attempt(self, username: str, source_ip: str, 
                                 success: bool, risk_level: str = None,
                                 additional_info: Dict[str, Any] = None):
        """Log authentication attempt"""
        event_data = {
            "event_type": "authentication",
            "username": username,
            "source_ip": source_ip,
            "success": success,
            "risk_level": risk_level,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        if success:
            self.logger.info("Authentication successful", **event_data)
        else:
            self.logger.warning("Authentication failed", **event_data)
    
    def log_threat_detection(self, threat_type: str, source_ip: str, 
                           target_ip: str, severity: str, confidence: float,
                           description: str, action_taken: str,
                           additional_info: Dict[str, Any] = None):
        """Log threat detection event"""
        event_data = {
            "event_type": "threat_detection",
            "threat_type": threat_type,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "action_taken": action_taken,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        if severity in ["HIGH", "CRITICAL"]:
            self.logger.error("High severity threat detected", **event_data)
        else:
            self.logger.warning("Threat detected", **event_data)
    
    def log_anomaly_detection(self, anomaly_type: str, source_ip: str,
                            anomaly_score: float, description: str,
                            additional_info: Dict[str, Any] = None):
        """Log anomaly detection event"""
        event_data = {
            "event_type": "anomaly_detection",
            "anomaly_type": anomaly_type,
            "source_ip": source_ip,
            "anomaly_score": anomaly_score,
            "description": description,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        self.logger.warning("Anomaly detected", **event_data)
    
    def log_access_violation(self, user_id: str, resource: str, action: str,
                           reason: str, source_ip: str,
                           additional_info: Dict[str, Any] = None):
        """Log access violation"""
        event_data = {
            "event_type": "access_violation",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "reason": reason,
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        self.logger.warning("Access violation", **event_data)
    
    def log_system_event(self, event_type: str, description: str,
                        severity: str = "INFO", component: str = None,
                        additional_info: Dict[str, Any] = None):
        """Log system event"""
        event_data = {
            "event_type": "system_event",
            "description": description,
            "component": component,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(f"System event: {event_type}", **event_data)

class AuditLogger:
    """Audit logger for compliance and forensics"""
    
    def __init__(self):
        self.logger = get_logger("audit")
    
    def log_configuration_change(self, user_id: str, component: str,
                                old_config: Dict, new_config: Dict,
                                source_ip: str):
        """Log configuration changes"""
        event_data = {
            "event_type": "configuration_change",
            "user_id": user_id,
            "component": component,
            "old_config": old_config,
            "new_config": new_config,
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info("Configuration changed", **event_data)
    
    def log_policy_change(self, user_id: str, policy_id: str,
                         action: str, policy_data: Dict,
                         source_ip: str):
        """Log security policy changes"""
        event_data = {
            "event_type": "policy_change",
            "user_id": user_id,
            "policy_id": policy_id,
            "action": action,
            "policy_data": policy_data,
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info("Security policy changed", **event_data)
    
    def log_data_access(self, user_id: str, resource: str,
                       action: str, result: str,
                       source_ip: str, additional_info: Dict = None):
        """Log data access attempts"""
        event_data = {
            "event_type": "data_access",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "result": result,
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_info:
            event_data.update(additional_info)
        
        self.logger.info("Data access", **event_data)

class PerformanceLogger:
    """Performance and metrics logger"""
    
    def __init__(self):
        self.logger = get_logger("performance")
    
    def log_performance_metric(self, metric_name: str, value: float,
                             unit: str, component: str = None,
                             additional_tags: Dict[str, str] = None):
        """Log performance metric"""
        event_data = {
            "event_type": "performance_metric",
            "metric_name": metric_name,
            "value": value,
            "unit": unit,
            "component": component,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_tags:
            event_data["tags"] = additional_tags
        
        self.logger.info("Performance metric", **event_data)
    
    def log_request_timing(self, endpoint: str, method: str,
                          duration_ms: float, status_code: int,
                          user_id: str = None, source_ip: str = None):
        """Log API request timing"""
        event_data = {
            "event_type": "request_timing",
            "endpoint": endpoint,
            "method": method,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "user_id": user_id,
            "source_ip": source_ip,
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info("Request completed", **event_data)
    
    def log_throughput(self, packets_per_second: float,
                      bytes_per_second: float,
                      connections_active: int):
        """Log network throughput metrics"""
        event_data = {
            "event_type": "throughput_metric",
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "connections_active": connections_active,
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.info("Throughput metrics", **event_data)

# Global logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()
performance_logger = PerformanceLogger()

# Correlation ID context manager
import contextvars
correlation_id_var = contextvars.ContextVar('correlation_id', default=None)

def set_correlation_id(correlation_id: str):
    """Set correlation ID for request tracing"""
    correlation_id_var.set(correlation_id)

def get_correlation_id() -> Optional[str]:
    """Get current correlation ID"""
    return correlation_id_var.get()

class CorrelationFilter(logging.Filter):
    """Add correlation ID to log records"""
    
    def filter(self, record):
        correlation_id = get_correlation_id()
        if correlation_id:
            record.correlation_id = correlation_id
        return True

# Add correlation filter to all handlers
correlation_filter = CorrelationFilter()
for handler in logging.getLogger().handlers:
    handler.addFilter(correlation_filter)