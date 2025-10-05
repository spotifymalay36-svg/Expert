"""
Configuration management for AI-Driven WAF
"""

import os
from typing import List, Dict, Any, Optional
from pydantic import BaseSettings, Field
from enum import Enum

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    app_name: str = "AI-Driven WAF"
    version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    log_level: LogLevel = Field(default=LogLevel.INFO, env="LOG_LEVEL")
    
    # Network Configuration
    interface: str = Field(default="eth0", env="NETWORK_INTERFACE")
    capture_filter: str = Field(default="", env="CAPTURE_FILTER")
    max_packet_size: int = Field(default=65535, env="MAX_PACKET_SIZE")
    
    # Database
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    postgres_url: str = Field(default="postgresql://waf_user:waf_pass@localhost:5432/waf_db", env="POSTGRES_URL")
    elasticsearch_url: str = Field(default="http://localhost:9200", env="ELASTICSEARCH_URL")
    
    # AI/ML Configuration
    model_path: str = Field(default="./models", env="MODEL_PATH")
    enable_gpu: bool = Field(default=False, env="ENABLE_GPU")
    batch_size: int = Field(default=32, env="BATCH_SIZE")
    confidence_threshold: float = Field(default=0.8, env="CONFIDENCE_THRESHOLD")
    
    # Threat Detection
    enable_dpi: bool = Field(default=True, env="ENABLE_DPI")
    enable_ssl_inspection: bool = Field(default=True, env="ENABLE_SSL_INSPECTION")
    enable_anomaly_detection: bool = Field(default=True, env="ENABLE_ANOMALY_DETECTION")
    anomaly_threshold: float = Field(default=0.7, env="ANOMALY_THRESHOLD")
    
    # Zero Trust
    enable_zero_trust: bool = Field(default=True, env="ENABLE_ZERO_TRUST")
    jwt_secret_key: str = Field(default="your-secret-key-change-in-production", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Threat Intelligence
    enable_threat_intel: bool = Field(default=True, env="ENABLE_THREAT_INTEL")
    threat_intel_feeds: List[str] = Field(default=[
        "https://api.threatintel.com/feed",
        "https://feeds.malwaredomains.com/files/justdomains"
    ], env="THREAT_INTEL_FEEDS")
    
    # Performance
    max_concurrent_connections: int = Field(default=10000, env="MAX_CONCURRENT_CONNECTIONS")
    packet_buffer_size: int = Field(default=1000000, env="PACKET_BUFFER_SIZE")
    processing_threads: int = Field(default=4, env="PROCESSING_THREADS")
    
    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")
    
    # Security Policies
    default_action: str = Field(default="ALLOW", env="DEFAULT_ACTION")  # ALLOW, BLOCK, LOG
    rate_limit_requests: int = Field(default=1000, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")  # seconds
    
    # Federated Learning
    enable_federated_learning: bool = Field(default=False, env="ENABLE_FEDERATED_LEARNING")
    federation_server: str = Field(default="localhost:8080", env="FEDERATION_SERVER")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class WAFRules:
    """WAF security rules configuration"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION[^\w]{1,5}SELECT",
        r"SELECT.*FROM.*WHERE",
        r"INSERT\s+INTO",
        r"UPDATE.*SET",
        r"DELETE\s+FROM"
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>",
        r"<link[^>]*>",
        r"<meta[^>]*>",
        r"expression\s*\(",
        r"vbscript:",
        r"<svg[^>]*>.*?</svg>"
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`]",
        r"\$\([^)]*\)",
        r"`[^`]*`",
        r"\|\s*\w+",
        r"&&\s*\w+",
        r";\s*\w+",
        r"nc\s+-",
        r"wget\s+",
        r"curl\s+",
        r"ping\s+-"
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e\\",
        r"\.\.%2f",
        r"\.\.%5c"
    ]
    
    # Suspicious User Agents
    SUSPICIOUS_USER_AGENTS = [
        "sqlmap",
        "nikto",
        "nessus",
        "openvas",
        "nmap",
        "masscan",
        "zap",
        "burp",
        "w3af",
        "skipfish"
    ]
    
    # Malicious IPs (example - should be updated from threat intel)
    MALICIOUS_IPS = [
        "192.168.1.100",  # Example malicious IP
        "10.0.0.50"       # Example malicious IP
    ]
    
    # Rate limiting rules
    RATE_LIMIT_RULES = {
        "default": {"requests": 1000, "window": 60},
        "api": {"requests": 100, "window": 60},
        "login": {"requests": 5, "window": 300},
        "admin": {"requests": 10, "window": 60}
    }

class MITREAttackTechniques:
    """MITRE ATT&CK framework techniques mapping"""
    
    TECHNIQUES = {
        "T1190": "Exploit Public-Facing Application",
        "T1059": "Command and Scripting Interpreter",
        "T1055": "Process Injection",
        "T1071": "Application Layer Protocol",
        "T1083": "File and Directory Discovery",
        "T1087": "Account Discovery",
        "T1018": "Remote System Discovery",
        "T1082": "System Information Discovery",
        "T1016": "System Network Configuration Discovery",
        "T1049": "System Network Connections Discovery"
    }
    
    TACTICS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution", 
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control"
    }