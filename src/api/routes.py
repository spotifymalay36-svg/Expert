"""
API Routes for AI-Driven WAF
RESTful API endpoints for WAF management and monitoring
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import json

from ..core.waf_engine import WAFEngine
from ..zero_trust.auth_manager import AuthManager, AuthenticationContext, AuthenticationResult
from ..threat_intel.intel_manager import IOCType, ThreatCategory
from ..core.config import ThreatLevel
from ..utils.logger import get_logger

# Security
security = HTTPBearer()
logger = get_logger(__name__)

# Request/Response Models
class AuthRequest(BaseModel):
    username: str
    password: str
    device_fingerprint: Optional[str] = None
    location: Optional[Dict] = None

class AuthResponse(BaseModel):
    success: bool
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    risk_level: Optional[str] = None
    message: str

class ThreatAlert(BaseModel):
    id: str
    timestamp: datetime
    threat_type: str
    severity: str
    source_ip: str
    target_ip: str
    description: str
    confidence: float
    action_taken: str

class WAFStats(BaseModel):
    packets_processed: int
    threats_detected: int
    alerts_generated: int
    blocked_requests: int
    uptime_seconds: float
    packets_per_second: float
    is_running: bool

class IOCRequest(BaseModel):
    ioc_type: str = Field(..., description="IOC type (ip-addr, domain-name, url, file)")
    value: str = Field(..., description="IOC value")
    threat_category: str = Field(..., description="Threat category")
    confidence: float = Field(0.9, ge=0.0, le=1.0)
    severity: str = Field("MEDIUM", description="Threat severity")
    description: Optional[str] = None

class PolicyRequest(BaseModel):
    name: str
    resource_pattern: str
    allowed_roles: List[str]
    allowed_ips: List[str] = ["*"]
    max_risk_level: str = "MEDIUM"
    requires_mfa: bool = False

# Create router
api_router = APIRouter()

# Dependency to get WAF engine
async def get_waf_engine(request: Request) -> WAFEngine:
    waf_engine = getattr(request.app.state, 'waf_engine', None)
    if not waf_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WAF engine not available"
        )
    return waf_engine

# Dependency to get auth manager
async def get_auth_manager(waf_engine: WAFEngine = Depends(get_waf_engine)) -> AuthManager:
    if not waf_engine.auth_manager:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication manager not available"
        )
    return waf_engine.auth_manager

# Dependency for authentication
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_manager: AuthManager = Depends(get_auth_manager)
) -> Dict:
    try:
        is_valid, user_info = await auth_manager.validate_session(credentials.credentials)
        
        if not is_valid or not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        
        return user_info
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

# Authentication endpoints
@api_router.post("/auth/login", response_model=AuthResponse)
async def login(
    auth_request: AuthRequest,
    request: Request,
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """Authenticate user and return access token"""
    try:
        # Create authentication context
        context = AuthenticationContext(
            user_id=None,
            username=auth_request.username,
            source_ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            device_fingerprint=auth_request.device_fingerprint,
            location=auth_request.location,
            timestamp=datetime.now(),
            authentication_method="password"
        )
        
        # Authenticate user
        result, additional_data = await auth_manager.authenticate_user(
            context, auth_request.password
        )
        
        if result == AuthenticationResult.SUCCESS:
            return AuthResponse(
                success=True,
                access_token=additional_data["access_token"],
                token_type=additional_data["token_type"],
                expires_in=additional_data["expires_in"],
                risk_level=additional_data["risk_level"],
                message="Authentication successful"
            )
        elif result == AuthenticationResult.REQUIRES_MFA:
            return AuthResponse(
                success=False,
                message="MFA required"
            )
        elif result == AuthenticationResult.BLOCKED:
            return AuthResponse(
                success=False,
                message="Account blocked due to security concerns"
            )
        else:
            return AuthResponse(
                success=False,
                message="Authentication failed"
            )
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )

@api_router.post("/auth/logout")
async def logout(
    current_user: Dict = Depends(get_current_user),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """Logout user and invalidate session"""
    try:
        session_id = current_user.get("session_id")
        if session_id:
            await auth_manager._invalidate_session(session_id)
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service error"
        )

@api_router.get("/auth/me")
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "roles": current_user["roles"],
        "risk_level": current_user.get("risk_level")
    }

# WAF Management endpoints
@api_router.get("/waf/status", response_model=WAFStats)
async def get_waf_status(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get WAF status and statistics"""
    try:
        stats = await waf_engine.get_statistics()
        
        return WAFStats(
            packets_processed=stats["packets_processed"],
            threats_detected=stats["threats_detected"],
            alerts_generated=stats["alerts_generated"],
            blocked_requests=stats["blocked_requests"],
            uptime_seconds=stats["uptime_seconds"],
            packets_per_second=stats["packets_per_second"],
            is_running=stats["is_running"]
        )
        
    except Exception as e:
        logger.error(f"Error getting WAF status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get WAF status"
        )

@api_router.get("/waf/alerts", response_model=List[ThreatAlert])
async def get_threat_alerts(
    limit: int = 100,
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get recent threat alerts"""
    try:
        alerts_data = await waf_engine.get_recent_alerts(limit)
        
        alerts = []
        for alert_data in alerts_data:
            alerts.append(ThreatAlert(
                id=alert_data["id"],
                timestamp=datetime.fromisoformat(alert_data["timestamp"]),
                threat_type=alert_data["threat_type"],
                severity=alert_data["severity"],
                source_ip=alert_data["source_ip"],
                target_ip=alert_data["target_ip"],
                description=alert_data["description"],
                confidence=alert_data["confidence"],
                action_taken=alert_data["action_taken"]
            ))
        
        return alerts
        
    except Exception as e:
        logger.error(f"Error getting threat alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get threat alerts"
        )

@api_router.get("/waf/blocked-ips")
async def get_blocked_ips(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get list of blocked IP addresses"""
    try:
        # This would need to be implemented in the WAF engine
        # For now, return empty list
        return {"blocked_ips": []}
        
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get blocked IPs"
        )

@api_router.post("/waf/unblock-ip/{ip_address}")
async def unblock_ip(
    ip_address: str,
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Unblock IP address"""
    try:
        # Check if user has admin role
        if "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required"
            )
        
        # Remove from Redis blocked list
        await waf_engine.redis_client.delete(f"blocked_ip:{ip_address}")
        
        return {"message": f"IP {ip_address} unblocked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unblock IP"
        )

# Threat Intelligence endpoints
@api_router.get("/threat-intel/stats")
async def get_threat_intel_stats(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get threat intelligence statistics"""
    try:
        if not waf_engine.threat_intel:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Threat intelligence not available"
            )
        
        stats = await waf_engine.threat_intel.get_threat_intelligence_stats()
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting threat intel stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get threat intelligence stats"
        )

@api_router.post("/threat-intel/add-ioc")
async def add_custom_ioc(
    ioc_request: IOCRequest,
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Add custom IOC to threat intelligence"""
    try:
        # Check if user has admin role
        if "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required"
            )
        
        if not waf_engine.threat_intel:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Threat intelligence not available"
            )
        
        # Convert string enums to proper types
        try:
            ioc_type = IOCType(ioc_request.ioc_type)
            threat_category = ThreatCategory(ioc_request.threat_category)
            severity = ThreatLevel(ioc_request.severity)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid enum value: {e}"
            )
        
        success = await waf_engine.threat_intel.add_custom_ioc(
            ioc_type=ioc_type,
            value=ioc_request.value,
            threat_category=threat_category,
            confidence=ioc_request.confidence,
            severity=severity,
            description=ioc_request.description
        )
        
        if success:
            return {"message": "IOC added successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add IOC"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding IOC: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add IOC"
        )

# ML Model endpoints
@api_router.get("/ml/models/status")
async def get_ml_models_status(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get ML models status"""
    try:
        status_info = {
            "threat_detector": {
                "initialized": waf_engine.threat_detector is not None,
                "models_loaded": len(waf_engine.threat_detector.models) if waf_engine.threat_detector else 0
            },
            "anomaly_detector": {
                "initialized": waf_engine.anomaly_detector is not None,
                "models_trained": bool(waf_engine.anomaly_detector and 
                                    waf_engine.anomaly_detector.models.get('isolation_forest'))
            }
        }
        
        return status_info
        
    except Exception as e:
        logger.error(f"Error getting ML models status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get ML models status"
        )

@api_router.post("/ml/models/train")
async def train_ml_models(
    background_tasks: BackgroundTasks,
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Trigger ML model training"""
    try:
        # Check if user has admin role
        if "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required"
            )
        
        # Add training task to background
        background_tasks.add_task(train_models_background, waf_engine)
        
        return {"message": "Model training started in background"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting model training: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start model training"
        )

async def train_models_background(waf_engine: WAFEngine):
    """Background task for model training"""
    try:
        logger.info("Starting background model training")
        
        # This would need training data - placeholder for now
        training_data = []
        
        if waf_engine.threat_detector:
            await waf_engine.threat_detector.train_models(training_data)
        
        if waf_engine.anomaly_detector:
            await waf_engine.anomaly_detector.train_anomaly_models(training_data)
        
        logger.info("Background model training completed")
        
    except Exception as e:
        logger.error(f"Error in background model training: {e}")

# Anomaly Detection endpoints
@api_router.get("/anomaly/stats")
async def get_anomaly_stats(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get anomaly detection statistics"""
    try:
        if not waf_engine.anomaly_detector:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Anomaly detector not available"
            )
        
        stats = await waf_engine.anomaly_detector.get_anomaly_statistics()
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting anomaly stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get anomaly statistics"
        )

# Network Segmentation endpoints
@api_router.get("/network/segments")
async def get_network_segments(
    auth_manager: AuthManager = Depends(get_auth_manager),
    current_user: Dict = Depends(get_current_user)
):
    """Get network segments configuration"""
    try:
        return {"segments": auth_manager.network_segments}
        
    except Exception as e:
        logger.error(f"Error getting network segments: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get network segments"
        )

@api_router.get("/network/segment/{ip_address}")
async def get_ip_segment(
    ip_address: str,
    auth_manager: AuthManager = Depends(get_auth_manager),
    current_user: Dict = Depends(get_current_user)
):
    """Get network segment for IP address"""
    try:
        segment = await auth_manager.get_network_segment(ip_address)
        return {"ip_address": ip_address, "segment": segment}
        
    except Exception as e:
        logger.error(f"Error getting IP segment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get IP segment"
        )

# Configuration endpoints
@api_router.get("/config/settings")
async def get_waf_settings(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get WAF configuration settings"""
    try:
        # Check if user has admin role
        if "admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required"
            )
        
        settings = {
            "enable_dpi": waf_engine.settings.enable_dpi,
            "enable_ssl_inspection": waf_engine.settings.enable_ssl_inspection,
            "enable_anomaly_detection": waf_engine.settings.enable_anomaly_detection,
            "enable_zero_trust": waf_engine.settings.enable_zero_trust,
            "enable_threat_intel": waf_engine.settings.enable_threat_intel,
            "confidence_threshold": waf_engine.settings.confidence_threshold,
            "anomaly_threshold": waf_engine.settings.anomaly_threshold
        }
        
        return settings
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting WAF settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get WAF settings"
        )

# Health check endpoint
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# System information endpoint
@api_router.get("/system/info")
async def get_system_info(
    waf_engine: WAFEngine = Depends(get_waf_engine),
    current_user: Dict = Depends(get_current_user)
):
    """Get system information"""
    try:
        import psutil
        import platform
        
        system_info = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            },
            "waf_version": "1.0.0",
            "uptime": waf_engine.stats.get("uptime_seconds", 0)
        }
        
        return system_info
        
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system information"
        )