"""
Zero Trust Authentication Manager
Implements continuous verification, risk-based authentication, and micro-segmentation
"""

import logging
import hashlib
import hmac
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import ipaddress

import jwt
from passlib.context import CryptContext
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

class AuthenticationResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    REQUIRES_MFA = "REQUIRES_MFA"
    BLOCKED = "BLOCKED"
    REQUIRES_ADDITIONAL_VERIFICATION = "REQUIRES_ADDITIONAL_VERIFICATION"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class User:
    """User entity"""
    id: str
    username: str
    email: str
    password_hash: str
    roles: List[str]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None

@dataclass
class Device:
    """Device entity"""
    id: str
    user_id: str
    device_fingerprint: str
    device_type: str
    os_info: str
    browser_info: Optional[str]
    is_trusted: bool
    first_seen: datetime
    last_seen: datetime
    location_history: List[Dict] = None

@dataclass
class AuthenticationContext:
    """Authentication context for risk assessment"""
    user_id: Optional[str]
    username: str
    source_ip: str
    user_agent: Optional[str]
    device_fingerprint: Optional[str]
    location: Optional[Dict]
    timestamp: datetime
    authentication_method: str
    session_id: Optional[str] = None

@dataclass
class RiskAssessment:
    """Risk assessment result"""
    risk_level: RiskLevel
    risk_score: float
    risk_factors: List[str]
    recommended_actions: List[str]
    requires_additional_verification: bool

@dataclass
class AccessPolicy:
    """Access control policy"""
    id: str
    name: str
    resource_pattern: str
    allowed_roles: List[str]
    allowed_ips: List[str]
    allowed_times: Dict[str, Any]  # Time-based access rules
    max_risk_level: RiskLevel
    requires_mfa: bool
    is_active: bool

class AuthManager:
    """Zero Trust Authentication Manager"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Redis client for session management
        self.redis_client: Optional[redis.Redis] = None
        
        # In-memory stores (in production, these would be in database)
        self.users: Dict[str, User] = {}
        self.devices: Dict[str, Device] = {}
        self.access_policies: Dict[str, AccessPolicy] = {}
        self.active_sessions: Dict[str, Dict] = {}
        
        # Risk assessment components
        self.risk_assessors = {
            'location': self._assess_location_risk,
            'device': self._assess_device_risk,
            'behavior': self._assess_behavioral_risk,
            'time': self._assess_time_risk,
            'network': self._assess_network_risk
        }
        
        # Behavioral baselines
        self.user_baselines: Dict[str, Dict] = {}
        
        # Network segments for micro-segmentation
        self.network_segments = {
            'trusted': ['10.0.1.0/24', '192.168.1.0/24'],
            'dmz': ['10.0.2.0/24'],
            'quarantine': ['10.0.99.0/24'],
            'guest': ['10.0.100.0/24']
        }
        
        self.logger.info("Zero Trust Auth Manager initialized")
    
    async def initialize(self):
        """Initialize authentication manager"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(self.settings.redis_url)
            await self.redis_client.ping()
            
            # Load default policies
            await self._load_default_policies()
            
            # Create default admin user
            await self._create_default_admin()
            
            self.logger.info("Auth Manager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Auth Manager: {e}")
            raise
    
    async def authenticate_user(self, context: AuthenticationContext, password: str) -> Tuple[AuthenticationResult, Optional[Dict]]:
        """Authenticate user with Zero Trust principles"""
        try:
            # Get user
            user = await self._get_user(context.username)
            if not user or not user.is_active:
                await self._log_authentication_attempt(context, False, "User not found or inactive")
                return AuthenticationResult.FAILED, None
            
            # Verify password
            if not self.pwd_context.verify(password, user.password_hash):
                user.failed_login_attempts += 1
                await self._update_user(user)
                await self._log_authentication_attempt(context, False, "Invalid password")
                
                # Block user after too many failed attempts
                if user.failed_login_attempts >= 5:
                    user.is_active = False
                    await self._update_user(user)
                    return AuthenticationResult.BLOCKED, None
                
                return AuthenticationResult.FAILED, None
            
            # Reset failed attempts on successful password verification
            user.failed_login_attempts = 0
            context.user_id = user.id
            
            # Perform risk assessment
            risk_assessment = await self._assess_authentication_risk(context, user)
            
            # Determine authentication result based on risk
            auth_result, additional_data = await self._determine_authentication_result(
                user, context, risk_assessment
            )
            
            # Create session if authentication successful
            if auth_result == AuthenticationResult.SUCCESS:
                session_data = await self._create_session(user, context, risk_assessment)
                additional_data = session_data
                
                # Update user login info
                user.last_login = datetime.now()
                await self._update_user(user)
            
            await self._log_authentication_attempt(context, auth_result == AuthenticationResult.SUCCESS, 
                                                 f"Risk level: {risk_assessment.risk_level}")
            
            return auth_result, additional_data
            
        except Exception as e:
            self.logger.error(f"Error in user authentication: {e}")
            return AuthenticationResult.FAILED, None
    
    async def _assess_authentication_risk(self, context: AuthenticationContext, user: User) -> RiskAssessment:
        """Comprehensive risk assessment for authentication"""
        try:
            risk_factors = []
            risk_scores = []
            
            # Run all risk assessors
            for assessor_name, assessor_func in self.risk_assessors.items():
                try:
                    score, factors = await assessor_func(context, user)
                    risk_scores.append(score)
                    risk_factors.extend(factors)
                except Exception as e:
                    self.logger.error(f"Error in {assessor_name} risk assessment: {e}")
                    risk_scores.append(0.5)  # Default medium risk
            
            # Calculate overall risk score
            overall_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.5
            
            # Determine risk level
            if overall_risk_score >= 0.8:
                risk_level = RiskLevel.CRITICAL
            elif overall_risk_score >= 0.6:
                risk_level = RiskLevel.HIGH
            elif overall_risk_score >= 0.4:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
            
            # Determine recommended actions
            recommended_actions = []
            requires_additional_verification = False
            
            if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                recommended_actions.append("Require MFA")
                requires_additional_verification = True
                
                if risk_level == RiskLevel.CRITICAL:
                    recommended_actions.extend([
                        "Additional device verification",
                        "Admin notification",
                        "Enhanced monitoring"
                    ])
            
            if overall_risk_score > 0.7:
                recommended_actions.append("Limit session duration")
            
            if "New location" in risk_factors:
                recommended_actions.append("Location verification")
            
            if "New device" in risk_factors:
                recommended_actions.append("Device registration")
            
            return RiskAssessment(
                risk_level=risk_level,
                risk_score=overall_risk_score,
                risk_factors=risk_factors,
                recommended_actions=recommended_actions,
                requires_additional_verification=requires_additional_verification
            )
            
        except Exception as e:
            self.logger.error(f"Error in risk assessment: {e}")
            return RiskAssessment(
                risk_level=RiskLevel.HIGH,
                risk_score=0.8,
                risk_factors=["Assessment error"],
                recommended_actions=["Require MFA"],
                requires_additional_verification=True
            )
    
    async def _assess_location_risk(self, context: AuthenticationContext, user: User) -> Tuple[float, List[str]]:
        """Assess location-based risk"""
        risk_factors = []
        risk_score = 0.0
        
        try:
            # Get user's location history
            user_locations = await self._get_user_locations(user.id)
            
            # Check if this is a new location
            current_location = context.location
            if current_location and user_locations:
                is_new_location = not any(
                    self._calculate_distance(current_location, loc) < 100  # 100km threshold
                    for loc in user_locations
                )
                
                if is_new_location:
                    risk_factors.append("New location")
                    risk_score += 0.3
            
            # Check for impossible travel
            if user.last_login and current_location and user_locations:
                last_location = user_locations[-1] if user_locations else None
                if last_location:
                    time_diff = (datetime.now() - user.last_login).total_seconds() / 3600  # hours
                    distance = self._calculate_distance(current_location, last_location)
                    
                    # Check if travel speed is impossible (>1000 km/h)
                    if time_diff > 0 and distance / time_diff > 1000:
                        risk_factors.append("Impossible travel detected")
                        risk_score += 0.5
            
            # Check for high-risk countries/regions
            if current_location and current_location.get('country') in ['XX', 'YY']:  # High-risk countries
                risk_factors.append("High-risk geographic location")
                risk_score += 0.2
            
        except Exception as e:
            self.logger.error(f"Error in location risk assessment: {e}")
            risk_score = 0.3  # Default medium-low risk
        
        return min(risk_score, 1.0), risk_factors
    
    async def _assess_device_risk(self, context: AuthenticationContext, user: User) -> Tuple[float, List[str]]:
        """Assess device-based risk"""
        risk_factors = []
        risk_score = 0.0
        
        try:
            if not context.device_fingerprint:
                risk_factors.append("No device fingerprint")
                return 0.4, risk_factors
            
            # Check if device is known
            device = await self._get_device(context.device_fingerprint, user.id)
            
            if not device:
                risk_factors.append("New device")
                risk_score += 0.3
                
                # Create new device record
                await self._register_device(context, user.id)
            else:
                # Check device trust level
                if not device.is_trusted:
                    risk_factors.append("Untrusted device")
                    risk_score += 0.2
                
                # Check time since last use
                time_since_last_use = (datetime.now() - device.last_seen).days
                if time_since_last_use > 30:
                    risk_factors.append("Device not used recently")
                    risk_score += 0.1
                
                # Update device last seen
                device.last_seen = datetime.now()
                await self._update_device(device)
            
            # Analyze user agent for suspicious patterns
            if context.user_agent:
                if self._is_suspicious_user_agent(context.user_agent):
                    risk_factors.append("Suspicious user agent")
                    risk_score += 0.2
        
        except Exception as e:
            self.logger.error(f"Error in device risk assessment: {e}")
            risk_score = 0.3
        
        return min(risk_score, 1.0), risk_factors
    
    async def _assess_behavioral_risk(self, context: AuthenticationContext, user: User) -> Tuple[float, List[str]]:
        """Assess behavioral risk based on user patterns"""
        risk_factors = []
        risk_score = 0.0
        
        try:
            # Get user behavioral baseline
            baseline = self.user_baselines.get(user.id, {})
            
            if not baseline:
                # No baseline yet, create one
                await self._update_user_baseline(user.id, context)
                return 0.2, ["No behavioral baseline"]
            
            # Check login time patterns
            current_hour = context.timestamp.hour
            typical_hours = baseline.get('typical_login_hours', [])
            
            if typical_hours and current_hour not in typical_hours:
                risk_factors.append("Unusual login time")
                risk_score += 0.2
            
            # Check authentication frequency
            recent_logins = await self._get_recent_logins(user.id, hours=24)
            if len(recent_logins) > 20:  # More than 20 logins in 24 hours
                risk_factors.append("High authentication frequency")
                risk_score += 0.3
            
            # Check for concurrent sessions
            active_sessions = await self._get_active_sessions(user.id)
            if len(active_sessions) > 3:
                risk_factors.append("Multiple concurrent sessions")
                risk_score += 0.2
            
            # Update baseline with current behavior
            await self._update_user_baseline(user.id, context)
        
        except Exception as e:
            self.logger.error(f"Error in behavioral risk assessment: {e}")
            risk_score = 0.2
        
        return min(risk_score, 1.0), risk_factors
    
    async def _assess_time_risk(self, context: AuthenticationContext, user: User) -> Tuple[float, List[str]]:
        """Assess time-based risk"""
        risk_factors = []
        risk_score = 0.0
        
        try:
            current_time = context.timestamp
            current_hour = current_time.hour
            current_day = current_time.weekday()  # 0 = Monday, 6 = Sunday
            
            # Check for off-hours access
            if current_hour < 6 or current_hour > 22:  # Outside 6 AM - 10 PM
                risk_factors.append("Off-hours access")
                risk_score += 0.2
            
            # Check for weekend access (if user typically works weekdays)
            if current_day >= 5:  # Saturday or Sunday
                risk_factors.append("Weekend access")
                risk_score += 0.1
            
            # Check for holiday access (simplified - would need holiday calendar)
            # This is a placeholder for holiday checking logic
            
        except Exception as e:
            self.logger.error(f"Error in time risk assessment: {e}")
            risk_score = 0.1
        
        return min(risk_score, 1.0), risk_factors
    
    async def _assess_network_risk(self, context: AuthenticationContext, user: User) -> Tuple[float, List[str]]:
        """Assess network-based risk"""
        risk_factors = []
        risk_score = 0.0
        
        try:
            source_ip = ipaddress.ip_address(context.source_ip)
            
            # Check if IP is in trusted networks
            is_trusted_network = any(
                source_ip in ipaddress.ip_network(network)
                for network in self.network_segments['trusted']
            )
            
            if not is_trusted_network:
                risk_factors.append("Untrusted network")
                risk_score += 0.3
            
            # Check for known malicious IPs (would integrate with threat intel)
            if await self._is_malicious_ip(context.source_ip):
                risk_factors.append("Malicious IP address")
                risk_score += 0.8
            
            # Check for VPN/Proxy usage (simplified detection)
            if await self._is_vpn_or_proxy(context.source_ip):
                risk_factors.append("VPN/Proxy detected")
                risk_score += 0.2
            
            # Check for geographic IP mismatch
            # This would require IP geolocation service
            
        except Exception as e:
            self.logger.error(f"Error in network risk assessment: {e}")
            risk_score = 0.2
        
        return min(risk_score, 1.0), risk_factors
    
    async def _determine_authentication_result(self, user: User, context: AuthenticationContext, 
                                             risk_assessment: RiskAssessment) -> Tuple[AuthenticationResult, Optional[Dict]]:
        """Determine authentication result based on risk assessment"""
        try:
            # Check if user requires MFA
            if user.mfa_enabled or risk_assessment.requires_additional_verification:
                return AuthenticationResult.REQUIRES_MFA, {
                    "risk_assessment": asdict(risk_assessment),
                    "mfa_methods": ["totp", "sms"] if user.mfa_enabled else ["email"]
                }
            
            # Check risk level against policies
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                return AuthenticationResult.BLOCKED, {
                    "reason": "High risk authentication blocked",
                    "risk_assessment": asdict(risk_assessment)
                }
            
            # Check if additional verification is needed
            if risk_assessment.requires_additional_verification:
                return AuthenticationResult.REQUIRES_ADDITIONAL_VERIFICATION, {
                    "verification_methods": ["email", "device_confirmation"],
                    "risk_assessment": asdict(risk_assessment)
                }
            
            # Success with conditions based on risk level
            session_conditions = {}
            if risk_assessment.risk_level == RiskLevel.HIGH:
                session_conditions["max_duration"] = 3600  # 1 hour
                session_conditions["require_reauth"] = True
            elif risk_assessment.risk_level == RiskLevel.MEDIUM:
                session_conditions["max_duration"] = 7200  # 2 hours
            
            return AuthenticationResult.SUCCESS, {
                "session_conditions": session_conditions,
                "risk_assessment": asdict(risk_assessment)
            }
            
        except Exception as e:
            self.logger.error(f"Error determining authentication result: {e}")
            return AuthenticationResult.FAILED, None
    
    async def _create_session(self, user: User, context: AuthenticationContext, 
                            risk_assessment: RiskAssessment) -> Dict:
        """Create authenticated session"""
        try:
            # Generate session token
            session_id = self._generate_session_id()
            
            # Determine session duration based on risk
            if risk_assessment.risk_level == RiskLevel.HIGH:
                expires_in = 3600  # 1 hour
            elif risk_assessment.risk_level == RiskLevel.MEDIUM:
                expires_in = 7200  # 2 hours
            else:
                expires_in = self.settings.access_token_expire_minutes * 60
            
            # Create JWT token
            token_payload = {
                "sub": user.id,
                "username": user.username,
                "roles": user.roles,
                "session_id": session_id,
                "risk_level": risk_assessment.risk_level.value,
                "iat": int(time.time()),
                "exp": int(time.time()) + expires_in
            }
            
            access_token = jwt.encode(
                token_payload,
                self.settings.jwt_secret_key,
                algorithm=self.settings.jwt_algorithm
            )
            
            # Store session in Redis
            session_data = {
                "user_id": user.id,
                "username": user.username,
                "source_ip": context.source_ip,
                "device_fingerprint": context.device_fingerprint,
                "risk_level": risk_assessment.risk_level.value,
                "risk_score": risk_assessment.risk_score,
                "created_at": context.timestamp.isoformat(),
                "expires_at": (context.timestamp + timedelta(seconds=expires_in)).isoformat()
            }
            
            await self.redis_client.setex(
                f"session:{session_id}",
                expires_in,
                json.dumps(session_data)
            )
            
            # Store in active sessions
            self.active_sessions[session_id] = session_data
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "session_id": session_id,
                "risk_level": risk_assessment.risk_level.value
            }
            
        except Exception as e:
            self.logger.error(f"Error creating session: {e}")
            raise
    
    async def validate_session(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Validate session token"""
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )
            
            session_id = payload.get("session_id")
            if not session_id:
                return False, None
            
            # Check if session exists in Redis
            session_data = await self.redis_client.get(f"session:{session_id}")
            if not session_data:
                return False, None
            
            session_info = json.loads(session_data)
            
            # Additional validation based on risk level
            risk_level = session_info.get("risk_level")
            if risk_level == "HIGH":
                # High-risk sessions require more frequent validation
                created_at = datetime.fromisoformat(session_info["created_at"])
                if (datetime.now() - created_at).total_seconds() > 1800:  # 30 minutes
                    await self._invalidate_session(session_id)
                    return False, None
            
            return True, {
                "user_id": payload["sub"],
                "username": payload["username"],
                "roles": payload["roles"],
                "session_id": session_id,
                "risk_level": risk_level
            }
            
        except jwt.ExpiredSignatureError:
            return False, {"error": "Token expired"}
        except jwt.InvalidTokenError:
            return False, {"error": "Invalid token"}
        except Exception as e:
            self.logger.error(f"Error validating session: {e}")
            return False, None
    
    async def check_access_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check if user has permission to access resource"""
        try:
            user = await self._get_user_by_id(user_id)
            if not user or not user.is_active:
                return False
            
            # Check access policies
            for policy in self.access_policies.values():
                if not policy.is_active:
                    continue
                
                # Check if resource matches policy pattern
                if self._resource_matches_pattern(resource, policy.resource_pattern):
                    # Check role-based access
                    if not any(role in policy.allowed_roles for role in user.roles):
                        continue
                    
                    # Additional checks would go here (IP, time, etc.)
                    return True
            
            # Check default permissions based on roles
            if "admin" in user.roles:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking access permission: {e}")
            return False
    
    async def get_network_segment(self, ip_address: str) -> str:
        """Determine network segment for IP address"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for segment_name, networks in self.network_segments.items():
                for network in networks:
                    if ip in ipaddress.ip_network(network):
                        return segment_name
            
            return "external"
            
        except Exception as e:
            self.logger.error(f"Error determining network segment: {e}")
            return "unknown"
    
    # Helper methods
    async def _get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        return next((user for user in self.users.values() if user.username == username), None)
    
    async def _get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    async def _update_user(self, user: User):
        """Update user information"""
        self.users[user.id] = user
    
    async def _get_device(self, device_fingerprint: str, user_id: str) -> Optional[Device]:
        """Get device by fingerprint and user ID"""
        return next(
            (device for device in self.devices.values() 
             if device.device_fingerprint == device_fingerprint and device.user_id == user_id),
            None
        )
    
    async def _register_device(self, context: AuthenticationContext, user_id: str):
        """Register new device"""
        device_id = f"device_{int(time.time())}"
        device = Device(
            id=device_id,
            user_id=user_id,
            device_fingerprint=context.device_fingerprint,
            device_type="unknown",
            os_info="unknown",
            browser_info=context.user_agent,
            is_trusted=False,
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        self.devices[device_id] = device
    
    async def _update_device(self, device: Device):
        """Update device information"""
        self.devices[device.id] = device
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return hashlib.sha256(f"{time.time()}{hash(time.time())}".encode()).hexdigest()
    
    def _calculate_distance(self, loc1: Dict, loc2: Dict) -> float:
        """Calculate distance between two locations (simplified)"""
        # This is a simplified distance calculation
        # In production, use proper geospatial calculations
        lat1, lon1 = loc1.get('lat', 0), loc1.get('lon', 0)
        lat2, lon2 = loc2.get('lat', 0), loc2.get('lon', 0)
        
        # Rough distance calculation (not accurate, just for demo)
        return abs(lat1 - lat2) + abs(lon1 - lon2) * 111  # Approximate km
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'curl', 'wget', 'python-requests'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)
    
    async def _is_malicious_ip(self, ip_address: str) -> bool:
        """Check if IP is known to be malicious"""
        # This would integrate with threat intelligence feeds
        # For now, return False (placeholder)
        return False
    
    async def _is_vpn_or_proxy(self, ip_address: str) -> bool:
        """Check if IP is VPN or proxy"""
        # This would integrate with VPN/proxy detection services
        # For now, return False (placeholder)
        return False
    
    def _resource_matches_pattern(self, resource: str, pattern: str) -> bool:
        """Check if resource matches access pattern"""
        # Simple pattern matching (could be enhanced with regex)
        if pattern == "*":
            return True
        
        return resource.startswith(pattern.rstrip("*"))
    
    async def _get_user_locations(self, user_id: str) -> List[Dict]:
        """Get user's location history"""
        # Placeholder - would retrieve from database
        return []
    
    async def _get_recent_logins(self, user_id: str, hours: int = 24) -> List[Dict]:
        """Get recent login attempts"""
        # Placeholder - would retrieve from database
        return []
    
    async def _get_active_sessions(self, user_id: str) -> List[Dict]:
        """Get active sessions for user"""
        return [
            session for session in self.active_sessions.values()
            if session.get("user_id") == user_id
        ]
    
    async def _update_user_baseline(self, user_id: str, context: AuthenticationContext):
        """Update user behavioral baseline"""
        if user_id not in self.user_baselines:
            self.user_baselines[user_id] = {
                'typical_login_hours': [],
                'typical_locations': [],
                'typical_devices': []
            }
        
        baseline = self.user_baselines[user_id]
        
        # Update typical login hours
        current_hour = context.timestamp.hour
        if current_hour not in baseline['typical_login_hours']:
            baseline['typical_login_hours'].append(current_hour)
        
        # Keep only recent patterns (last 30 entries)
        if len(baseline['typical_login_hours']) > 30:
            baseline['typical_login_hours'] = baseline['typical_login_hours'][-30:]
    
    async def _log_authentication_attempt(self, context: AuthenticationContext, 
                                        success: bool, details: str):
        """Log authentication attempt"""
        log_entry = {
            "timestamp": context.timestamp.isoformat(),
            "username": context.username,
            "source_ip": context.source_ip,
            "success": success,
            "details": details,
            "user_agent": context.user_agent
        }
        
        # Store in Redis for quick access
        await self.redis_client.lpush("auth_logs", json.dumps(log_entry))
        await self.redis_client.ltrim("auth_logs", 0, 10000)  # Keep last 10k logs
        
        # Log to application logger
        if success:
            self.logger.info(f"Authentication success: {context.username} from {context.source_ip}")
        else:
            self.logger.warning(f"Authentication failed: {context.username} from {context.source_ip} - {details}")
    
    async def _invalidate_session(self, session_id: str):
        """Invalidate session"""
        try:
            await self.redis_client.delete(f"session:{session_id}")
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
        except Exception as e:
            self.logger.error(f"Error invalidating session: {e}")
    
    async def _load_default_policies(self):
        """Load default access policies"""
        # Admin policy
        admin_policy = AccessPolicy(
            id="admin_policy",
            name="Administrator Access",
            resource_pattern="*",
            allowed_roles=["admin"],
            allowed_ips=["*"],
            allowed_times={"all_day": True},
            max_risk_level=RiskLevel.HIGH,
            requires_mfa=True,
            is_active=True
        )
        
        # User policy
        user_policy = AccessPolicy(
            id="user_policy",
            name="Standard User Access",
            resource_pattern="/api/user/*",
            allowed_roles=["user", "admin"],
            allowed_ips=["*"],
            allowed_times={"business_hours": True},
            max_risk_level=RiskLevel.MEDIUM,
            requires_mfa=False,
            is_active=True
        )
        
        self.access_policies[admin_policy.id] = admin_policy
        self.access_policies[user_policy.id] = user_policy
    
    async def _create_default_admin(self):
        """Create default admin user"""
        admin_id = "admin_001"
        if admin_id not in self.users:
            admin_user = User(
                id=admin_id,
                username="admin",
                email="admin@waf.local",
                password_hash=self.pwd_context.hash("admin123"),  # Change in production!
                roles=["admin"],
                is_active=True,
                created_at=datetime.now(),
                mfa_enabled=True
            )
            self.users[admin_id] = admin_user
            self.logger.info("Created default admin user (username: admin, password: admin123)")