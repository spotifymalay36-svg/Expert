"""
Advanced Anomaly Detection for Zero-Day and Unknown Threats
Uses unsupervised learning and statistical methods
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import pickle
import os
from datetime import datetime, timedelta
from collections import deque, defaultdict
import asyncio

from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.covariance import EllipticEnvelope
import scipy.stats as stats

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class AnomalyResult:
    """Anomaly detection result"""
    is_anomaly: bool
    anomaly_type: str
    description: str
    anomaly_score: float
    severity: ThreatLevel
    method_used: str
    features_analyzed: List[str] = None

@dataclass
class NetworkFlow:
    """Network flow representation"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    packets_sent: int
    duration: float
    timestamp: datetime

class AnomalyDetector:
    """Advanced anomaly detection system"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Detection models
        self.models = {}
        self.scalers = {}
        
        # Baseline statistics
        self.baselines = {
            'traffic_volume': deque(maxlen=1000),
            'packet_sizes': deque(maxlen=1000),
            'connection_rates': deque(maxlen=1000),
            'protocol_distribution': defaultdict(int),
            'port_usage': defaultdict(int)
        }
        
        # Flow tracking
        self.active_flows = {}
        self.flow_history = deque(maxlen=10000)
        
        # Time series data for behavioral analysis
        self.time_series_data = {
            'hourly_traffic': defaultdict(list),
            'daily_patterns': defaultdict(list),
            'user_behavior': defaultdict(list)
        }
        
        # Anomaly detection methods
        self.detection_methods = {
            'statistical': self._statistical_anomaly_detection,
            'isolation_forest': self._isolation_forest_detection,
            'clustering': self._clustering_based_detection,
            'behavioral': self._behavioral_anomaly_detection,
            'time_series': self._time_series_anomaly_detection
        }
        
        self.logger.info("Anomaly Detector initialized")
    
    async def initialize(self):
        """Initialize anomaly detection models"""
        try:
            self.logger.info("Initializing anomaly detection models...")
            
            # Create models directory
            os.makedirs(self.settings.model_path, exist_ok=True)
            
            # Load or create models
            await self._load_or_create_models()
            
            # Initialize baseline statistics
            await self._initialize_baselines()
            
            self.logger.info("Anomaly detection models initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize anomaly detector: {e}")
            await self._create_default_models()
    
    async def _load_or_create_models(self):
        """Load existing models or create new ones"""
        model_configs = {
            'isolation_forest': {
                'file': 'anomaly_isolation_forest.pkl',
                'class': IsolationForest,
                'params': {'contamination': 0.1, 'random_state': 42, 'n_jobs': -1}
            },
            'elliptic_envelope': {
                'file': 'anomaly_elliptic_envelope.pkl',
                'class': EllipticEnvelope,
                'params': {'contamination': 0.1, 'random_state': 42}
            },
            'dbscan': {
                'file': 'anomaly_dbscan.pkl',
                'class': DBSCAN,
                'params': {'eps': 0.5, 'min_samples': 5}
            }
        }
        
        for model_name, config in model_configs.items():
            model_path = os.path.join(self.settings.model_path, config['file'])
            
            if os.path.exists(model_path):
                try:
                    with open(model_path, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                    self.logger.info(f"Loaded anomaly model: {model_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load model {model_name}: {e}")
                    self.models[model_name] = config['class'](**config['params'])
            else:
                self.models[model_name] = config['class'](**config['params'])
                self.logger.info(f"Created new anomaly model: {model_name}")
        
        # Load scalers
        scaler_path = os.path.join(self.settings.model_path, 'anomaly_scaler.pkl')
        if os.path.exists(scaler_path):
            try:
                with open(scaler_path, 'rb') as f:
                    self.scalers['main'] = pickle.load(f)
                self.logger.info("Loaded anomaly scaler")
            except Exception as e:
                self.logger.warning(f"Failed to load scaler: {e}")
                self.scalers['main'] = StandardScaler()
        else:
            self.scalers['main'] = StandardScaler()
    
    async def _create_default_models(self):
        """Create default models if loading fails"""
        self.models = {
            'isolation_forest': IsolationForest(contamination=0.1, random_state=42),
            'elliptic_envelope': EllipticEnvelope(contamination=0.1, random_state=42),
            'dbscan': DBSCAN(eps=0.5, min_samples=5)
        }
        self.scalers['main'] = StandardScaler()
    
    async def _initialize_baselines(self):
        """Initialize baseline statistics from historical data"""
        try:
            baseline_path = os.path.join(self.settings.model_path, 'baselines.pkl')
            if os.path.exists(baseline_path):
                with open(baseline_path, 'rb') as f:
                    saved_baselines = pickle.load(f)
                    for key, value in saved_baselines.items():
                        if key in self.baselines:
                            self.baselines[key] = value
                self.logger.info("Loaded baseline statistics")
            else:
                self.logger.info("No baseline statistics found, will build from incoming data")
        except Exception as e:
            self.logger.error(f"Error loading baselines: {e}")
    
    async def detect_anomaly(self, packet_info) -> AnomalyResult:
        """Main anomaly detection method"""
        try:
            # Update baselines with current packet
            await self._update_baselines(packet_info)
            
            # Extract features for anomaly detection
            features = self._extract_anomaly_features(packet_info)
            
            # Run different detection methods
            results = []
            
            for method_name, method_func in self.detection_methods.items():
                try:
                    result = await method_func(packet_info, features)
                    if result and result.is_anomaly:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error in {method_name} detection: {e}")
            
            # Combine results
            if results:
                return self._combine_anomaly_results(results)
            
            return AnomalyResult(
                is_anomaly=False,
                anomaly_type="NORMAL",
                description="No anomalies detected",
                anomaly_score=0.0,
                severity=ThreatLevel.LOW,
                method_used="ensemble"
            )
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return AnomalyResult(
                is_anomaly=False,
                anomaly_type="ERROR",
                description=f"Anomaly detection error: {e}",
                anomaly_score=0.0,
                severity=ThreatLevel.LOW,
                method_used="error"
            )
    
    async def _update_baselines(self, packet_info):
        """Update baseline statistics with current packet"""
        try:
            # Update traffic volume
            self.baselines['traffic_volume'].append(packet_info.size)
            
            # Update packet sizes
            self.baselines['packet_sizes'].append(packet_info.size)
            
            # Update protocol distribution
            self.baselines['protocol_distribution'][packet_info.protocol] += 1
            
            # Update port usage
            self.baselines['port_usage'][packet_info.dst_port] += 1
            
            # Update connection rates (simplified)
            current_time = datetime.now()
            connection_key = f"{packet_info.src_ip}:{packet_info.dst_ip}"
            
            # Track active flows
            flow_key = f"{packet_info.src_ip}:{packet_info.src_port}->{packet_info.dst_ip}:{packet_info.dst_port}"
            if flow_key not in self.active_flows:
                self.active_flows[flow_key] = NetworkFlow(
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol,
                    bytes_sent=packet_info.size,
                    packets_sent=1,
                    duration=0.0,
                    timestamp=current_time
                )
            else:
                flow = self.active_flows[flow_key]
                flow.bytes_sent += packet_info.size
                flow.packets_sent += 1
                flow.duration = (current_time - flow.timestamp).total_seconds()
            
        except Exception as e:
            self.logger.error(f"Error updating baselines: {e}")
    
    def _extract_anomaly_features(self, packet_info) -> np.ndarray:
        """Extract features for anomaly detection"""
        try:
            features = []
            
            # Basic packet features
            features.extend([
                packet_info.size,
                packet_info.src_port,
                packet_info.dst_port,
                len(packet_info.payload) if packet_info.payload else 0
            ])
            
            # Statistical features based on baselines
            if self.baselines['packet_sizes']:
                avg_size = np.mean(self.baselines['packet_sizes'])
                std_size = np.std(self.baselines['packet_sizes'])
                size_zscore = (packet_info.size - avg_size) / max(std_size, 1)
                features.append(size_zscore)
            else:
                features.append(0.0)
            
            # Protocol frequency features
            total_packets = sum(self.baselines['protocol_distribution'].values())
            if total_packets > 0:
                protocol_freq = self.baselines['protocol_distribution'][packet_info.protocol] / total_packets
                features.append(protocol_freq)
            else:
                features.append(0.0)
            
            # Port usage features
            total_port_usage = sum(self.baselines['port_usage'].values())
            if total_port_usage > 0:
                port_freq = self.baselines['port_usage'][packet_info.dst_port] / total_port_usage
                features.append(port_freq)
            else:
                features.append(0.0)
            
            # Time-based features
            current_hour = datetime.now().hour
            features.extend([
                current_hour / 24.0,  # Normalized hour
                1 if 9 <= current_hour <= 17 else 0,  # Business hours
                1 if current_hour >= 22 or current_hour <= 6 else 0  # Night hours
            ])
            
            # Flow-based features
            flow_key = f"{packet_info.src_ip}:{packet_info.src_port}->{packet_info.dst_ip}:{packet_info.dst_port}"
            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                features.extend([
                    flow.bytes_sent,
                    flow.packets_sent,
                    flow.duration,
                    flow.bytes_sent / max(flow.packets_sent, 1)  # Avg packet size in flow
                ])
            else:
                features.extend([0, 0, 0, 0])
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            self.logger.error(f"Error extracting anomaly features: {e}")
            return np.array([0] * 15).reshape(1, -1)
    
    async def _statistical_anomaly_detection(self, packet_info, features) -> Optional[AnomalyResult]:
        """Statistical anomaly detection using Z-scores and percentiles"""
        try:
            anomalies = []
            
            # Packet size anomaly
            if self.baselines['packet_sizes'] and len(self.baselines['packet_sizes']) > 10:
                sizes = list(self.baselines['packet_sizes'])
                z_score = stats.zscore([packet_info.size], sizes)[0]
                
                if abs(z_score) > 3:  # 3-sigma rule
                    anomalies.append(f"Unusual packet size (z-score: {z_score:.2f})")
            
            # Traffic volume anomaly
            if self.baselines['traffic_volume'] and len(self.baselines['traffic_volume']) > 10:
                volumes = list(self.baselines['traffic_volume'])
                percentile_95 = np.percentile(volumes, 95)
                percentile_5 = np.percentile(volumes, 5)
                
                if packet_info.size > percentile_95:
                    anomalies.append(f"High traffic volume (>{percentile_95:.0f} bytes)")
                elif packet_info.size < percentile_5:
                    anomalies.append(f"Low traffic volume (<{percentile_5:.0f} bytes)")
            
            # Protocol distribution anomaly
            total_packets = sum(self.baselines['protocol_distribution'].values())
            if total_packets > 100:  # Need sufficient data
                protocol_freq = self.baselines['protocol_distribution'][packet_info.protocol] / total_packets
                
                if protocol_freq < 0.01:  # Less than 1% of traffic
                    anomalies.append(f"Rare protocol usage: {packet_info.protocol}")
            
            # Port usage anomaly
            total_port_usage = sum(self.baselines['port_usage'].values())
            if total_port_usage > 100:
                port_freq = self.baselines['port_usage'][packet_info.dst_port] / total_port_usage
                
                if port_freq < 0.005 and packet_info.dst_port > 1024:  # Rare high port
                    anomalies.append(f"Rare port usage: {packet_info.dst_port}")
            
            if anomalies:
                anomaly_score = min(1.0, len(anomalies) * 0.3)
                severity = ThreatLevel.MEDIUM if anomaly_score > 0.6 else ThreatLevel.LOW
                
                return AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="STATISTICAL",
                    description="; ".join(anomalies),
                    anomaly_score=anomaly_score,
                    severity=severity,
                    method_used="statistical"
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in statistical anomaly detection: {e}")
            return None
    
    async def _isolation_forest_detection(self, packet_info, features) -> Optional[AnomalyResult]:
        """Isolation Forest based anomaly detection"""
        try:
            if 'isolation_forest' not in self.models:
                return None
            
            model = self.models['isolation_forest']
            
            # Scale features
            if 'main' in self.scalers and hasattr(self.scalers['main'], 'transform'):
                try:
                    features_scaled = self.scalers['main'].transform(features)
                except:
                    # Scaler not fitted yet
                    return None
            else:
                features_scaled = features
            
            # Make prediction
            try:
                prediction = model.predict(features_scaled)
                anomaly_score = model.decision_function(features_scaled)[0]
                
                if prediction[0] == -1:  # Anomaly detected
                    severity = ThreatLevel.HIGH if abs(anomaly_score) > 0.5 else ThreatLevel.MEDIUM
                    
                    return AnomalyResult(
                        is_anomaly=True,
                        anomaly_type="ISOLATION_FOREST",
                        description=f"Isolation Forest detected anomaly (score: {anomaly_score:.3f})",
                        anomaly_score=abs(anomaly_score),
                        severity=severity,
                        method_used="isolation_forest"
                    )
            except:
                # Model not trained yet
                return None
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in Isolation Forest detection: {e}")
            return None
    
    async def _clustering_based_detection(self, packet_info, features) -> Optional[AnomalyResult]:
        """DBSCAN clustering based anomaly detection"""
        try:
            # This method requires a batch of recent samples
            # For real-time detection, we'll use a simplified approach
            
            # Collect recent features for clustering
            if not hasattr(self, 'recent_features'):
                self.recent_features = deque(maxlen=100)
            
            self.recent_features.append(features.flatten())
            
            if len(self.recent_features) < 20:  # Need minimum samples
                return None
            
            # Perform clustering on recent samples
            recent_array = np.array(list(self.recent_features))
            
            # Scale features
            scaler = StandardScaler()
            recent_scaled = scaler.fit_transform(recent_array)
            
            # Apply DBSCAN
            dbscan = DBSCAN(eps=0.5, min_samples=3)
            labels = dbscan.fit_predict(recent_scaled)
            
            # Check if current sample is an outlier (label = -1)
            current_label = labels[-1]
            
            if current_label == -1:
                # Calculate distance to nearest cluster
                cluster_centers = []
                unique_labels = set(labels[labels != -1])
                
                for label in unique_labels:
                    cluster_points = recent_scaled[labels == label]
                    if len(cluster_points) > 0:
                        center = np.mean(cluster_points, axis=0)
                        cluster_centers.append(center)
                
                if cluster_centers:
                    current_point = recent_scaled[-1]
                    distances = [np.linalg.norm(current_point - center) for center in cluster_centers]
                    min_distance = min(distances)
                    
                    if min_distance > 1.0:  # Threshold for anomaly
                        return AnomalyResult(
                            is_anomaly=True,
                            anomaly_type="CLUSTERING",
                            description=f"DBSCAN detected outlier (distance: {min_distance:.3f})",
                            anomaly_score=min(1.0, min_distance / 3.0),
                            severity=ThreatLevel.MEDIUM,
                            method_used="dbscan"
                        )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in clustering detection: {e}")
            return None
    
    async def _behavioral_anomaly_detection(self, packet_info, features) -> Optional[AnomalyResult]:
        """Behavioral anomaly detection based on user/IP patterns"""
        try:
            anomalies = []
            current_time = datetime.now()
            
            # Track per-IP behavior
            if not hasattr(self, 'ip_behavior'):
                self.ip_behavior = defaultdict(lambda: {
                    'packet_count': 0,
                    'byte_count': 0,
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'ports_accessed': set(),
                    'protocols_used': set()
                })
            
            ip_stats = self.ip_behavior[packet_info.src_ip]
            ip_stats['packet_count'] += 1
            ip_stats['byte_count'] += packet_info.size
            ip_stats['last_seen'] = current_time
            ip_stats['ports_accessed'].add(packet_info.dst_port)
            ip_stats['protocols_used'].add(packet_info.protocol)
            
            # Check for scanning behavior
            if len(ip_stats['ports_accessed']) > 50:  # Port scanning
                anomalies.append("Port scanning detected")
            
            # Check for high connection rate
            time_window = (current_time - ip_stats['first_seen']).total_seconds()
            if time_window > 0:
                connection_rate = ip_stats['packet_count'] / time_window
                if connection_rate > 100:  # More than 100 packets per second
                    anomalies.append(f"High connection rate: {connection_rate:.1f} pps")
            
            # Check for unusual data volume
            if ip_stats['byte_count'] > 10 * 1024 * 1024:  # More than 10MB
                anomalies.append(f"High data volume: {ip_stats['byte_count'] / (1024*1024):.1f} MB")
            
            # Check for protocol diversity (potential tunneling)
            if len(ip_stats['protocols_used']) > 5:
                anomalies.append("Multiple protocols used")
            
            if anomalies:
                anomaly_score = min(1.0, len(anomalies) * 0.25)
                severity = ThreatLevel.HIGH if anomaly_score > 0.7 else ThreatLevel.MEDIUM
                
                return AnomalyResult(
                    is_anomaly=True,
                    anomaly_type="BEHAVIORAL",
                    description="; ".join(anomalies),
                    anomaly_score=anomaly_score,
                    severity=severity,
                    method_used="behavioral"
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in behavioral anomaly detection: {e}")
            return None
    
    async def _time_series_anomaly_detection(self, packet_info, features) -> Optional[AnomalyResult]:
        """Time series based anomaly detection"""
        try:
            current_time = datetime.now()
            current_hour = current_time.hour
            
            # Track hourly traffic patterns
            hour_key = f"{current_hour}"
            if hour_key not in self.time_series_data['hourly_traffic']:
                self.time_series_data['hourly_traffic'][hour_key] = deque(maxlen=100)
            
            self.time_series_data['hourly_traffic'][hour_key].append(packet_info.size)
            
            # Check for unusual traffic during off-hours
            if current_hour >= 22 or current_hour <= 6:  # Night hours
                if packet_info.size > 1024:  # Large packets during night
                    return AnomalyResult(
                        is_anomaly=True,
                        anomaly_type="TIME_SERIES",
                        description=f"Large packet during off-hours: {packet_info.size} bytes at {current_hour}:00",
                        anomaly_score=0.6,
                        severity=ThreatLevel.MEDIUM,
                        method_used="time_series"
                    )
            
            # Check for traffic spikes
            if len(self.time_series_data['hourly_traffic'][hour_key]) > 10:
                recent_traffic = list(self.time_series_data['hourly_traffic'][hour_key])
                avg_traffic = np.mean(recent_traffic[:-1])  # Exclude current packet
                std_traffic = np.std(recent_traffic[:-1])
                
                if std_traffic > 0:
                    z_score = (packet_info.size - avg_traffic) / std_traffic
                    if abs(z_score) > 2.5:  # Traffic spike
                        return AnomalyResult(
                            is_anomaly=True,
                            anomaly_type="TIME_SERIES",
                            description=f"Traffic spike detected (z-score: {z_score:.2f})",
                            anomaly_score=min(1.0, abs(z_score) / 5.0),
                            severity=ThreatLevel.MEDIUM,
                            method_used="time_series"
                        )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in time series anomaly detection: {e}")
            return None
    
    def _combine_anomaly_results(self, results: List[AnomalyResult]) -> AnomalyResult:
        """Combine multiple anomaly detection results"""
        try:
            # Calculate weighted anomaly score
            total_score = sum(result.anomaly_score for result in results)
            avg_score = total_score / len(results)
            
            # Determine overall severity
            max_severity = max(results, key=lambda x: self._severity_to_int(x.severity)).severity
            
            # Combine descriptions
            descriptions = [f"{result.method_used}: {result.description}" for result in results]
            combined_description = "; ".join(descriptions)
            
            # Combine anomaly types
            anomaly_types = list(set(result.anomaly_type for result in results))
            combined_type = "+".join(anomaly_types)
            
            return AnomalyResult(
                is_anomaly=True,
                anomaly_type=combined_type,
                description=combined_description,
                anomaly_score=min(1.0, avg_score * 1.2),  # Boost combined score
                severity=max_severity,
                method_used="ensemble",
                features_analyzed=[result.method_used for result in results]
            )
            
        except Exception as e:
            self.logger.error(f"Error combining anomaly results: {e}")
            return results[0] if results else AnomalyResult(
                is_anomaly=False, anomaly_type="ERROR", description="Combination error",
                anomaly_score=0.0, severity=ThreatLevel.LOW, method_used="error"
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
    
    async def train_anomaly_models(self, training_data: List[np.ndarray]) -> bool:
        """Train anomaly detection models with normal traffic data"""
        try:
            if len(training_data) < 50:
                self.logger.warning("Insufficient training data for anomaly models")
                return False
            
            self.logger.info("Training anomaly detection models...")
            
            # Prepare data
            X = np.vstack(training_data)
            
            # Fit scaler
            self.scalers['main'].fit(X)
            X_scaled = self.scalers['main'].transform(X)
            
            # Train Isolation Forest
            if 'isolation_forest' in self.models:
                self.models['isolation_forest'].fit(X_scaled)
                self.logger.info("Isolation Forest trained")
            
            # Train Elliptic Envelope
            if 'elliptic_envelope' in self.models:
                self.models['elliptic_envelope'].fit(X_scaled)
                self.logger.info("Elliptic Envelope trained")
            
            # Save models
            await self._save_anomaly_models()
            
            self.logger.info("Anomaly detection models training completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training anomaly models: {e}")
            return False
    
    async def _save_anomaly_models(self):
        """Save anomaly detection models"""
        try:
            # Save models
            for model_name, model in self.models.items():
                if hasattr(model, 'fit'):  # Scikit-learn model
                    model_path = os.path.join(self.settings.model_path, f'anomaly_{model_name}.pkl')
                    with open(model_path, 'wb') as f:
                        pickle.dump(model, f)
            
            # Save scaler
            scaler_path = os.path.join(self.settings.model_path, 'anomaly_scaler.pkl')
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scalers['main'], f)
            
            # Save baselines
            baseline_path = os.path.join(self.settings.model_path, 'baselines.pkl')
            with open(baseline_path, 'wb') as f:
                # Convert deques to lists for serialization
                serializable_baselines = {}
                for key, value in self.baselines.items():
                    if isinstance(value, deque):
                        serializable_baselines[key] = list(value)
                    else:
                        serializable_baselines[key] = value
                pickle.dump(serializable_baselines, f)
            
            self.logger.info("Anomaly detection models saved")
            
        except Exception as e:
            self.logger.error(f"Error saving anomaly models: {e}")
    
    async def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        try:
            stats = {
                'baseline_samples': {
                    'traffic_volume': len(self.baselines['traffic_volume']),
                    'packet_sizes': len(self.baselines['packet_sizes']),
                    'connection_rates': len(self.baselines['connection_rates'])
                },
                'protocol_distribution': dict(self.baselines['protocol_distribution']),
                'port_usage': dict(list(self.baselines['port_usage'].items())[:10]),  # Top 10 ports
                'active_flows': len(self.active_flows),
                'models_trained': {
                    model_name: hasattr(model, 'fit') and 
                    (hasattr(model, 'tree_') or hasattr(model, 'support_') or hasattr(model, 'core_sample_indices_'))
                    for model_name, model in self.models.items()
                }
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting anomaly statistics: {e}")
            return {}