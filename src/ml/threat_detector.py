"""
AI/ML-based Threat Detection using Deep Learning
Implements CNN and transformer models for advanced threat detection
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import pickle
import asyncio
from datetime import datetime
import hashlib

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class MLThreatResult:
    """ML threat detection result"""
    is_threat: bool
    threat_type: str
    description: str
    severity: ThreatLevel
    confidence: float
    model_name: str
    features_used: List[str] = None

class PayloadCNN(nn.Module):
    """Convolutional Neural Network for payload analysis"""
    
    def __init__(self, vocab_size=256, embedding_dim=128, num_classes=5):
        super(PayloadCNN, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        
        # Multiple CNN layers with different kernel sizes
        self.conv1 = nn.Conv1d(embedding_dim, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(embedding_dim, 64, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(embedding_dim, 64, kernel_size=7, padding=3)
        
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.dropout = nn.Dropout(0.5)
        
        # Fully connected layers
        self.fc1 = nn.Linear(64 * 3, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, num_classes)
        
    def forward(self, x):
        # Embedding
        x = self.embedding(x)  # (batch_size, seq_len, embedding_dim)
        x = x.transpose(1, 2)  # (batch_size, embedding_dim, seq_len)
        
        # Parallel convolutions
        conv1_out = F.relu(self.conv1(x))
        conv2_out = F.relu(self.conv2(x))
        conv3_out = F.relu(self.conv3(x))
        
        # Global max pooling
        pool1 = self.pool(conv1_out).squeeze(-1)
        pool2 = self.pool(conv2_out).squeeze(-1)
        pool3 = self.pool(conv3_out).squeeze(-1)
        
        # Concatenate features
        features = torch.cat([pool1, pool2, pool3], dim=1)
        features = self.dropout(features)
        
        # Classification
        x = F.relu(self.fc1(features))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        
        return x

class ThreatDetector:
    """Advanced ML-based threat detector"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Model storage
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        
        # Feature extractors
        self.feature_extractors = {
            'statistical': self._extract_statistical_features,
            'ngram': self._extract_ngram_features,
            'entropy': self._extract_entropy_features,
            'protocol': self._extract_protocol_features
        }
        
        # Threat categories
        self.threat_categories = [
            'BENIGN',
            'SQL_INJECTION',
            'XSS',
            'COMMAND_INJECTION',
            'MALWARE'
        ]
        
        self.logger.info("Threat Detector initialized")
    
    async def initialize(self):
        """Initialize ML models"""
        try:
            self.logger.info("Loading ML models...")
            
            # Create models directory if it doesn't exist
            os.makedirs(self.settings.model_path, exist_ok=True)
            
            # Load or create models
            await self._load_or_create_models()
            
            # Load or create feature processors
            await self._load_or_create_processors()
            
            self.logger.info("ML models loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
            # Create basic models if loading fails
            await self._create_basic_models()
    
    async def _load_or_create_models(self):
        """Load existing models or create new ones"""
        model_files = {
            'cnn_payload': 'cnn_payload_model.pth',
            'rf_classifier': 'rf_classifier.pkl',
            'isolation_forest': 'isolation_forest.pkl'
        }
        
        for model_name, filename in model_files.items():
            model_path = os.path.join(self.settings.model_path, filename)
            
            if os.path.exists(model_path):
                try:
                    if model_name == 'cnn_payload':
                        # Load PyTorch model
                        model = PayloadCNN()
                        model.load_state_dict(torch.load(model_path, map_location='cpu'))
                        model.eval()
                        self.models[model_name] = model
                    else:
                        # Load scikit-learn model
                        with open(model_path, 'rb') as f:
                            self.models[model_name] = pickle.load(f)
                    
                    self.logger.info(f"Loaded model: {model_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load model {model_name}: {e}")
                    await self._create_model(model_name)
            else:
                await self._create_model(model_name)
    
    async def _create_model(self, model_name: str):
        """Create a new model"""
        try:
            if model_name == 'cnn_payload':
                model = PayloadCNN()
                self.models[model_name] = model
                
            elif model_name == 'rf_classifier':
                model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                )
                self.models[model_name] = model
                
            elif model_name == 'isolation_forest':
                model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_jobs=-1
                )
                self.models[model_name] = model
            
            self.logger.info(f"Created new model: {model_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to create model {model_name}: {e}")
    
    async def _load_or_create_processors(self):
        """Load or create feature processors"""
        processor_files = {
            'scaler': 'feature_scaler.pkl',
            'label_encoder': 'label_encoder.pkl'
        }
        
        for processor_name, filename in processor_files.items():
            processor_path = os.path.join(self.settings.model_path, filename)
            
            if os.path.exists(processor_path):
                try:
                    with open(processor_path, 'rb') as f:
                        if processor_name == 'scaler':
                            self.scalers['main'] = pickle.load(f)
                        elif processor_name == 'label_encoder':
                            self.encoders['main'] = pickle.load(f)
                    
                    self.logger.info(f"Loaded processor: {processor_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load processor {processor_name}: {e}")
                    await self._create_processor(processor_name)
            else:
                await self._create_processor(processor_name)
    
    async def _create_processor(self, processor_name: str):
        """Create new feature processor"""
        try:
            if processor_name == 'scaler':
                self.scalers['main'] = StandardScaler()
            elif processor_name == 'label_encoder':
                encoder = LabelEncoder()
                encoder.fit(self.threat_categories)
                self.encoders['main'] = encoder
            
            self.logger.info(f"Created new processor: {processor_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to create processor {processor_name}: {e}")
    
    async def _create_basic_models(self):
        """Create basic models if initialization fails"""
        self.logger.info("Creating basic fallback models...")
        
        # Simple rule-based classifier as fallback
        self.models['fallback'] = {
            'type': 'rule_based',
            'rules': {
                'sql_keywords': ['select', 'union', 'insert', 'update', 'delete', 'drop'],
                'xss_keywords': ['<script', 'javascript:', 'onerror', 'onload'],
                'cmd_keywords': ['system(', 'exec(', 'eval(', 'shell_exec(']
            }
        }
    
    async def analyze_packet(self, packet_info) -> MLThreatResult:
        """Analyze packet using ML models"""
        try:
            # Extract features
            features = await self._extract_all_features(packet_info)
            
            # Get predictions from different models
            predictions = []
            
            # CNN-based payload analysis
            if 'cnn_payload' in self.models:
                cnn_result = await self._analyze_with_cnn(packet_info.payload)
                if cnn_result:
                    predictions.append(cnn_result)
            
            # Random Forest classification
            if 'rf_classifier' in self.models and features:
                rf_result = await self._analyze_with_rf(features)
                if rf_result:
                    predictions.append(rf_result)
            
            # Isolation Forest anomaly detection
            if 'isolation_forest' in self.models and features:
                iso_result = await self._analyze_with_isolation_forest(features)
                if iso_result:
                    predictions.append(iso_result)
            
            # Ensemble prediction
            if predictions:
                return self._ensemble_prediction(predictions, packet_info)
            
            # Fallback to rule-based analysis
            return await self._fallback_analysis(packet_info)
            
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            return MLThreatResult(
                is_threat=False,
                threat_type="ERROR",
                description=f"ML analysis error: {e}",
                severity=ThreatLevel.LOW,
                confidence=0.0,
                model_name="error"
            )
    
    async def _extract_all_features(self, packet_info) -> Optional[np.ndarray]:
        """Extract all features from packet"""
        try:
            all_features = []
            
            for extractor_name, extractor_func in self.feature_extractors.items():
                features = extractor_func(packet_info)
                if features is not None:
                    all_features.extend(features)
            
            if all_features:
                return np.array(all_features).reshape(1, -1)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return None
    
    def _extract_statistical_features(self, packet_info) -> List[float]:
        """Extract statistical features from packet"""
        try:
            payload = packet_info.payload
            if not payload:
                return [0] * 10
            
            payload_str = payload.decode('utf-8', errors='ignore')
            
            features = [
                len(payload),  # Payload length
                len(payload_str),  # String length
                packet_info.src_port,  # Source port
                packet_info.dst_port,  # Destination port
                payload_str.count(' '),  # Space count
                payload_str.count('='),  # Equal signs
                payload_str.count('&'),  # Ampersands
                payload_str.count('?'),  # Question marks
                payload_str.count('%'),  # Percent signs (URL encoding)
                len(set(payload_str))  # Unique characters
            ]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting statistical features: {e}")
            return [0] * 10
    
    def _extract_ngram_features(self, packet_info) -> List[float]:
        """Extract n-gram features from payload"""
        try:
            payload_str = packet_info.payload.decode('utf-8', errors='ignore')
            
            # Common malicious n-grams
            malicious_ngrams = [
                'script', 'select', 'union', 'insert', 'update', 'delete',
                'exec', 'eval', 'system', 'shell', 'cmd', 'powershell'
            ]
            
            features = []
            for ngram in malicious_ngrams:
                count = payload_str.lower().count(ngram)
                features.append(count)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting n-gram features: {e}")
            return [0] * 12
    
    def _extract_entropy_features(self, packet_info) -> List[float]:
        """Extract entropy-based features"""
        try:
            payload = packet_info.payload
            if not payload:
                return [0] * 3
            
            # Calculate Shannon entropy
            entropy = self._calculate_entropy(payload)
            
            # Calculate byte frequency variance
            byte_counts = np.bincount(payload, minlength=256)
            byte_variance = np.var(byte_counts)
            
            # Calculate compression ratio (simple approximation)
            import zlib
            compressed = zlib.compress(payload)
            compression_ratio = len(compressed) / max(len(payload), 1)
            
            return [entropy, byte_variance, compression_ratio]
            
        except Exception as e:
            self.logger.error(f"Error extracting entropy features: {e}")
            return [0] * 3
    
    def _extract_protocol_features(self, packet_info) -> List[float]:
        """Extract protocol-specific features"""
        try:
            features = [
                1 if packet_info.protocol == 'TCP' else 0,
                1 if packet_info.protocol == 'UDP' else 0,
                1 if packet_info.dst_port == 80 else 0,  # HTTP
                1 if packet_info.dst_port == 443 else 0,  # HTTPS
                1 if packet_info.dst_port == 53 else 0,  # DNS
                packet_info.size,  # Packet size
            ]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting protocol features: {e}")
            return [0] * 6
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = np.bincount(data, minlength=256)
            probabilities = byte_counts / len(data)
            
            # Calculate entropy
            entropy = 0.0
            for p in probabilities:
                if p > 0:
                    entropy -= p * np.log2(p)
            
            return entropy
            
        except Exception as e:
            return 0.0
    
    async def _analyze_with_cnn(self, payload: bytes) -> Optional[MLThreatResult]:
        """Analyze payload using CNN model"""
        try:
            if 'cnn_payload' not in self.models:
                return None
            
            model = self.models['cnn_payload']
            
            # Convert payload to sequence
            sequence = self._payload_to_sequence(payload)
            if sequence is None:
                return None
            
            # Make prediction
            with torch.no_grad():
                input_tensor = torch.tensor(sequence).unsqueeze(0)
                outputs = model(input_tensor)
                probabilities = F.softmax(outputs, dim=1)
                predicted_class = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0][predicted_class].item()
            
            # Map prediction to threat type
            if predicted_class > 0 and confidence > self.settings.confidence_threshold:
                threat_type = self.threat_categories[predicted_class]
                severity = self._map_threat_to_severity(threat_type)
                
                return MLThreatResult(
                    is_threat=True,
                    threat_type=threat_type,
                    description=f"CNN detected {threat_type} with confidence {confidence:.2f}",
                    severity=severity,
                    confidence=confidence,
                    model_name="cnn_payload"
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in CNN analysis: {e}")
            return None
    
    async def _analyze_with_rf(self, features: np.ndarray) -> Optional[MLThreatResult]:
        """Analyze using Random Forest classifier"""
        try:
            if 'rf_classifier' not in self.models:
                return None
            
            model = self.models['rf_classifier']
            
            # Scale features if scaler is available
            if 'main' in self.scalers:
                features = self.scalers['main'].transform(features)
            
            # Make prediction
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(features)[0]
                predicted_class = np.argmax(probabilities)
                confidence = probabilities[predicted_class]
            else:
                # Model not trained yet, return None
                return None
            
            if predicted_class > 0 and confidence > self.settings.confidence_threshold:
                threat_type = self.threat_categories[predicted_class]
                severity = self._map_threat_to_severity(threat_type)
                
                return MLThreatResult(
                    is_threat=True,
                    threat_type=threat_type,
                    description=f"Random Forest detected {threat_type} with confidence {confidence:.2f}",
                    severity=severity,
                    confidence=confidence,
                    model_name="random_forest"
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in Random Forest analysis: {e}")
            return None
    
    async def _analyze_with_isolation_forest(self, features: np.ndarray) -> Optional[MLThreatResult]:
        """Analyze using Isolation Forest for anomaly detection"""
        try:
            if 'isolation_forest' not in self.models:
                return None
            
            model = self.models['isolation_forest']
            
            # Scale features if scaler is available
            if 'main' in self.scalers:
                features = self.scalers['main'].transform(features)
            
            # Make prediction
            if hasattr(model, 'decision_function'):
                anomaly_score = model.decision_function(features)[0]
                is_anomaly = model.predict(features)[0] == -1
            else:
                # Model not trained yet
                return None
            
            if is_anomaly and abs(anomaly_score) > 0.5:
                return MLThreatResult(
                    is_threat=True,
                    threat_type="ANOMALY",
                    description=f"Anomaly detected with score {anomaly_score:.2f}",
                    severity=ThreatLevel.MEDIUM,
                    confidence=min(0.9, abs(anomaly_score)),
                    model_name="isolation_forest"
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in Isolation Forest analysis: {e}")
            return None
    
    def _payload_to_sequence(self, payload: bytes, max_length: int = 1000) -> Optional[List[int]]:
        """Convert payload bytes to integer sequence"""
        try:
            if not payload:
                return None
            
            # Convert bytes to integers
            sequence = list(payload[:max_length])
            
            # Pad or truncate to fixed length
            if len(sequence) < max_length:
                sequence.extend([0] * (max_length - len(sequence)))
            
            return sequence
            
        except Exception as e:
            self.logger.error(f"Error converting payload to sequence: {e}")
            return None
    
    def _map_threat_to_severity(self, threat_type: str) -> ThreatLevel:
        """Map threat type to severity level"""
        severity_mapping = {
            'SQL_INJECTION': ThreatLevel.HIGH,
            'XSS': ThreatLevel.HIGH,
            'COMMAND_INJECTION': ThreatLevel.CRITICAL,
            'MALWARE': ThreatLevel.CRITICAL,
            'ANOMALY': ThreatLevel.MEDIUM
        }
        
        return severity_mapping.get(threat_type, ThreatLevel.LOW)
    
    def _ensemble_prediction(self, predictions: List[MLThreatResult], packet_info) -> MLThreatResult:
        """Combine predictions from multiple models"""
        try:
            # Filter threat predictions
            threat_predictions = [p for p in predictions if p.is_threat]
            
            if not threat_predictions:
                return MLThreatResult(
                    is_threat=False,
                    threat_type="BENIGN",
                    description="No threats detected by ensemble",
                    severity=ThreatLevel.LOW,
                    confidence=0.0,
                    model_name="ensemble"
                )
            
            # Weight predictions by confidence
            weighted_score = sum(p.confidence for p in threat_predictions) / len(threat_predictions)
            
            # Select highest confidence prediction
            best_prediction = max(threat_predictions, key=lambda x: x.confidence)
            
            # Adjust confidence based on ensemble agreement
            model_agreement = len(threat_predictions) / len(predictions)
            adjusted_confidence = best_prediction.confidence * model_agreement
            
            return MLThreatResult(
                is_threat=True,
                threat_type=best_prediction.threat_type,
                description=f"Ensemble prediction: {best_prediction.description} (agreement: {model_agreement:.2f})",
                severity=best_prediction.severity,
                confidence=adjusted_confidence,
                model_name="ensemble",
                features_used=[p.model_name for p in threat_predictions]
            )
            
        except Exception as e:
            self.logger.error(f"Error in ensemble prediction: {e}")
            return predictions[0] if predictions else MLThreatResult(
                is_threat=False, threat_type="ERROR", description="Ensemble error",
                severity=ThreatLevel.LOW, confidence=0.0, model_name="ensemble"
            )
    
    async def _fallback_analysis(self, packet_info) -> MLThreatResult:
        """Fallback rule-based analysis"""
        try:
            if 'fallback' not in self.models:
                return MLThreatResult(
                    is_threat=False,
                    threat_type="BENIGN",
                    description="No analysis available",
                    severity=ThreatLevel.LOW,
                    confidence=0.0,
                    model_name="none"
                )
            
            payload_str = packet_info.payload.decode('utf-8', errors='ignore').lower()
            rules = self.models['fallback']['rules']
            
            # Check SQL injection keywords
            sql_matches = sum(1 for keyword in rules['sql_keywords'] if keyword in payload_str)
            if sql_matches >= 2:
                return MLThreatResult(
                    is_threat=True,
                    threat_type="SQL_INJECTION",
                    description=f"Rule-based SQL injection detection ({sql_matches} matches)",
                    severity=ThreatLevel.HIGH,
                    confidence=0.6,
                    model_name="rule_based"
                )
            
            # Check XSS keywords
            xss_matches = sum(1 for keyword in rules['xss_keywords'] if keyword in payload_str)
            if xss_matches >= 1:
                return MLThreatResult(
                    is_threat=True,
                    threat_type="XSS",
                    description=f"Rule-based XSS detection ({xss_matches} matches)",
                    severity=ThreatLevel.HIGH,
                    confidence=0.6,
                    model_name="rule_based"
                )
            
            # Check command injection keywords
            cmd_matches = sum(1 for keyword in rules['cmd_keywords'] if keyword in payload_str)
            if cmd_matches >= 1:
                return MLThreatResult(
                    is_threat=True,
                    threat_type="COMMAND_INJECTION",
                    description=f"Rule-based command injection detection ({cmd_matches} matches)",
                    severity=ThreatLevel.CRITICAL,
                    confidence=0.7,
                    model_name="rule_based"
                )
            
            return MLThreatResult(
                is_threat=False,
                threat_type="BENIGN",
                description="Rule-based analysis: clean",
                severity=ThreatLevel.LOW,
                confidence=0.5,
                model_name="rule_based"
            )
            
        except Exception as e:
            self.logger.error(f"Error in fallback analysis: {e}")
            return MLThreatResult(
                is_threat=False,
                threat_type="ERROR",
                description=f"Fallback analysis error: {e}",
                severity=ThreatLevel.LOW,
                confidence=0.0,
                model_name="error"
            )
    
    async def train_models(self, training_data: List[Dict]) -> bool:
        """Train ML models with new data"""
        try:
            self.logger.info("Starting model training...")
            
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if len(X) < 10:  # Need minimum samples
                self.logger.warning("Insufficient training data")
                return False
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train Random Forest
            if 'rf_classifier' in self.models:
                self.models['rf_classifier'].fit(X_train, y_train)
                accuracy = self.models['rf_classifier'].score(X_test, y_test)
                self.logger.info(f"Random Forest accuracy: {accuracy:.3f}")
            
            # Train Isolation Forest
            if 'isolation_forest' in self.models:
                # Use only benign samples for anomaly detection
                benign_samples = X_train[y_train == 0]
                if len(benign_samples) > 5:
                    self.models['isolation_forest'].fit(benign_samples)
            
            # Save models
            await self._save_models()
            
            self.logger.info("Model training completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
            return False
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        X = []
        y = []
        
        for sample in training_data:
            # Extract features (this would need to be implemented based on your data format)
            features = sample.get('features', [])
            label = sample.get('label', 'BENIGN')
            
            if features and label in self.threat_categories:
                X.append(features)
                y.append(self.threat_categories.index(label))
        
        return np.array(X), np.array(y)
    
    async def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save PyTorch models
            if 'cnn_payload' in self.models:
                torch.save(
                    self.models['cnn_payload'].state_dict(),
                    os.path.join(self.settings.model_path, 'cnn_payload_model.pth')
                )
            
            # Save scikit-learn models
            for model_name in ['rf_classifier', 'isolation_forest']:
                if model_name in self.models:
                    with open(os.path.join(self.settings.model_path, f'{model_name}.pkl'), 'wb') as f:
                        pickle.dump(self.models[model_name], f)
            
            # Save processors
            if 'main' in self.scalers:
                with open(os.path.join(self.settings.model_path, 'feature_scaler.pkl'), 'wb') as f:
                    pickle.dump(self.scalers['main'], f)
            
            if 'main' in self.encoders:
                with open(os.path.join(self.settings.model_path, 'label_encoder.pkl'), 'wb') as f:
                    pickle.dump(self.encoders['main'], f)
            
            self.logger.info("Models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")