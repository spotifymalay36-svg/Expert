"""
Federated Learning Framework for Distributed Threat Intelligence
Implements privacy-preserving model training across distributed WAF nodes
"""

import asyncio
import logging
import pickle
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

import tensorflow as tf
import tensorflow_federated as tff
from collections import OrderedDict

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class FederatedNode:
    """Federated learning node information"""
    node_id: str
    node_url: str
    is_active: bool
    last_update: datetime
    model_version: int
    samples_contributed: int
    trust_score: float

@dataclass
class FederatedRound:
    """Federated learning round information"""
    round_id: int
    participants: List[str]
    aggregated_metrics: Dict[str, float]
    model_version: int
    timestamp: datetime
    convergence_score: float

class FederatedLearningServer:
    """Federated Learning Server for model aggregation"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Federated nodes registry
        self.nodes: Dict[str, FederatedNode] = {}
        
        # Model versioning
        self.current_model_version = 1
        self.global_model = None
        
        # Training history
        self.training_rounds: List[FederatedRound] = []
        
        # Federated learning configuration
        self.min_nodes_required = 3
        self.rounds_per_aggregation = 1
        self.differential_privacy_enabled = True
        self.privacy_budget = 1.0  # Epsilon for differential privacy
        
        # Model architecture
        self.model_path = Path(settings.model_path) / "federated"
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.logger.info("Federated Learning Server initialized")
    
    async def initialize(self):
        """Initialize federated learning server"""
        try:
            # Create global model
            self.global_model = self._create_threat_detection_model()
            
            # Initialize TFF
            self._setup_tff_environment()
            
            self.logger.info("Federated Learning Server ready")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize federated learning: {e}")
            raise
    
    def _create_threat_detection_model(self) -> tf.keras.Model:
        """Create the global threat detection model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(100,)),  # Feature vector size
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(5, activation='softmax')  # 5 threat classes
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _setup_tff_environment(self):
        """Setup TensorFlow Federated environment"""
        try:
            # Set TFF execution context
            tff.backends.native.set_local_python_execution_context()
            
            # Create federated data type
            self.federated_data_type = tff.FederatedType(
                tff.SequenceType(
                    tff.StructType([
                        ('x', tff.TensorType(tf.float32, [None, 100])),
                        ('y', tff.TensorType(tf.int32, [None]))
                    ])
                ),
                tff.CLIENTS
            )
            
            self.logger.info("TFF environment configured")
            
        except Exception as e:
            self.logger.error(f"Error setting up TFF: {e}")
    
    async def register_node(self, node_id: str, node_url: str) -> bool:
        """Register a new federated learning node"""
        try:
            if node_id in self.nodes:
                self.logger.warning(f"Node {node_id} already registered, updating...")
            
            self.nodes[node_id] = FederatedNode(
                node_id=node_id,
                node_url=node_url,
                is_active=True,
                last_update=datetime.now(),
                model_version=self.current_model_version,
                samples_contributed=0,
                trust_score=1.0
            )
            
            self.logger.info(f"Registered federated node: {node_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering node {node_id}: {e}")
            return False
    
    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a federated learning node"""
        try:
            if node_id in self.nodes:
                del self.nodes[node_id]
                self.logger.info(f"Unregistered node: {node_id}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error unregistering node {node_id}: {e}")
            return False
    
    async def federated_train_round(self, client_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one round of federated training"""
        try:
            self.logger.info(f"Starting federated training round {len(self.training_rounds) + 1}")
            
            # Get active nodes
            active_nodes = [node for node in self.nodes.values() if node.is_active]
            
            if len(active_nodes) < self.min_nodes_required:
                self.logger.warning(f"Insufficient nodes for federated training: {len(active_nodes)}/{self.min_nodes_required}")
                return {"success": False, "reason": "insufficient_nodes"}
            
            # Collect model updates from clients
            client_updates = []
            client_weights = []
            
            for node_id, data in client_data.items():
                if node_id in self.nodes:
                    # Extract model weights and metrics
                    model_update = data.get('model_weights')
                    num_samples = data.get('num_samples', 1)
                    
                    if model_update:
                        client_updates.append(model_update)
                        client_weights.append(num_samples)
                        
                        # Update node statistics
                        self.nodes[node_id].samples_contributed += num_samples
                        self.nodes[node_id].last_update = datetime.now()
            
            if not client_updates:
                self.logger.warning("No valid client updates received")
                return {"success": False, "reason": "no_updates"}
            
            # Apply differential privacy if enabled
            if self.differential_privacy_enabled:
                client_updates = self._apply_differential_privacy(client_updates)
            
            # Federated averaging
            aggregated_weights = self._federated_averaging(
                client_updates, 
                client_weights
            )
            
            # Update global model
            self.global_model.set_weights(aggregated_weights)
            self.current_model_version += 1
            
            # Evaluate global model
            metrics = await self._evaluate_global_model()
            
            # Create training round record
            training_round = FederatedRound(
                round_id=len(self.training_rounds) + 1,
                participants=[node.node_id for node in active_nodes],
                aggregated_metrics=metrics,
                model_version=self.current_model_version,
                timestamp=datetime.now(),
                convergence_score=metrics.get('accuracy', 0.0)
            )
            
            self.training_rounds.append(training_round)
            
            # Save global model
            await self._save_global_model()
            
            self.logger.info(f"Federated training round completed. Accuracy: {metrics.get('accuracy', 0.0):.4f}")
            
            return {
                "success": True,
                "round_id": training_round.round_id,
                "model_version": self.current_model_version,
                "metrics": metrics,
                "global_weights": aggregated_weights
            }
            
        except Exception as e:
            self.logger.error(f"Error in federated training round: {e}")
            return {"success": False, "reason": str(e)}
    
    def _federated_averaging(self, client_updates: List[List], client_weights: List[int]) -> List:
        """Perform federated averaging of model weights"""
        try:
            # Normalize weights
            total_samples = sum(client_weights)
            normalized_weights = [w / total_samples for w in client_weights]
            
            # Initialize aggregated weights
            aggregated = []
            
            # Average each layer
            num_layers = len(client_updates[0])
            for layer_idx in range(num_layers):
                # Weighted average of this layer across all clients
                layer_weights = []
                
                for client_idx, client_update in enumerate(client_updates):
                    weight = normalized_weights[client_idx]
                    layer = client_update[layer_idx]
                    
                    if client_idx == 0:
                        layer_weights = layer * weight
                    else:
                        layer_weights += layer * weight
                
                aggregated.append(layer_weights)
            
            return aggregated
            
        except Exception as e:
            self.logger.error(f"Error in federated averaging: {e}")
            raise
    
    def _apply_differential_privacy(self, client_updates: List[List]) -> List[List]:
        """Apply differential privacy to client updates"""
        try:
            # Add Gaussian noise for differential privacy
            noise_scale = self._calculate_noise_scale()
            
            noisy_updates = []
            for update in client_updates:
                noisy_update = []
                for layer in update:
                    # Add Gaussian noise
                    noise = np.random.normal(0, noise_scale, layer.shape)
                    noisy_layer = layer + noise
                    noisy_update.append(noisy_layer)
                
                noisy_updates.append(noisy_update)
            
            self.logger.debug(f"Applied differential privacy with noise scale: {noise_scale}")
            return noisy_updates
            
        except Exception as e:
            self.logger.error(f"Error applying differential privacy: {e}")
            return client_updates
    
    def _calculate_noise_scale(self) -> float:
        """Calculate noise scale for differential privacy"""
        # Using Gaussian mechanism
        # noise_scale = sensitivity / epsilon
        sensitivity = 1.0  # Assuming clipped gradients
        return sensitivity / self.privacy_budget
    
    async def _evaluate_global_model(self) -> Dict[str, float]:
        """Evaluate global model performance"""
        try:
            # Generate synthetic validation data
            # In production, this would use real validation data
            X_val = np.random.randn(1000, 100).astype(np.float32)
            y_val = np.random.randint(0, 5, size=1000).astype(np.int32)
            
            # Evaluate
            loss, accuracy = self.global_model.evaluate(X_val, y_val, verbose=0)
            
            return {
                "loss": float(loss),
                "accuracy": float(accuracy),
                "num_parameters": self.global_model.count_params()
            }
            
        except Exception as e:
            self.logger.error(f"Error evaluating global model: {e}")
            return {"loss": 0.0, "accuracy": 0.0}
    
    async def _save_global_model(self):
        """Save global model to disk"""
        try:
            model_file = self.model_path / f"global_model_v{self.current_model_version}.h5"
            self.global_model.save(model_file)
            
            # Save metadata
            metadata = {
                "version": self.current_model_version,
                "timestamp": datetime.now().isoformat(),
                "nodes": len(self.nodes),
                "rounds": len(self.training_rounds)
            }
            
            metadata_file = self.model_path / f"global_model_v{self.current_model_version}_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"Saved global model v{self.current_model_version}")
            
        except Exception as e:
            self.logger.error(f"Error saving global model: {e}")
    
    async def get_global_model_weights(self) -> Optional[List]:
        """Get current global model weights for distribution to clients"""
        try:
            if self.global_model:
                return self.global_model.get_weights()
            return None
        except Exception as e:
            self.logger.error(f"Error getting global model weights: {e}")
            return None
    
    def get_federation_stats(self) -> Dict[str, Any]:
        """Get federated learning statistics"""
        try:
            active_nodes = [n for n in self.nodes.values() if n.is_active]
            
            return {
                "total_nodes": len(self.nodes),
                "active_nodes": len(active_nodes),
                "current_model_version": self.current_model_version,
                "training_rounds": len(self.training_rounds),
                "total_samples_contributed": sum(n.samples_contributed for n in self.nodes.values()),
                "average_node_trust": np.mean([n.trust_score for n in active_nodes]) if active_nodes else 0.0,
                "differential_privacy_enabled": self.differential_privacy_enabled,
                "privacy_budget": self.privacy_budget,
                "last_round_accuracy": self.training_rounds[-1].aggregated_metrics.get('accuracy', 0.0) if self.training_rounds else 0.0
            }
        except Exception as e:
            self.logger.error(f"Error getting federation stats: {e}")
            return {}


class FederatedLearningClient:
    """Federated Learning Client for local model training"""
    
    def __init__(self, settings: Settings, node_id: str):
        self.settings = settings
        self.node_id = node_id
        self.logger = get_logger(__name__)
        
        # Local model
        self.local_model = None
        
        # Local training data buffer
        self.training_buffer: List[Tuple[np.ndarray, int]] = []
        self.max_buffer_size = 10000
        
        # Server connection
        self.server_url = settings.federated_server_url
        
        self.logger.info(f"Federated Learning Client initialized: {node_id}")
    
    async def initialize(self):
        """Initialize federated client"""
        try:
            # Create local model (same architecture as server)
            self.local_model = self._create_local_model()
            
            # Register with server
            await self._register_with_server()
            
            self.logger.info("Federated client initialized and registered")
            
        except Exception as e:
            self.logger.error(f"Error initializing federated client: {e}")
            raise
    
    def _create_local_model(self) -> tf.keras.Model:
        """Create local training model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(100,)),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(5, activation='softmax')
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    async def _register_with_server(self):
        """Register this client with the federated server"""
        try:
            # In production, this would make an HTTP request to the server
            # For now, we'll simulate registration
            self.logger.info(f"Client {self.node_id} registered with server at {self.server_url}")
        except Exception as e:
            self.logger.error(f"Error registering with server: {e}")
    
    def add_training_sample(self, features: np.ndarray, label: int):
        """Add a training sample to the local buffer"""
        try:
            if len(self.training_buffer) >= self.max_buffer_size:
                # Remove oldest sample
                self.training_buffer.pop(0)
            
            self.training_buffer.append((features, label))
            
        except Exception as e:
            self.logger.error(f"Error adding training sample: {e}")
    
    async def local_train(self, epochs: int = 5, batch_size: int = 32) -> Dict[str, Any]:
        """Train local model on buffered data"""
        try:
            if len(self.training_buffer) < batch_size:
                self.logger.warning("Insufficient training samples")
                return {"success": False, "reason": "insufficient_samples"}
            
            # Prepare training data
            X = np.array([sample[0] for sample in self.training_buffer])
            y = np.array([sample[1] for sample in self.training_buffer])
            
            # Train local model
            history = self.local_model.fit(
                X, y,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                verbose=0
            )
            
            # Get model weights
            model_weights = self.local_model.get_weights()
            
            metrics = {
                "loss": float(history.history['loss'][-1]),
                "accuracy": float(history.history['accuracy'][-1]),
                "val_loss": float(history.history['val_loss'][-1]),
                "val_accuracy": float(history.history['val_accuracy'][-1])
            }
            
            self.logger.info(f"Local training completed. Accuracy: {metrics['accuracy']:.4f}")
            
            return {
                "success": True,
                "model_weights": model_weights,
                "num_samples": len(self.training_buffer),
                "metrics": metrics
            }
            
        except Exception as e:
            self.logger.error(f"Error in local training: {e}")
            return {"success": False, "reason": str(e)}
    
    async def update_from_global_model(self, global_weights: List):
        """Update local model with global model weights"""
        try:
            self.local_model.set_weights(global_weights)
            self.logger.info("Local model updated with global weights")
        except Exception as e:
            self.logger.error(f"Error updating from global model: {e}")
    
    def get_client_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            "node_id": self.node_id,
            "buffered_samples": len(self.training_buffer),
            "max_buffer_size": self.max_buffer_size,
            "server_url": self.server_url
        }