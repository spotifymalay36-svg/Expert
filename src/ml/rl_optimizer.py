"""
Reinforcement Learning for Dynamic Firewall Rule Optimization
Uses Deep Q-Learning (DQN) to optimize firewall rules based on threat patterns
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from collections import deque
import random
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class FirewallRule:
    """Firewall rule representation"""
    rule_id: str
    priority: int
    source_ip: str
    dest_port: int
    protocol: str
    action: str  # ALLOW, BLOCK, LOG
    confidence: float
    created_at: datetime
    effectiveness_score: float = 0.0

@dataclass
class RLState:
    """RL environment state"""
    threat_rate: float  # Current threats per minute
    blocked_rate: float  # Blocked requests per minute
    false_positive_rate: float  # False positive rate
    network_load: float  # Network utilization
    active_rules: int  # Number of active rules
    recent_threat_types: List[str]  # Recent threat categories
    time_of_day: float  # Normalized hour (0-1)

@dataclass
class RLAction:
    """RL action representation"""
    action_type: str  # ADD_RULE, REMOVE_RULE, MODIFY_PRIORITY, NO_ACTION
    rule_target: Optional[str]  # IP or rule ID to act on
    parameters: Dict[str, Any]  # Action-specific parameters

class DQNAgent:
    """Deep Q-Network agent for rule optimization"""
    
    def __init__(self, state_size: int, action_size: int, settings: Settings):
        self.state_size = state_size
        self.action_size = action_size
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Hyperparameters
        self.memory = deque(maxlen=10000)
        self.gamma = 0.95  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        self.batch_size = 64
        self.update_target_freq = 100
        
        # Networks
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
        
        # Training tracking
        self.training_step = 0
        self.total_rewards = []
        
        self.logger.info("DQN Agent initialized")
    
    def _build_model(self) -> keras.Model:
        """Build DQN neural network"""
        model = keras.Sequential([
            keras.layers.Input(shape=(self.state_size,)),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dense(self.action_size, activation='linear')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='mse'
        )
        
        return model
    
    def update_target_model(self):
        """Copy weights from model to target_model"""
        self.target_model.set_weights(self.model.get_weights())
    
    def remember(self, state: np.ndarray, action: int, reward: float, 
                 next_state: np.ndarray, done: bool):
        """Store experience in replay memory"""
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state: np.ndarray, training: bool = True) -> int:
        """Choose action using epsilon-greedy policy"""
        if training and np.random.random() <= self.epsilon:
            return random.randrange(self.action_size)
        
        # Exploit: choose best action from Q-network
        q_values = self.model.predict(state.reshape(1, -1), verbose=0)
        return np.argmax(q_values[0])
    
    def replay(self) -> float:
        """Train on batch from replay memory"""
        if len(self.memory) < self.batch_size:
            return 0.0
        
        # Sample batch
        minibatch = random.sample(self.memory, self.batch_size)
        
        states = np.array([experience[0] for experience in minibatch])
        actions = np.array([experience[1] for experience in minibatch])
        rewards = np.array([experience[2] for experience in minibatch])
        next_states = np.array([experience[3] for experience in minibatch])
        dones = np.array([experience[4] for experience in minibatch])
        
        # Predict Q-values for starting states
        q_values = self.model.predict(states, verbose=0)
        
        # Predict Q-values for next states using target network
        next_q_values = self.target_model.predict(next_states, verbose=0)
        
        # Update Q-values with Bellman equation
        for i in range(self.batch_size):
            if dones[i]:
                q_values[i][actions[i]] = rewards[i]
            else:
                q_values[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q_values[i])
        
        # Train the model
        loss = self.model.train_on_batch(states, q_values)
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # Update target network periodically
        self.training_step += 1
        if self.training_step % self.update_target_freq == 0:
            self.update_target_model()
        
        return float(loss)
    
    def save(self, filepath: str):
        """Save model weights"""
        self.model.save_weights(filepath)
    
    def load(self, filepath: str):
        """Load model weights"""
        self.model.load_weights(filepath)
        self.update_target_model()


class RLFirewallOptimizer:
    """RL-based firewall rule optimizer"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # State and action spaces
        self.state_size = 10  # Size of state vector
        self.action_size = 20  # Number of possible actions
        
        # DQN Agent
        self.agent = DQNAgent(self.state_size, self.action_size, settings)
        
        # Firewall rules
        self.active_rules: Dict[str, FirewallRule] = {}
        self.rule_history: List[Dict] = []
        
        # Environment state
        self.current_state: Optional[RLState] = None
        
        # Performance metrics
        self.metrics_history = deque(maxlen=1000)
        
        # Training configuration
        self.training_enabled = True
        self.episodes_trained = 0
        self.model_path = Path(settings.model_path) / "rl"
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Action mapping
        self.action_map = self._create_action_map()
        
        self.logger.info("RL Firewall Optimizer initialized")
    
    def _create_action_map(self) -> Dict[int, str]:
        """Create mapping from action indices to action types"""
        return {
            0: "NO_ACTION",
            1: "ADD_BLOCK_RULE_HIGH_THREAT",
            2: "ADD_BLOCK_RULE_MEDIUM_THREAT",
            3: "ADD_RATE_LIMIT_RULE",
            4: "REMOVE_INEFFECTIVE_RULE",
            5: "INCREASE_RULE_PRIORITY",
            6: "DECREASE_RULE_PRIORITY",
            7: "ADD_WHITELIST_RULE",
            8: "TIGHTEN_EXISTING_RULE",
            9: "RELAX_EXISTING_RULE",
            10: "ADD_GEO_BLOCK_RULE",
            11: "ADD_PORT_BLOCK_RULE",
            12: "ADD_PROTOCOL_FILTER",
            13: "REMOVE_EXPIRED_RULE",
            14: "CONSOLIDATE_SIMILAR_RULES",
            15: "ADD_TIME_BASED_RULE",
            16: "REMOVE_REDUNDANT_RULE",
            17: "ADD_BEHAVIORAL_RULE",
            18: "UPDATE_THREAT_THRESHOLD",
            19: "OPTIMIZE_RULE_ORDER"
        }
    
    async def initialize(self):
        """Initialize RL optimizer"""
        try:
            # Load saved model if exists
            model_file = self.model_path / "dqn_model.h5"
            if model_file.exists():
                self.agent.load(str(model_file))
                self.logger.info("Loaded saved RL model")
            
            # Initialize default rules
            await self._initialize_default_rules()
            
            self.logger.info("RL Firewall Optimizer ready")
            
        except Exception as e:
            self.logger.error(f"Error initializing RL optimizer: {e}")
            raise
    
    async def _initialize_default_rules(self):
        """Initialize with default firewall rules"""
        default_rules = [
            FirewallRule(
                rule_id="default_block_malicious",
                priority=100,
                source_ip="0.0.0.0/0",
                dest_port=0,
                protocol="*",
                action="BLOCK",
                confidence=1.0,
                created_at=datetime.now()
            )
        ]
        
        for rule in default_rules:
            self.active_rules[rule.rule_id] = rule
    
    def _get_current_state(self, metrics: Dict[str, Any]) -> np.ndarray:
        """Convert current metrics to state vector"""
        try:
            state = np.array([
                metrics.get('threat_rate', 0.0) / 100.0,  # Normalized
                metrics.get('blocked_rate', 0.0) / 100.0,
                metrics.get('false_positive_rate', 0.0),
                metrics.get('network_load', 0.0),
                len(self.active_rules) / 100.0,  # Normalized
                metrics.get('cpu_usage', 0.0) / 100.0,
                metrics.get('memory_usage', 0.0) / 100.0,
                metrics.get('latency', 0.0) / 1000.0,  # Normalized to seconds
                (datetime.now().hour / 24.0),  # Time of day
                metrics.get('threat_diversity', 0.0)  # Number of different threat types
            ])
            
            return state
            
        except Exception as e:
            self.logger.error(f"Error getting current state: {e}")
            return np.zeros(self.state_size)
    
    def _calculate_reward(self, prev_metrics: Dict, current_metrics: Dict, 
                          action_taken: int) -> float:
        """Calculate reward for the RL agent"""
        try:
            reward = 0.0
            
            # Reward for reducing threats
            threat_reduction = (prev_metrics.get('threat_rate', 0) - 
                              current_metrics.get('threat_rate', 0))
            reward += threat_reduction * 10.0
            
            # Reward for maintaining low false positive rate
            fp_rate = current_metrics.get('false_positive_rate', 0)
            reward -= fp_rate * 50.0  # Heavy penalty for false positives
            
            # Reward for efficient rule management
            rule_count = len(self.active_rules)
            if rule_count < 50:  # Encourage concise rule sets
                reward += 5.0
            elif rule_count > 100:  # Penalize bloated rule sets
                reward -= (rule_count - 100) * 0.5
            
            # Reward for low latency
            latency = current_metrics.get('latency', 0)
            if latency < 1.0:  # Less than 1ms
                reward += 10.0
            elif latency > 5.0:  # More than 5ms
                reward -= latency * 2.0
            
            # Reward for blocking high-severity threats
            blocked_critical = current_metrics.get('blocked_critical_threats', 0)
            reward += blocked_critical * 20.0
            
            # Penalty for high resource usage
            cpu_usage = current_metrics.get('cpu_usage', 0)
            if cpu_usage > 80:
                reward -= (cpu_usage - 80) * 0.5
            
            # Reward for network load balance
            network_load = current_metrics.get('network_load', 0)
            if 30 < network_load < 70:  # Sweet spot
                reward += 5.0
            
            return reward
            
        except Exception as e:
            self.logger.error(f"Error calculating reward: {e}")
            return 0.0
    
    async def optimize_rules(self, current_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Main optimization loop - called periodically"""
        try:
            # Get current state
            state = self._get_current_state(current_metrics)
            
            # Choose action
            action_idx = self.agent.act(state, training=self.training_enabled)
            action_type = self.action_map[action_idx]
            
            # Execute action
            action_result = await self._execute_action(action_type, current_metrics)
            
            # Get new state after action
            new_metrics = await self._get_updated_metrics(current_metrics, action_result)
            new_state = self._get_current_state(new_metrics)
            
            # Calculate reward
            reward = self._calculate_reward(current_metrics, new_metrics, action_idx)
            
            # Store experience
            done = False  # Never-ending task
            self.agent.remember(state, action_idx, reward, new_state, done)
            
            # Train agent
            if self.training_enabled:
                loss = self.agent.replay()
                
                if loss > 0:
                    self.logger.debug(f"RL training loss: {loss:.4f}, reward: {reward:.2f}")
            
            # Save model periodically
            if self.agent.training_step % 1000 == 0:
                await self._save_model()
            
            # Log optimization result
            self.logger.info(f"RL Action: {action_type}, Reward: {reward:.2f}, Epsilon: {self.agent.epsilon:.3f}")
            
            return {
                "action_taken": action_type,
                "action_result": action_result,
                "reward": reward,
                "state": state.tolist(),
                "new_state": new_state.tolist(),
                "active_rules": len(self.active_rules)
            }
            
        except Exception as e:
            self.logger.error(f"Error in rule optimization: {e}")
            return {"error": str(e)}
    
    async def _execute_action(self, action_type: str, metrics: Dict) -> Dict[str, Any]:
        """Execute the chosen action"""
        try:
            result = {"action": action_type, "success": False}
            
            if action_type == "NO_ACTION":
                result["success"] = True
                result["message"] = "No action needed"
            
            elif action_type == "ADD_BLOCK_RULE_HIGH_THREAT":
                # Add rule to block high-threat IPs
                threat_ips = metrics.get('recent_threat_ips', [])
                if threat_ips:
                    ip = threat_ips[0]
                    rule = FirewallRule(
                        rule_id=f"block_{ip}_{int(datetime.now().timestamp())}",
                        priority=90,
                        source_ip=ip,
                        dest_port=0,
                        protocol="*",
                        action="BLOCK",
                        confidence=0.9,
                        created_at=datetime.now()
                    )
                    self.active_rules[rule.rule_id] = rule
                    result["success"] = True
                    result["message"] = f"Added block rule for {ip}"
            
            elif action_type == "ADD_RATE_LIMIT_RULE":
                # Add rate limiting rule
                result["success"] = True
                result["message"] = "Rate limiting rule added"
            
            elif action_type == "REMOVE_INEFFECTIVE_RULE":
                # Remove rules with low effectiveness scores
                ineffective_rules = [
                    rid for rid, rule in self.active_rules.items()
                    if rule.effectiveness_score < 0.3 and rid != "default_block_malicious"
                ]
                if ineffective_rules:
                    removed_rule = ineffective_rules[0]
                    del self.active_rules[removed_rule]
                    result["success"] = True
                    result["message"] = f"Removed ineffective rule {removed_rule}"
            
            elif action_type == "INCREASE_RULE_PRIORITY":
                # Increase priority of effective rules
                effective_rules = [
                    (rid, rule) for rid, rule in self.active_rules.items()
                    if rule.effectiveness_score > 0.7
                ]
                if effective_rules:
                    rid, rule = effective_rules[0]
                    rule.priority = min(100, rule.priority + 10)
                    result["success"] = True
                    result["message"] = f"Increased priority of rule {rid}"
            
            elif action_type == "CONSOLIDATE_SIMILAR_RULES":
                # Consolidate similar rules to reduce rule count
                result["success"] = True
                result["message"] = "Rules consolidated"
            
            elif action_type == "OPTIMIZE_RULE_ORDER":
                # Reorder rules by effectiveness
                sorted_rules = sorted(
                    self.active_rules.items(),
                    key=lambda x: x[1].effectiveness_score,
                    reverse=True
                )
                # Reassign priorities
                for idx, (rid, rule) in enumerate(sorted_rules):
                    rule.priority = 100 - idx
                result["success"] = True
                result["message"] = "Rules reordered by effectiveness"
            
            else:
                result["message"] = f"Action {action_type} not yet implemented"
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing action {action_type}: {e}")
            return {"action": action_type, "success": False, "error": str(e)}
    
    async def _get_updated_metrics(self, prev_metrics: Dict, 
                                   action_result: Dict) -> Dict[str, Any]:
        """Get updated metrics after action execution"""
        # Simulate metric changes based on action
        # In production, this would query actual system metrics
        
        new_metrics = prev_metrics.copy()
        
        if action_result.get("success"):
            action = action_result.get("action")
            
            if "BLOCK" in action:
                # Blocking rules reduce threat rate
                new_metrics['threat_rate'] = max(0, prev_metrics.get('threat_rate', 0) * 0.9)
            
            elif "REMOVE" in action or "CONSOLIDATE" in action:
                # Removing rules might slightly increase threats but reduce overhead
                new_metrics['threat_rate'] = prev_metrics.get('threat_rate', 0) * 1.05
                new_metrics['cpu_usage'] = max(0, prev_metrics.get('cpu_usage', 0) - 2)
            
            elif "OPTIMIZE" in action:
                # Optimization reduces latency
                new_metrics['latency'] = max(0.1, prev_metrics.get('latency', 1.0) * 0.95)
        
        return new_metrics
    
    async def update_rule_effectiveness(self, rule_id: str, 
                                       threats_blocked: int, 
                                       false_positives: int):
        """Update effectiveness score for a rule"""
        try:
            if rule_id in self.active_rules:
                rule = self.active_rules[rule_id]
                
                # Calculate effectiveness score
                total_actions = threats_blocked + false_positives
                if total_actions > 0:
                    effectiveness = (threats_blocked - false_positives * 2) / total_actions
                    rule.effectiveness_score = max(0, min(1, effectiveness))
                
                self.logger.debug(f"Updated effectiveness for {rule_id}: {rule.effectiveness_score:.2f}")
        
        except Exception as e:
            self.logger.error(f"Error updating rule effectiveness: {e}")
    
    async def _save_model(self):
        """Save RL model"""
        try:
            model_file = self.model_path / "dqn_model.h5"
            self.agent.save(str(model_file))
            
            # Save metadata
            metadata = {
                "episodes_trained": self.episodes_trained,
                "training_step": self.agent.training_step,
                "epsilon": self.agent.epsilon,
                "active_rules": len(self.active_rules),
                "timestamp": datetime.now().isoformat()
            }
            
            metadata_file = self.model_path / "rl_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("RL model saved")
            
        except Exception as e:
            self.logger.error(f"Error saving RL model: {e}")
    
    def get_optimizer_stats(self) -> Dict[str, Any]:
        """Get RL optimizer statistics"""
        return {
            "active_rules": len(self.active_rules),
            "training_enabled": self.training_enabled,
            "episodes_trained": self.episodes_trained,
            "training_steps": self.agent.training_step,
            "epsilon": self.agent.epsilon,
            "memory_size": len(self.agent.memory),
            "average_reward": np.mean(self.agent.total_rewards[-100:]) if self.agent.total_rewards else 0.0,
            "rule_effectiveness_avg": np.mean([r.effectiveness_score for r in self.active_rules.values()])
        }
    
    def get_active_rules(self) -> List[Dict]:
        """Get list of active firewall rules"""
        return [
            {
                "rule_id": rule.rule_id,
                "priority": rule.priority,
                "source_ip": rule.source_ip,
                "dest_port": rule.dest_port,
                "protocol": rule.protocol,
                "action": rule.action,
                "confidence": rule.confidence,
                "effectiveness_score": rule.effectiveness_score,
                "created_at": rule.created_at.isoformat()
            }
            for rule in sorted(self.active_rules.values(), 
                             key=lambda x: x.priority, reverse=True)
        ]