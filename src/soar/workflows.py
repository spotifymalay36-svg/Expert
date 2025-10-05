"""
SOAR (Security Orchestration, Automation and Response) Workflows
Automated incident response and threat mitigation
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import uuid

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger, security_logger

class WorkflowStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    QUARANTINE_USER = "QUARANTINE_USER"
    NOTIFY_ADMIN = "NOTIFY_ADMIN"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    UPDATE_THREAT_INTEL = "UPDATE_THREAT_INTEL"
    GENERATE_REPORT = "GENERATE_REPORT"
    ISOLATE_SYSTEM = "ISOLATE_SYSTEM"
    RESET_PASSWORD = "RESET_PASSWORD"

@dataclass
class WorkflowAction:
    """Individual workflow action"""
    id: str
    action_type: ActionType
    parameters: Dict[str, Any]
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3
    status: WorkflowStatus = WorkflowStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

@dataclass
class IncidentContext:
    """Context information for incident response"""
    incident_id: str
    threat_type: str
    severity: ThreatLevel
    source_ip: str
    target_ip: str
    user_id: Optional[str]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class Workflow:
    """SOAR workflow definition"""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    actions: List[WorkflowAction]
    status: WorkflowStatus = WorkflowStatus.PENDING
    context: Optional[IncidentContext] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_log: List[Dict[str, Any]] = field(default_factory=list)

class SOAREngine:
    """Security Orchestration, Automation and Response Engine"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Workflow storage
        self.workflows: Dict[str, Workflow] = {}
        self.workflow_templates: Dict[str, Dict] = {}
        
        # Action executors
        self.action_executors: Dict[ActionType, Callable] = {
            ActionType.BLOCK_IP: self._execute_block_ip,
            ActionType.QUARANTINE_USER: self._execute_quarantine_user,
            ActionType.NOTIFY_ADMIN: self._execute_notify_admin,
            ActionType.COLLECT_EVIDENCE: self._execute_collect_evidence,
            ActionType.UPDATE_THREAT_INTEL: self._execute_update_threat_intel,
            ActionType.GENERATE_REPORT: self._execute_generate_report,
            ActionType.ISOLATE_SYSTEM: self._execute_isolate_system,
            ActionType.RESET_PASSWORD: self._execute_reset_password
        }
        
        # Running workflows
        self.running_workflows: Dict[str, asyncio.Task] = {}
        
        # Statistics
        self.stats = {
            'workflows_executed': 0,
            'workflows_successful': 0,
            'workflows_failed': 0,
            'actions_executed': 0,
            'average_execution_time': 0.0
        }
        
        # Initialize default workflow templates
        self._initialize_workflow_templates()
        
        self.logger.info("SOAR Engine initialized")
    
    def _initialize_workflow_templates(self):
        """Initialize default workflow templates"""
        
        # High Severity Threat Response
        self.workflow_templates['high_severity_threat'] = {
            'name': 'High Severity Threat Response',
            'description': 'Automated response for high severity threats',
            'trigger_conditions': {
                'severity': ['HIGH', 'CRITICAL'],
                'threat_types': ['SQL_INJECTION', 'COMMAND_INJECTION', 'MALWARE']
            },
            'actions': [
                {
                    'action_type': ActionType.BLOCK_IP,
                    'parameters': {'duration_hours': 24},
                    'timeout_seconds': 30
                },
                {
                    'action_type': ActionType.COLLECT_EVIDENCE,
                    'parameters': {'include_packets': True, 'include_logs': True},
                    'timeout_seconds': 120
                },
                {
                    'action_type': ActionType.NOTIFY_ADMIN,
                    'parameters': {'urgency': 'HIGH', 'channels': ['email', 'slack']},
                    'timeout_seconds': 60
                },
                {
                    'action_type': ActionType.UPDATE_THREAT_INTEL,
                    'parameters': {'confidence': 0.9},
                    'timeout_seconds': 30
                }
            ]
        }
        
        # Anomaly Detection Response
        self.workflow_templates['anomaly_response'] = {
            'name': 'Anomaly Detection Response',
            'description': 'Response workflow for detected anomalies',
            'trigger_conditions': {
                'threat_types': ['ANOMALY'],
                'anomaly_score': {'min': 0.7}
            },
            'actions': [
                {
                    'action_type': ActionType.COLLECT_EVIDENCE,
                    'parameters': {'include_behavior': True},
                    'timeout_seconds': 60
                },
                {
                    'action_type': ActionType.QUARANTINE_USER,
                    'parameters': {'duration_hours': 2},
                    'timeout_seconds': 30
                },
                {
                    'action_type': ActionType.NOTIFY_ADMIN,
                    'parameters': {'urgency': 'MEDIUM'},
                    'timeout_seconds': 60
                }
            ]
        }
        
        # Brute Force Attack Response
        self.workflow_templates['brute_force_response'] = {
            'name': 'Brute Force Attack Response',
            'description': 'Response to brute force authentication attempts',
            'trigger_conditions': {
                'threat_types': ['BRUTE_FORCE'],
                'failed_attempts': {'min': 5}
            },
            'actions': [
                {
                    'action_type': ActionType.BLOCK_IP,
                    'parameters': {'duration_hours': 1},
                    'timeout_seconds': 30
                },
                {
                    'action_type': ActionType.RESET_PASSWORD,
                    'parameters': {'force_reset': True},
                    'timeout_seconds': 60
                },
                {
                    'action_type': ActionType.NOTIFY_ADMIN,
                    'parameters': {'urgency': 'MEDIUM'},
                    'timeout_seconds': 30
                }
            ]
        }
        
        # Malware Detection Response
        self.workflow_templates['malware_response'] = {
            'name': 'Malware Detection Response',
            'description': 'Comprehensive malware incident response',
            'trigger_conditions': {
                'threat_types': ['MALWARE'],
                'severity': ['HIGH', 'CRITICAL']
            },
            'actions': [
                {
                    'action_type': ActionType.ISOLATE_SYSTEM,
                    'parameters': {'isolation_level': 'FULL'},
                    'timeout_seconds': 60
                },
                {
                    'action_type': ActionType.COLLECT_EVIDENCE,
                    'parameters': {'include_memory_dump': True, 'include_network_logs': True},
                    'timeout_seconds': 300
                },
                {
                    'action_type': ActionType.NOTIFY_ADMIN,
                    'parameters': {'urgency': 'CRITICAL', 'escalate': True},
                    'timeout_seconds': 30
                },
                {
                    'action_type': ActionType.UPDATE_THREAT_INTEL,
                    'parameters': {'confidence': 0.95, 'share_indicators': True},
                    'timeout_seconds': 60
                },
                {
                    'action_type': ActionType.GENERATE_REPORT,
                    'parameters': {'include_timeline': True, 'include_iocs': True},
                    'timeout_seconds': 120
                }
            ]
        }
    
    async def trigger_workflow(self, incident_context: IncidentContext) -> Optional[str]:
        """Trigger appropriate workflow based on incident context"""
        try:
            # Find matching workflow template
            template = self._find_matching_template(incident_context)
            
            if not template:
                self.logger.warning(f"No matching workflow template for incident {incident_context.incident_id}")
                return None
            
            # Create workflow from template
            workflow = self._create_workflow_from_template(template, incident_context)
            
            # Store workflow
            self.workflows[workflow.id] = workflow
            
            # Start workflow execution
            task = asyncio.create_task(self._execute_workflow(workflow))
            self.running_workflows[workflow.id] = task
            
            self.logger.info(f"Started workflow {workflow.id} for incident {incident_context.incident_id}")
            
            # Log security event
            security_logger.log_system_event(
                "workflow_triggered",
                f"SOAR workflow {workflow.name} triggered for incident {incident_context.incident_id}",
                "INFO",
                "SOAR",
                {
                    "workflow_id": workflow.id,
                    "incident_id": incident_context.incident_id,
                    "threat_type": incident_context.threat_type,
                    "severity": incident_context.severity.value
                }
            )
            
            return workflow.id
            
        except Exception as e:
            self.logger.error(f"Error triggering workflow: {e}")
            return None
    
    def _find_matching_template(self, context: IncidentContext) -> Optional[Dict]:
        """Find workflow template that matches incident context"""
        try:
            for template_name, template in self.workflow_templates.items():
                conditions = template['trigger_conditions']
                
                # Check severity
                if 'severity' in conditions:
                    if context.severity.value not in conditions['severity']:
                        continue
                
                # Check threat types
                if 'threat_types' in conditions:
                    if context.threat_type not in conditions['threat_types']:
                        continue
                
                # Check anomaly score
                if 'anomaly_score' in conditions:
                    score_conditions = conditions['anomaly_score']
                    if 'min' in score_conditions and context.confidence < score_conditions['min']:
                        continue
                    if 'max' in score_conditions and context.confidence > score_conditions['max']:
                        continue
                
                # Check failed attempts (for brute force)
                if 'failed_attempts' in conditions:
                    failed_attempts = context.evidence.get('failed_attempts', 0)
                    attempt_conditions = conditions['failed_attempts']
                    if 'min' in attempt_conditions and failed_attempts < attempt_conditions['min']:
                        continue
                
                # All conditions matched
                return template
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding matching template: {e}")
            return None
    
    def _create_workflow_from_template(self, template: Dict, context: IncidentContext) -> Workflow:
        """Create workflow instance from template"""
        workflow_id = str(uuid.uuid4())
        
        # Create actions from template
        actions = []
        for action_template in template['actions']:
            action_id = str(uuid.uuid4())
            
            action = WorkflowAction(
                id=action_id,
                action_type=ActionType(action_template['action_type']),
                parameters=action_template.get('parameters', {}),
                timeout_seconds=action_template.get('timeout_seconds', 300),
                max_retries=action_template.get('max_retries', 3)
            )
            
            # Inject context parameters
            action.parameters.update({
                'incident_id': context.incident_id,
                'source_ip': context.source_ip,
                'target_ip': context.target_ip,
                'user_id': context.user_id,
                'threat_type': context.threat_type,
                'severity': context.severity.value
            })
            
            actions.append(action)
        
        workflow = Workflow(
            id=workflow_id,
            name=template['name'],
            description=template['description'],
            trigger_conditions=template['trigger_conditions'],
            actions=actions,
            context=context
        )
        
        return workflow
    
    async def _execute_workflow(self, workflow: Workflow):
        """Execute workflow actions sequentially"""
        try:
            workflow.status = WorkflowStatus.RUNNING
            workflow.started_at = datetime.now()
            
            self.logger.info(f"Executing workflow {workflow.id}: {workflow.name}")
            
            # Execute actions sequentially
            for action in workflow.actions:
                try:
                    await self._execute_action(action, workflow)
                    
                    if action.status == WorkflowStatus.FAILED and action.retry_count >= action.max_retries:
                        # Critical action failed, abort workflow
                        workflow.status = WorkflowStatus.FAILED
                        self._log_workflow_event(workflow, f"Workflow failed due to action {action.id} failure")
                        break
                        
                except Exception as e:
                    self.logger.error(f"Error executing action {action.id}: {e}")
                    action.status = WorkflowStatus.FAILED
                    action.error_message = str(e)
                    
                    # Continue with next action unless it's critical
                    if action.action_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_SYSTEM]:
                        workflow.status = WorkflowStatus.FAILED
                        break
            
            # Complete workflow
            if workflow.status == WorkflowStatus.RUNNING:
                workflow.status = WorkflowStatus.COMPLETED
                self.stats['workflows_successful'] += 1
            else:
                self.stats['workflows_failed'] += 1
            
            workflow.completed_at = datetime.now()
            execution_time = (workflow.completed_at - workflow.started_at).total_seconds()
            
            # Update statistics
            self.stats['workflows_executed'] += 1
            self.stats['average_execution_time'] = (
                (self.stats['average_execution_time'] * (self.stats['workflows_executed'] - 1) + execution_time) /
                self.stats['workflows_executed']
            )
            
            self._log_workflow_event(workflow, f"Workflow completed with status: {workflow.status.value}")
            
            # Clean up
            if workflow.id in self.running_workflows:
                del self.running_workflows[workflow.id]
            
        except Exception as e:
            self.logger.error(f"Error executing workflow {workflow.id}: {e}")
            workflow.status = WorkflowStatus.FAILED
            workflow.completed_at = datetime.now()
            self.stats['workflows_failed'] += 1
    
    async def _execute_action(self, action: WorkflowAction, workflow: Workflow):
        """Execute individual workflow action"""
        try:
            action.status = WorkflowStatus.RUNNING
            action.started_at = datetime.now()
            
            self.logger.info(f"Executing action {action.id}: {action.action_type.value}")
            
            # Get action executor
            executor = self.action_executors.get(action.action_type)
            if not executor:
                raise Exception(f"No executor found for action type {action.action_type}")
            
            # Execute with timeout
            try:
                result = await asyncio.wait_for(
                    executor(action, workflow),
                    timeout=action.timeout_seconds
                )
                
                action.result = result
                action.status = WorkflowStatus.COMPLETED
                action.completed_at = datetime.now()
                
                self.stats['actions_executed'] += 1
                
                self._log_workflow_event(workflow, f"Action {action.action_type.value} completed successfully")
                
            except asyncio.TimeoutError:
                raise Exception(f"Action {action.action_type} timed out after {action.timeout_seconds} seconds")
            
        except Exception as e:
            action.error_message = str(e)
            action.retry_count += 1
            
            if action.retry_count <= action.max_retries:
                self.logger.warning(f"Action {action.id} failed, retrying ({action.retry_count}/{action.max_retries}): {e}")
                await asyncio.sleep(2 ** action.retry_count)  # Exponential backoff
                await self._execute_action(action, workflow)  # Retry
            else:
                action.status = WorkflowStatus.FAILED
                action.completed_at = datetime.now()
                self.logger.error(f"Action {action.id} failed after {action.max_retries} retries: {e}")
                self._log_workflow_event(workflow, f"Action {action.action_type.value} failed: {e}")
    
    # Action Executors
    async def _execute_block_ip(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute IP blocking action"""
        try:
            source_ip = action.parameters.get('source_ip')
            duration_hours = action.parameters.get('duration_hours', 24)
            
            if not source_ip:
                raise Exception("No source IP provided for blocking")
            
            # This would integrate with firewall/network equipment
            # For now, we'll simulate the action
            
            self.logger.info(f"Blocking IP {source_ip} for {duration_hours} hours")
            
            # Simulate network call delay
            await asyncio.sleep(1)
            
            return {
                'action': 'IP_BLOCKED',
                'ip_address': source_ip,
                'duration_hours': duration_hours,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to block IP: {e}")
    
    async def _execute_quarantine_user(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute user quarantine action"""
        try:
            user_id = action.parameters.get('user_id')
            duration_hours = action.parameters.get('duration_hours', 2)
            
            if not user_id:
                raise Exception("No user ID provided for quarantine")
            
            self.logger.info(f"Quarantining user {user_id} for {duration_hours} hours")
            
            # Simulate quarantine action
            await asyncio.sleep(0.5)
            
            return {
                'action': 'USER_QUARANTINED',
                'user_id': user_id,
                'duration_hours': duration_hours,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to quarantine user: {e}")
    
    async def _execute_notify_admin(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute admin notification action"""
        try:
            urgency = action.parameters.get('urgency', 'MEDIUM')
            channels = action.parameters.get('channels', ['email'])
            escalate = action.parameters.get('escalate', False)
            
            incident_id = action.parameters.get('incident_id')
            threat_type = action.parameters.get('threat_type')
            
            self.logger.info(f"Notifying admin about incident {incident_id} via {channels}")
            
            # Simulate notification
            await asyncio.sleep(0.3)
            
            # Log notification
            security_logger.log_system_event(
                "admin_notification",
                f"Admin notified about {threat_type} incident {incident_id}",
                urgency,
                "SOAR",
                {
                    "incident_id": incident_id,
                    "urgency": urgency,
                    "channels": channels,
                    "escalated": escalate
                }
            )
            
            return {
                'action': 'ADMIN_NOTIFIED',
                'urgency': urgency,
                'channels': channels,
                'escalated': escalate,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to notify admin: {e}")
    
    async def _execute_collect_evidence(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute evidence collection action"""
        try:
            include_packets = action.parameters.get('include_packets', False)
            include_logs = action.parameters.get('include_logs', True)
            include_behavior = action.parameters.get('include_behavior', False)
            include_memory_dump = action.parameters.get('include_memory_dump', False)
            
            incident_id = action.parameters.get('incident_id')
            
            self.logger.info(f"Collecting evidence for incident {incident_id}")
            
            # Simulate evidence collection
            await asyncio.sleep(2)
            
            evidence = {
                'incident_id': incident_id,
                'collection_timestamp': datetime.now().isoformat(),
                'evidence_types': []
            }
            
            if include_packets:
                evidence['evidence_types'].append('network_packets')
                evidence['packet_capture_file'] = f'/evidence/{incident_id}/packets.pcap'
            
            if include_logs:
                evidence['evidence_types'].append('system_logs')
                evidence['log_files'] = [f'/evidence/{incident_id}/system.log', f'/evidence/{incident_id}/security.log']
            
            if include_behavior:
                evidence['evidence_types'].append('behavioral_data')
                evidence['behavior_analysis'] = f'/evidence/{incident_id}/behavior.json'
            
            if include_memory_dump:
                evidence['evidence_types'].append('memory_dump')
                evidence['memory_dump_file'] = f'/evidence/{incident_id}/memory.dump'
            
            return {
                'action': 'EVIDENCE_COLLECTED',
                'evidence': evidence
            }
            
        except Exception as e:
            raise Exception(f"Failed to collect evidence: {e}")
    
    async def _execute_update_threat_intel(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute threat intelligence update action"""
        try:
            confidence = action.parameters.get('confidence', 0.8)
            share_indicators = action.parameters.get('share_indicators', False)
            
            source_ip = action.parameters.get('source_ip')
            threat_type = action.parameters.get('threat_type')
            
            self.logger.info(f"Updating threat intelligence with IOC {source_ip}")
            
            # Simulate threat intel update
            await asyncio.sleep(1)
            
            return {
                'action': 'THREAT_INTEL_UPDATED',
                'ioc': source_ip,
                'threat_type': threat_type,
                'confidence': confidence,
                'shared': share_indicators,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to update threat intelligence: {e}")
    
    async def _execute_generate_report(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute report generation action"""
        try:
            include_timeline = action.parameters.get('include_timeline', True)
            include_iocs = action.parameters.get('include_iocs', True)
            
            incident_id = action.parameters.get('incident_id')
            
            self.logger.info(f"Generating incident report for {incident_id}")
            
            # Simulate report generation
            await asyncio.sleep(3)
            
            report = {
                'incident_id': incident_id,
                'report_id': str(uuid.uuid4()),
                'generated_at': datetime.now().isoformat(),
                'report_file': f'/reports/{incident_id}_report.pdf',
                'sections': []
            }
            
            if include_timeline:
                report['sections'].append('timeline')
            
            if include_iocs:
                report['sections'].append('indicators_of_compromise')
            
            return {
                'action': 'REPORT_GENERATED',
                'report': report
            }
            
        except Exception as e:
            raise Exception(f"Failed to generate report: {e}")
    
    async def _execute_isolate_system(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute system isolation action"""
        try:
            isolation_level = action.parameters.get('isolation_level', 'PARTIAL')
            target_ip = action.parameters.get('target_ip')
            
            if not target_ip:
                raise Exception("No target IP provided for isolation")
            
            self.logger.info(f"Isolating system {target_ip} with level {isolation_level}")
            
            # Simulate system isolation
            await asyncio.sleep(2)
            
            return {
                'action': 'SYSTEM_ISOLATED',
                'target_ip': target_ip,
                'isolation_level': isolation_level,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to isolate system: {e}")
    
    async def _execute_reset_password(self, action: WorkflowAction, workflow: Workflow) -> Dict[str, Any]:
        """Execute password reset action"""
        try:
            user_id = action.parameters.get('user_id')
            force_reset = action.parameters.get('force_reset', True)
            
            if not user_id:
                raise Exception("No user ID provided for password reset")
            
            self.logger.info(f"Resetting password for user {user_id}")
            
            # Simulate password reset
            await asyncio.sleep(1)
            
            return {
                'action': 'PASSWORD_RESET',
                'user_id': user_id,
                'forced': force_reset,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to reset password: {e}")
    
    def _log_workflow_event(self, workflow: Workflow, message: str):
        """Log workflow execution event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'workflow_status': workflow.status.value
        }
        
        workflow.execution_log.append(event)
        self.logger.info(f"Workflow {workflow.id}: {message}")
    
    # Management methods
    async def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel running workflow"""
        try:
            if workflow_id in self.running_workflows:
                task = self.running_workflows[workflow_id]
                task.cancel()
                
                workflow = self.workflows.get(workflow_id)
                if workflow:
                    workflow.status = WorkflowStatus.CANCELLED
                    workflow.completed_at = datetime.now()
                
                del self.running_workflows[workflow_id]
                
                self.logger.info(f"Cancelled workflow {workflow_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error cancelling workflow {workflow_id}: {e}")
            return False
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status and progress"""
        try:
            workflow = self.workflows.get(workflow_id)
            if not workflow:
                return None
            
            # Calculate progress
            total_actions = len(workflow.actions)
            completed_actions = sum(1 for action in workflow.actions if action.status == WorkflowStatus.COMPLETED)
            progress_percent = (completed_actions / total_actions * 100) if total_actions > 0 else 0
            
            return {
                'workflow_id': workflow.id,
                'name': workflow.name,
                'status': workflow.status.value,
                'progress_percent': progress_percent,
                'total_actions': total_actions,
                'completed_actions': completed_actions,
                'created_at': workflow.created_at.isoformat(),
                'started_at': workflow.started_at.isoformat() if workflow.started_at else None,
                'completed_at': workflow.completed_at.isoformat() if workflow.completed_at else None,
                'execution_log': workflow.execution_log[-10:]  # Last 10 events
            }
            
        except Exception as e:
            self.logger.error(f"Error getting workflow status: {e}")
            return None
    
    def get_soar_statistics(self) -> Dict[str, Any]:
        """Get SOAR engine statistics"""
        return {
            'total_workflows': len(self.workflows),
            'running_workflows': len(self.running_workflows),
            'workflows_executed': self.stats['workflows_executed'],
            'workflows_successful': self.stats['workflows_successful'],
            'workflows_failed': self.stats['workflows_failed'],
            'success_rate': (self.stats['workflows_successful'] / max(self.stats['workflows_executed'], 1)) * 100,
            'actions_executed': self.stats['actions_executed'],
            'average_execution_time': self.stats['average_execution_time'],
            'available_templates': list(self.workflow_templates.keys())
        }