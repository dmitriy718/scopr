"""
Scan Workflows Module - Automated multi-stage reconnaissance pipelines.
Allows users to create, save, and execute predefined scan sequences.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json
import uuid
from datetime import datetime


class StageType(Enum):
    ENDPOINT_SCAN = "endpoint_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    JS_EXTRACTION = "js_extraction"
    SECRETS_SCAN = "secrets_scan"
    SECURITY_HEADERS = "security_headers"
    PARAMETER_DISCOVERY = "parameter_discovery"
    TAKEOVER_CHECK = "takeover_check"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"


@dataclass
class WorkflowStage:
    stage_type: StageType
    name: str
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "stage_type": self.stage_type.value,
            "name": self.name,
            "enabled": self.enabled,
            "config": self.config
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'WorkflowStage':
        return cls(
            stage_type=StageType(data["stage_type"]),
            name=data["name"],
            enabled=data.get("enabled", True),
            config=data.get("config", {})
        )


@dataclass
class ScanWorkflow:
    id: str
    name: str
    description: str
    stages: List[WorkflowStage]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    is_preset: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "stages": [s.to_dict() for s in self.stages],
            "created_at": self.created_at,
            "is_preset": self.is_preset
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanWorkflow':
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            stages=[WorkflowStage.from_dict(s) for s in data["stages"]],
            created_at=data.get("created_at", datetime.now().isoformat()),
            is_preset=data.get("is_preset", False)
        )


@dataclass
class WorkflowExecution:
    id: str
    workflow_id: str
    domain: str
    status: str = "pending"
    current_stage: int = 0
    total_stages: int = 0
    stage_results: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "workflow_id": self.workflow_id,
            "domain": self.domain,
            "status": self.status,
            "current_stage": self.current_stage,
            "total_stages": self.total_stages,
            "stage_results": self.stage_results,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error
        }


class WorkflowManager:
    def __init__(self):
        self.workflows: Dict[str, ScanWorkflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self._load_presets()
    
    def _load_presets(self):
        presets = [
            ScanWorkflow(
                id="preset_quick_recon",
                name="Quick Recon",
                description="Fast scan with endpoint discovery and technology fingerprinting",
                stages=[
                    WorkflowStage(StageType.ENDPOINT_SCAN, "Endpoint Discovery", config={"wordlist": "directories", "recursive": False}),
                    WorkflowStage(StageType.TECHNOLOGY_FINGERPRINT, "Technology Detection"),
                    WorkflowStage(StageType.SECURITY_HEADERS, "Security Headers"),
                ],
                is_preset=True
            ),
            ScanWorkflow(
                id="preset_full_recon",
                name="Full Recon",
                description="Comprehensive scan including subdomains, JS parsing, and secrets detection",
                stages=[
                    WorkflowStage(StageType.SUBDOMAIN_ENUM, "Subdomain Enumeration"),
                    WorkflowStage(StageType.TAKEOVER_CHECK, "Takeover Detection"),
                    WorkflowStage(StageType.ENDPOINT_SCAN, "Endpoint Discovery", config={"wordlist": "all", "recursive": True, "recursive_depth": 2}),
                    WorkflowStage(StageType.TECHNOLOGY_FINGERPRINT, "Technology Detection"),
                    WorkflowStage(StageType.JS_EXTRACTION, "JS Endpoint Extraction"),
                    WorkflowStage(StageType.SECRETS_SCAN, "Secrets Detection"),
                    WorkflowStage(StageType.SECURITY_HEADERS, "Security Analysis"),
                ],
                is_preset=True
            ),
            ScanWorkflow(
                id="preset_api_recon",
                name="API Recon",
                description="Focused on API endpoints, parameters, and sensitive data exposure",
                stages=[
                    WorkflowStage(StageType.ENDPOINT_SCAN, "API Endpoint Discovery", config={"wordlist": "api", "recursive": False}),
                    WorkflowStage(StageType.JS_EXTRACTION, "JS API Extraction"),
                    WorkflowStage(StageType.PARAMETER_DISCOVERY, "Parameter Discovery"),
                    WorkflowStage(StageType.SECRETS_SCAN, "API Key Detection"),
                ],
                is_preset=True
            ),
            ScanWorkflow(
                id="preset_subdomain_takeover",
                name="Subdomain Takeover Hunt",
                description="Focus on finding subdomain takeover vulnerabilities",
                stages=[
                    WorkflowStage(StageType.SUBDOMAIN_ENUM, "Subdomain Enumeration"),
                    WorkflowStage(StageType.TAKEOVER_CHECK, "Takeover Detection"),
                ],
                is_preset=True
            ),
            ScanWorkflow(
                id="preset_secrets_hunt",
                name="Secrets Hunt",
                description="Deep scan for exposed secrets, API keys, and credentials",
                stages=[
                    WorkflowStage(StageType.ENDPOINT_SCAN, "Endpoint Discovery", config={"wordlist": "all", "recursive": True}),
                    WorkflowStage(StageType.JS_EXTRACTION, "JS Parsing"),
                    WorkflowStage(StageType.SECRETS_SCAN, "Secrets Detection"),
                ],
                is_preset=True
            ),
        ]
        
        for preset in presets:
            self.workflows[preset.id] = preset
    
    def get_all_workflows(self) -> List[Dict]:
        return [w.to_dict() for w in self.workflows.values()]
    
    def get_presets(self) -> List[Dict]:
        return [w.to_dict() for w in self.workflows.values() if w.is_preset]
    
    def get_custom_workflows(self) -> List[Dict]:
        return [w.to_dict() for w in self.workflows.values() if not w.is_preset]
    
    def get_workflow(self, workflow_id: str) -> Optional[ScanWorkflow]:
        return self.workflows.get(workflow_id)
    
    def create_workflow(self, name: str, description: str, stages: List[Dict]) -> ScanWorkflow:
        workflow_id = f"custom_{str(uuid.uuid4())[:8]}"
        workflow = ScanWorkflow(
            id=workflow_id,
            name=name,
            description=description,
            stages=[WorkflowStage.from_dict(s) for s in stages],
            is_preset=False
        )
        self.workflows[workflow_id] = workflow
        return workflow
    
    def delete_workflow(self, workflow_id: str) -> bool:
        if workflow_id in self.workflows and not self.workflows[workflow_id].is_preset:
            del self.workflows[workflow_id]
            return True
        return False
    
    def create_execution(self, workflow_id: str, domain: str) -> Optional[WorkflowExecution]:
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return None
        
        enabled_stages = [s for s in workflow.stages if s.enabled]
        execution = WorkflowExecution(
            id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            domain=domain,
            total_stages=len(enabled_stages)
        )
        self.executions[execution.id] = execution
        return execution
    
    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        return self.executions.get(execution_id)
    
    def update_execution(self, execution_id: str, **kwargs) -> Optional[WorkflowExecution]:
        execution = self.executions.get(execution_id)
        if execution:
            for key, value in kwargs.items():
                if hasattr(execution, key):
                    setattr(execution, key, value)
        return execution
    
    def get_stage_options(self, stage_type: StageType) -> Dict:
        stage_info = {
            StageType.ENDPOINT_SCAN: {
                "name": "Endpoint Discovery",
                "description": "Scan for accessible endpoints and directories",
                "icon": "bi-folder-fill",
                "color": "primary",
                "configurable": True,
                "config_options": {
                    "wordlist": ["all", "directories", "api", "hidden", "files", "backup"],
                    "recursive": True,
                    "recursive_depth": [1, 2, 3]
                }
            },
            StageType.SUBDOMAIN_ENUM: {
                "name": "Subdomain Enumeration",
                "description": "Discover subdomains via DNS queries",
                "icon": "bi-diagram-3-fill",
                "color": "info",
                "configurable": False
            },
            StageType.JS_EXTRACTION: {
                "name": "JS Endpoint Extraction",
                "description": "Parse JavaScript files for hidden API endpoints",
                "icon": "bi-file-code-fill",
                "color": "warning",
                "configurable": False
            },
            StageType.SECRETS_SCAN: {
                "name": "Secrets Detection",
                "description": "Scan for exposed API keys, tokens, and credentials",
                "icon": "bi-key-fill",
                "color": "danger",
                "configurable": False
            },
            StageType.SECURITY_HEADERS: {
                "name": "Security Header Analysis",
                "description": "Analyze HTTP security headers and generate grades",
                "icon": "bi-shield-fill-check",
                "color": "success",
                "configurable": False
            },
            StageType.PARAMETER_DISCOVERY: {
                "name": "Parameter Discovery",
                "description": "Test URLs for hidden query parameters",
                "icon": "bi-input-cursor-text",
                "color": "purple",
                "configurable": False
            },
            StageType.TAKEOVER_CHECK: {
                "name": "Subdomain Takeover",
                "description": "Check for dangling DNS and takeover vulnerabilities",
                "icon": "bi-exclamation-triangle-fill",
                "color": "danger",
                "configurable": False
            },
            StageType.TECHNOLOGY_FINGERPRINT: {
                "name": "Technology Fingerprinting",
                "description": "Detect CMS, frameworks, and server technologies",
                "icon": "bi-cpu-fill",
                "color": "info",
                "configurable": False
            }
        }
        return stage_info.get(stage_type, {})


workflow_manager = WorkflowManager()
