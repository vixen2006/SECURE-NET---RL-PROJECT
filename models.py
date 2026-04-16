from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


Action = None
Observation = None
Reward = None


class ActionType(str, Enum):
    QUERY_LOGS = "query_logs"
    ANALYZE_PROCESS = "analyze_process"
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    THREAT_INTEL = "threat_intel"
    QUARANTINE_PROCESS = "quarantine_process"


class SecureNetAction(BaseModel):
    action_type: ActionType = Field(..., description="Action to execute.")
    target_node: Optional[str] = Field(None)
    timeframe: Optional[str] = Field(None)
    ip_address: Optional[str] = Field(None)
    process_name: Optional[str] = Field(None)
    ioc: Optional[str] = Field(None)


class SecureNetObservation(BaseModel):
    result: str = Field(..., description="Action result text.")
    success: bool = Field(...)
    echoed_message: str = Field("", description="Short planner-facing summary.")
    available_nodes: List[str] = Field(default_factory=list)
    blocked_iocs: List[str] = Field(default_factory=list)
    isolated_hosts: List[str] = Field(default_factory=list)
    step_index: int = Field(0)
    max_steps: int = Field(0)


class SecureNetReward(BaseModel):
    value: float = Field(..., ge=0.0, le=1.0, description="Final task score in [0,1].")
    partial_score: float = Field(0.0, ge=0.0, le=1.0)
    step_reward: float = Field(0.0)
    reason: str = Field("")


class StepResult(BaseModel):
    observation: SecureNetObservation
    reward: SecureNetReward
    done: bool = Field(False)
    info: Dict[str, Any] = Field(default_factory=dict)


Action = SecureNetAction
Observation = SecureNetObservation
Reward = SecureNetReward
