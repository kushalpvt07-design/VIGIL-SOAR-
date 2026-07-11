from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ThreatDossier(BaseModel):
    """
    The immutable shared state passed between the Auto-SOC agents.
    Every node reads from and writes to this exact schema.
    """
    # 1. Ingestion Data (Populated by the SIEM script)
    event_id: str = Field(default="", description="Unique identifier for the SIEM alert")
    raw_log: str = Field(default="", description="The raw unstructured network log string")
    
    # 2. Sentinel Triage Data (Populated by Sentinel Agent)
    threat_classification: str = Field(default="PENDING", description="e.g., BENIGN, SUSPICIOUS, MALICIOUS")
    severity_score: int = Field(default=0, description="1 to 100 scale of threat severity")
    target_user: Optional[str] = Field(default=None, description="The Active Directory user implicated")
    target_ip: Optional[str] = Field(default=None, description="The external IP address implicated")
    
    # 3. Forensics Data (Populated by Forensics Agent)
    forensic_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Results from database tool calls")
    is_compromise_confirmed: bool = Field(default=False, description="Did forensics confirm an actual breach?")
    
    # 4. Mitigation Data (Populated by Responder Agent)
    executed_actions: List[str] = Field(default_factory=list, description="List of defensive actions taken")
    resolution_status: str = Field(default="OPEN", description="OPEN, MITIGATED, or ESCALATED")
