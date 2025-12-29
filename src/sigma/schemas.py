"""Pydantic schemas for Sigma Translator API."""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# Enums
class ConversionTypeEnum(str, Enum):
    SIGMA_TO_SPL = "sigma_to_spl"
    SPL_TO_SIGMA = "spl_to_sigma"
    TEXT_TO_SIGMA = "text_to_sigma"


class MappingStatusEnum(str, Enum):
    OK = "ok"
    MISSING = "missing"
    SUGGESTED = "suggested"


# Profile Schemas
class ProfileBase(BaseModel):
    name: str
    description: Optional[str] = None
    index_name: str = "*"
    sourcetype: Optional[str] = None
    cim_enabled: bool = False
    macros: Optional[Dict[str, str]] = None


class ProfileCreate(ProfileBase):
    pass


class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    index_name: Optional[str] = None
    sourcetype: Optional[str] = None
    cim_enabled: Optional[bool] = None
    is_default: Optional[bool] = None
    macros: Optional[Dict[str, str]] = None


class ProfileResponse(ProfileBase):
    id: int
    is_default: bool
    created_at: datetime
    updated_at: datetime
    mapping_count: int = 0

    class Config:
        from_attributes = True


# Field Mapping Schemas
class FieldMappingBase(BaseModel):
    sigma_field: str
    target_field: str
    status: MappingStatusEnum = MappingStatusEnum.OK
    category: Optional[str] = None
    notes: Optional[str] = None


class FieldMappingCreate(FieldMappingBase):
    profile_id: int


class FieldMappingUpdate(BaseModel):
    target_field: Optional[str] = None
    status: Optional[MappingStatusEnum] = None
    notes: Optional[str] = None


class FieldMappingResponse(FieldMappingBase):
    id: int
    profile_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BulkMappingImport(BaseModel):
    profile_id: int
    mappings: List[FieldMappingBase]


# Conversion Schemas
class ConvertSigmaRequest(BaseModel):
    sigma_yaml: str
    profile_id: Optional[int] = None
    cim_override: Optional[bool] = None
    index_override: Optional[str] = None
    sourcetype_override: Optional[str] = None
    time_range: Optional[str] = None


class ConvertSPLRequest(BaseModel):
    spl_query: str
    title: Optional[str] = "Custom Detection Rule"
    level: str = "medium"
    status: str = "experimental"
    author: Optional[str] = None
    description: Optional[str] = None


class DescribeRequest(BaseModel):
    description: str
    log_source: Optional[str] = None
    level: str = "medium"
    include_false_positives: bool = False
    include_attack_techniques: bool = False


class RequiredLogSource(BaseModel):
    name: str
    description: str
    windows_channel: Optional[str] = None
    splunk_sourcetype: Optional[str] = None
    event_ids: List[Dict[str, Any]] = []
    setup_instructions: List[str] = []


class PrerequisiteInfo(BaseModel):
    log_source: Dict[str, Optional[str]]
    required_logs: List[RequiredLogSource] = []
    event_ids: List[Dict[str, Any]] = []
    channels: List[str] = []
    configuration: List[str] = []


class GapItem(BaseModel):
    field: str
    location: str
    impact: str
    suggestions: List[str]


class HealthCheck(BaseModel):
    name: str
    description: str
    query: str


class MappingResult(BaseModel):
    sigma_field: str
    target_field: Optional[str]
    status: MappingStatusEnum


class ConversionResponse(BaseModel):
    id: Optional[int] = None
    name: str
    spl: str
    sigma_yaml: Optional[str] = None
    prerequisites: PrerequisiteInfo
    mappings: List[MappingResult]
    gaps: List[GapItem]
    health_checks: List[HealthCheck]
    correlation_notes: Optional[str] = None
    llm_used: bool = False


class ConversionHistoryItem(BaseModel):
    id: int
    name: str
    conversion_type: ConversionTypeEnum
    profile_name: Optional[str] = None
    input_preview: str
    output_preview: str
    created_at: datetime

    class Config:
        from_attributes = True


class ConversionDetail(BaseModel):
    id: int
    name: str
    conversion_type: ConversionTypeEnum
    profile_id: Optional[int]
    profile_name: Optional[str] = None
    input_content: str
    output_sigma: Optional[str]
    output_spl: Optional[str]
    prerequisites: Optional[Dict[str, Any]]
    gap_analysis: Optional[List[Dict[str, Any]]]
    health_checks: Optional[List[Dict[str, Any]]]
    correlation_notes: Optional[str]
    llm_used: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Sigma Repository Schemas
class SigmaRuleInfo(BaseModel):
    path: str
    filename: str
    title: str
    status: Optional[str] = None
    level: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = []
    description: Optional[str] = None


class SigmaRepoResponse(BaseModel):
    available: bool
    path: str
    rule_count: int


class SigmaRuleContent(BaseModel):
    path: str
    content: str
    parsed: Dict[str, Any]


# Export all schemas
__all__ = [
    "ConversionTypeEnum",
    "MappingStatusEnum",
    "ProfileBase",
    "ProfileCreate",
    "ProfileUpdate",
    "ProfileResponse",
    "FieldMappingBase",
    "FieldMappingCreate",
    "FieldMappingUpdate",
    "FieldMappingResponse",
    "BulkMappingImport",
    "ConvertSigmaRequest",
    "ConvertSPLRequest",
    "DescribeRequest",
    "RequiredLogSource",
    "PrerequisiteInfo",
    "GapItem",
    "HealthCheck",
    "MappingResult",
    "ConversionResponse",
    "ConversionHistoryItem",
    "ConversionDetail",
    "SigmaRuleInfo",
    "SigmaRepoResponse",
    "SigmaRuleContent",
]
