"""Database models for Sigma Translator module."""
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import json
from dataclasses import dataclass, field


class ConversionType(str, Enum):
    SIGMA_TO_SPL = "sigma_to_spl"
    SPL_TO_SIGMA = "spl_to_sigma"
    TEXT_TO_SIGMA = "text_to_sigma"


class MappingStatus(str, Enum):
    OK = "ok"
    MISSING = "missing"
    SUGGESTED = "suggested"


@dataclass
class Profile:
    """Profile for Sigma to SPL conversion settings."""
    id: Optional[int] = None
    name: str = ""
    description: Optional[str] = None
    index_name: str = "*"
    sourcetype: Optional[str] = None
    cim_enabled: bool = False
    is_default: bool = False
    macros: Optional[str] = None  # JSON string
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def get_macros(self) -> dict:
        if self.macros:
            return json.loads(self.macros)
        return {}

    def set_macros(self, macros: dict):
        self.macros = json.dumps(macros)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "index_name": self.index_name,
            "sourcetype": self.sourcetype,
            "cim_enabled": self.cim_enabled,
            "is_default": self.is_default,
            "macros": self.get_macros(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class FieldMapping:
    """Field mapping for Sigma to Splunk field conversion."""
    id: Optional[int] = None
    profile_id: int = 0
    sigma_field: str = ""
    target_field: str = ""
    status: MappingStatus = MappingStatus.OK
    category: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "profile_id": self.profile_id,
            "sigma_field": self.sigma_field,
            "target_field": self.target_field,
            "status": self.status.value if isinstance(self.status, MappingStatus) else self.status,
            "category": self.category,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class SigmaConversion:
    """Conversion history entry."""
    id: Optional[int] = None
    name: str = ""
    conversion_type: ConversionType = ConversionType.SIGMA_TO_SPL
    profile_id: Optional[int] = None
    input_content: str = ""  # Original input (Sigma YAML, SPL, or text)
    output_sigma: Optional[str] = None
    output_spl: Optional[str] = None
    prerequisites: Optional[str] = None  # JSON string
    gap_analysis: Optional[str] = None  # JSON string
    health_checks: Optional[str] = None  # JSON string
    correlation_notes: Optional[str] = None
    llm_used: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)

    def get_prerequisites(self) -> dict:
        if self.prerequisites:
            return json.loads(self.prerequisites)
        return {}

    def get_gap_analysis(self) -> list:
        if self.gap_analysis:
            return json.loads(self.gap_analysis)
        return []

    def get_health_checks(self) -> list:
        if self.health_checks:
            return json.loads(self.health_checks)
        return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "conversion_type": self.conversion_type.value if isinstance(self.conversion_type, ConversionType) else self.conversion_type,
            "profile_id": self.profile_id,
            "input_content": self.input_content,
            "output_sigma": self.output_sigma,
            "output_spl": self.output_spl,
            "prerequisites": self.get_prerequisites(),
            "gap_analysis": self.get_gap_analysis(),
            "health_checks": self.get_health_checks(),
            "correlation_notes": self.correlation_notes,
            "llm_used": self.llm_used,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class SigmaSetting:
    """Application setting."""
    id: Optional[int] = None
    key: str = ""
    value: str = ""
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class SysmonConfig:
    """Sysmon configuration with enabled Event IDs and fields."""
    id: Optional[int] = None
    name: str = ""
    version: str = ""
    schema_version: str = ""
    enabled_event_ids: str = ""  # JSON array of integers
    disabled_event_ids: str = ""  # JSON array of integers
    rules_json: str = ""  # JSON array of rule objects
    raw_xml: Optional[str] = None  # Original XML content
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def get_enabled_event_ids(self) -> List[int]:
        if self.enabled_event_ids:
            return json.loads(self.enabled_event_ids)
        return []

    def set_enabled_event_ids(self, ids: List[int]):
        self.enabled_event_ids = json.dumps(ids)

    def get_disabled_event_ids(self) -> List[int]:
        if self.disabled_event_ids:
            return json.loads(self.disabled_event_ids)
        return []

    def set_disabled_event_ids(self, ids: List[int]):
        self.disabled_event_ids = json.dumps(ids)

    def get_rules(self) -> List[Dict[str, Any]]:
        if self.rules_json:
            return json.loads(self.rules_json)
        return []

    def set_rules(self, rules: List[Dict[str, Any]]):
        self.rules_json = json.dumps(rules)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "schema_version": self.schema_version,
            "enabled_event_ids": self.get_enabled_event_ids(),
            "disabled_event_ids": self.get_disabled_event_ids(),
            "rules": self.get_rules(),
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class WindowsAuditConfig:
    """Windows Audit Policy configuration."""
    id: Optional[int] = None
    name: str = ""
    categories_json: str = ""  # JSON array of category objects
    raw_content: Optional[str] = None  # Original audit policy content
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def get_categories(self) -> List[Dict[str, Any]]:
        if self.categories_json:
            return json.loads(self.categories_json)
        return []

    def set_categories(self, categories: List[Dict[str, Any]]):
        self.categories_json = json.dumps(categories)

    def get_enabled_subcategories(self) -> List[str]:
        """Get list of enabled audit subcategories."""
        enabled = []
        for cat in self.get_categories():
            for subcat in cat.get("subcategories", []):
                if subcat.get("success") or subcat.get("failure"):
                    enabled.append(subcat.get("name", ""))
        return enabled

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "categories": self.get_categories(),
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Export all models
__all__ = [
    "Profile",
    "FieldMapping",
    "SigmaConversion",
    "SigmaSetting",
    "SysmonConfig",
    "WindowsAuditConfig",
    "ConversionType",
    "MappingStatus",
]
