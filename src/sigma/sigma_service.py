"""Sigma parsing and repository service."""
import yaml
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from .config import sigma_settings


class SigmaService:
    """Service for parsing and managing Sigma rules."""

    def __init__(self):
        self.repo_path = Path(sigma_settings.SIGMA_REPO_PATH)

    def is_repo_available(self) -> bool:
        """Check if Sigma repository is mounted and accessible."""
        return self.repo_path.exists() and self.repo_path.is_dir()

    def get_repo_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        if not self.is_repo_available():
            return {"available": False, "path": str(self.repo_path), "rule_count": 0}

        rule_count = len(list(self.repo_path.rglob("*.yml"))) + len(
            list(self.repo_path.rglob("*.yaml"))
        )
        return {
            "available": True,
            "path": str(self.repo_path),
            "rule_count": rule_count,
        }

    def list_rules(
        self,
        search: Optional[str] = None,
        product: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List Sigma rules with optional filtering."""
        if not self.is_repo_available():
            return [], 0

        rules = []
        all_files = list(self.repo_path.rglob("*.yml")) + list(
            self.repo_path.rglob("*.yaml")
        )

        for file_path in all_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Handle multi-document YAML
                    docs = list(yaml.safe_load_all(content))
                    if not docs:
                        continue
                    rule = docs[0]

                if not isinstance(rule, dict) or "title" not in rule:
                    continue

                # Extract metadata
                logsource = rule.get("logsource", {})
                rule_info = {
                    "path": str(file_path.relative_to(self.repo_path)),
                    "filename": file_path.name,
                    "title": rule.get("title", "Untitled"),
                    "status": rule.get("status"),
                    "level": rule.get("level"),
                    "product": logsource.get("product"),
                    "service": logsource.get("service"),
                    "category": logsource.get("category"),
                    "tags": rule.get("tags", []),
                    "description": rule.get("description"),
                }

                # Apply filters
                if search:
                    search_lower = search.lower()
                    if not (
                        search_lower in rule_info["title"].lower()
                        or search_lower in str(rule_info.get("description", "")).lower()
                        or search_lower in file_path.name.lower()
                    ):
                        continue

                if product and rule_info.get("product") != product:
                    continue

                if service and rule_info.get("service") != service:
                    continue

                if category and rule_info.get("category") != category:
                    continue

                if tags:
                    rule_tags = [t.lower() for t in rule_info.get("tags", [])]
                    if not any(t.lower() in rule_tags for t in tags):
                        continue

                rules.append(rule_info)

            except Exception:
                continue

        # Sort by title
        rules.sort(key=lambda x: x["title"].lower())
        total = len(rules)

        # Apply pagination
        return rules[offset : offset + limit], total

    def get_rule_content(self, path: str) -> Optional[Dict[str, Any]]:
        """Get the content of a specific Sigma rule."""
        if not self.is_repo_available():
            return None

        file_path = self.repo_path / path
        if not file_path.exists() or not file_path.is_file():
            return None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                docs = list(yaml.safe_load_all(content))
                parsed = docs[0] if docs else {}

            return {"path": path, "content": content, "parsed": parsed}
        except Exception:
            return None

    def parse_yaml(self, yaml_content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Parse YAML content and validate it's a Sigma rule."""
        try:
            docs = list(yaml.safe_load_all(yaml_content))
            if not docs:
                return None, "Empty YAML content"

            rule = docs[0]
            if not isinstance(rule, dict):
                return None, "Invalid YAML structure: expected a mapping"

            # Basic Sigma validation
            if "title" not in rule:
                return None, "Missing required field: title"
            if "logsource" not in rule:
                return None, "Missing required field: logsource"
            if "detection" not in rule:
                return None, "Missing required field: detection"

            detection = rule["detection"]
            if "condition" not in detection:
                return None, "Missing required field: detection.condition"

            return rule, None

        except yaml.YAMLError as e:
            return None, f"YAML parsing error: {str(e)}"
        except Exception as e:
            return None, f"Error parsing Sigma rule: {str(e)}"

    def extract_fields(self, rule: Dict[str, Any]) -> List[str]:
        """Extract all field names used in the detection section."""
        fields = set()
        detection = rule.get("detection", {})

        def extract_from_dict(d: Dict[str, Any], prefix: str = ""):
            for key, value in d.items():
                if key == "condition":
                    continue

                # Check if this is a selection/filter block
                if isinstance(value, dict):
                    extract_from_dict(value, key)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            extract_from_dict(item, key)
                else:
                    # This is a field reference
                    field_name = key.split("|")[0]  # Remove modifiers
                    if not field_name.startswith("_"):
                        fields.add(field_name)

        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                extract_from_dict(value, key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        extract_from_dict(item, "")

        return sorted(list(fields))

    def get_logsource_info(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Extract logsource information from a Sigma rule."""
        logsource = rule.get("logsource", {})
        return {
            "product": logsource.get("product"),
            "service": logsource.get("service"),
            "category": logsource.get("category"),
            "definition": logsource.get("definition"),
        }

    def get_filters(self) -> Dict[str, List[str]]:
        """Get available filter options from the repository."""
        if not self.is_repo_available():
            return {"products": [], "services": [], "categories": [], "tags": []}

        products = set()
        services = set()
        categories = set()
        tags = set()

        all_files = list(self.repo_path.rglob("*.yml")) + list(
            self.repo_path.rglob("*.yaml")
        )

        for file_path in all_files[:500]:  # Limit for performance
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    docs = list(yaml.safe_load_all(content))
                    if not docs:
                        continue
                    rule = docs[0]

                if not isinstance(rule, dict):
                    continue

                logsource = rule.get("logsource", {})
                if logsource.get("product"):
                    products.add(logsource["product"])
                if logsource.get("service"):
                    services.add(logsource["service"])
                if logsource.get("category"):
                    categories.add(logsource["category"])
                for tag in rule.get("tags", []):
                    tags.add(tag)

            except Exception:
                continue

        return {
            "products": sorted(list(products)),
            "services": sorted(list(services)),
            "categories": sorted(list(categories)),
            "tags": sorted(list(tags))[:100],  # Limit tags
        }


# Singleton instance
sigma_service = SigmaService()
