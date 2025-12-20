"""Playbook parser module for loading and validating YAML playbooks."""

import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
import yaml
from jsonschema import validate


class PlaybookParser:
    """Parser for threat hunting playbooks."""

    def __init__(self, playbooks_dir: Optional[Path] = None):
        """Initialize the parser.

        Args:
            playbooks_dir: Directory containing playbooks. Defaults to ./playbooks/techniques/
        """
        if playbooks_dir is None:
            # Default to playbooks/techniques relative to project root
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent
            playbooks_dir = project_root / "playbooks" / "techniques"

        self.playbooks_dir = Path(playbooks_dir)
        self.schema_path = self.playbooks_dir.parent / "schema.json"
        self.schema = self._load_schema()
        self._playbooks_cache: Dict[str, Dict[str, Any]] = {}

    def _load_schema(self) -> Dict[str, Any]:
        """Load the JSON schema for playbook validation."""
        if not self.schema_path.exists():
            return {}

        with open(self.schema_path, "r") as f:
            return yaml.safe_load(f)

    def _convert_dates_to_strings(self, data: Any) -> Any:
        """Recursively convert date/datetime objects to ISO format strings.

        Args:
            data: The data structure to process

        Returns:
            The data with all date objects converted to strings
        """
        if isinstance(data, (date, datetime)):
            return data.isoformat()
        elif isinstance(data, dict):
            return {
                key: self._convert_dates_to_strings(value)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self._convert_dates_to_strings(item) for item in data]
        else:
            return data

    def load_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Load a specific playbook by ID.

        Args:
            playbook_id: The playbook ID (e.g., PB-T1566-001)

        Returns:
            Dictionary containing playbook data

        Raises:
            FileNotFoundError: If playbook doesn't exist
            yaml.YAMLError: If YAML is invalid
            jsonschema.ValidationError: If playbook doesn't match schema
        """
        # Check cache first
        if playbook_id in self._playbooks_cache:
            return self._playbooks_cache[playbook_id]

        # Find playbook file
        playbook_path = self._find_playbook_file(playbook_id)
        if not playbook_path:
            raise FileNotFoundError(f"Playbook {playbook_id} not found")

        # Load and parse YAML
        with open(playbook_path, "r") as f:
            playbook_data = yaml.safe_load(f)

        # Convert date objects to strings for JSON schema validation
        playbook_data = self._convert_dates_to_strings(playbook_data)

        # Validate against schema
        if self.schema:
            try:
                validate(instance=playbook_data, schema=self.schema)
            except jsonschema.ValidationError as e:
                raise ValueError(f"Playbook validation failed: {e.message}")

        # Load query files
        playbook_data = self._load_queries(playbook_data, playbook_path.parent)

        # Cache and return
        self._playbooks_cache[playbook_id] = playbook_data
        return playbook_data

    def _find_playbook_file(self, playbook_id: str) -> Optional[Path]:
        """Find the playbook.yaml file for a given playbook ID."""
        for technique_dir in self.playbooks_dir.iterdir():
            if technique_dir.is_dir():
                playbook_file = technique_dir / "playbook.yaml"
                if playbook_file.exists():
                    try:
                        with open(playbook_file, "r") as f:
                            data = yaml.safe_load(f)
                            if data.get("id") == playbook_id:
                                return playbook_file
                    except Exception:
                        continue
        return None

    def _load_queries(
        self, playbook_data: Dict[str, Any], playbook_dir: Path
    ) -> Dict[str, Any]:
        """Load query files referenced in the playbook."""
        if "queries" not in playbook_data:
            return playbook_data

        queries = playbook_data["queries"]
        loaded_queries = {}

        for siem, query_path in queries.items():
            full_path = playbook_dir / query_path
            if full_path.exists():
                with open(full_path, "r") as f:
                    loaded_queries[siem] = f.read()
            else:
                loaded_queries[siem] = f"# Query file not found: {query_path}"

        playbook_data["queries_content"] = loaded_queries
        return playbook_data

    def list_all_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks.

        Returns:
            List of playbook metadata dictionaries
        """
        playbooks = []

        if not self.playbooks_dir.exists():
            return playbooks

        for technique_dir in self.playbooks_dir.iterdir():
            if technique_dir.is_dir():
                playbook_file = technique_dir / "playbook.yaml"
                if playbook_file.exists():
                    try:
                        with open(playbook_file, "r") as f:
                            data = yaml.safe_load(f)
                            # Convert dates to strings
                            data = self._convert_dates_to_strings(data)
                            # Add summary info
                            playbooks.append(
                                {
                                    "id": data.get("id"),
                                    "name": data.get("name"),
                                    "description": data.get("description"),
                                    "technique": data.get("mitre", {}).get("technique"),
                                    "tactic": data.get("mitre", {}).get("tactic"),
                                    "severity": data.get("severity"),
                                    "tags": data.get("tags", []),
                                }
                            )
                    except Exception as e:
                        # Skip invalid playbooks
                        continue

        return sorted(playbooks, key=lambda x: x.get("id", ""))

    def get_playbook_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get all playbooks for a specific MITRE technique.

        Args:
            technique_id: MITRE technique ID (e.g., T1566)

        Returns:
            List of matching playbooks
        """
        all_playbooks = self.list_all_playbooks()
        return [p for p in all_playbooks if p.get("technique") == technique_id]

    def search_playbooks(
        self,
        keyword: Optional[str] = None,
        technique: Optional[str] = None,
        tactic: Optional[str] = None,
        tag: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search playbooks by various criteria.

        Args:
            keyword: Search in name and description
            technique: MITRE technique ID
            tactic: MITRE tactic name
            tag: Tag to search for
            severity: Severity level

        Returns:
            List of matching playbooks
        """
        all_playbooks = self.list_all_playbooks()
        results = all_playbooks

        if keyword:
            keyword_lower = keyword.lower()
            results = [
                p
                for p in results
                if keyword_lower in p.get("name", "").lower()
                or keyword_lower in p.get("description", "").lower()
            ]

        if technique:
            results = [p for p in results if p.get("technique") == technique]

        if tactic:
            tactic_lower = tactic.lower()
            results = [
                p for p in results if p.get("tactic", "").lower() == tactic_lower
            ]

        if tag:
            tag_lower = tag.lower()
            results = [
                p
                for p in results
                if any(tag_lower == t.lower() for t in p.get("tags", []))
            ]

        if severity:
            severity_lower = severity.lower()
            results = [
                p for p in results if p.get("severity", "").lower() == severity_lower
            ]

        return results
