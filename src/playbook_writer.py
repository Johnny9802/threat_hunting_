"""Playbook writer module for creating, updating and deleting playbooks."""

import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class PlaybookWriter:
    """Writer for creating and managing threat hunting playbooks."""

    def __init__(self, playbooks_dir: Optional[Path] = None):
        """Initialize the writer.

        Args:
            playbooks_dir: Directory containing playbooks. Defaults to ./playbooks/techniques/
        """
        if playbooks_dir is None:
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent
            playbooks_dir = project_root / "playbooks" / "techniques"

        self.playbooks_dir = Path(playbooks_dir)
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)

    def create_playbook(self, playbook_data: Dict[str, Any]) -> Path:
        """Create a new playbook with directory structure.

        Args:
            playbook_data: Dictionary containing playbook information

        Returns:
            Path to created playbook directory

        Raises:
            ValueError: If playbook already exists or data is invalid
        """
        playbook_id = playbook_data.get("id")
        if not playbook_id:
            raise ValueError("Playbook ID is required")

        # Extract technique from MITRE data or ID
        technique = playbook_data.get("mitre", {}).get("technique", "")
        if not technique:
            # Try to extract from ID (e.g., PB-T1566-001 -> T1566)
            import re

            match = re.search(r"T\d+", playbook_id)
            if match:
                technique = match.group(0)
            else:
                raise ValueError("Unable to determine MITRE technique")

        # Get tactic name for directory
        tactic = playbook_data.get("mitre", {}).get("tactic", "unknown")

        # Create directory name: T1566-phishing or T1566-tactic-name
        dir_name = f"{technique}-{tactic}".lower().replace(" ", "-")
        playbook_dir = self.playbooks_dir / dir_name

        # Check if already exists
        if playbook_dir.exists():
            raise ValueError(f"Playbook directory already exists: {dir_name}")

        # Create directory structure
        playbook_dir.mkdir(parents=True, exist_ok=True)
        queries_dir = playbook_dir / "queries"
        queries_dir.mkdir(exist_ok=True)

        # Separate queries_content from main playbook data
        queries_content = playbook_data.pop("queries_content", {})

        # Create queries dict with file references
        if queries_content:
            playbook_data["queries"] = {}
            for siem, content in queries_content.items():
                filename = self._get_query_filename(siem)
                query_path = queries_dir / filename

                # Write query file
                with open(query_path, "w") as f:
                    f.write(content)

                # Add reference to playbook
                playbook_data["queries"][siem] = f"queries/{filename}"

        # Write playbook.yaml
        playbook_file = playbook_dir / "playbook.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(
                playbook_data,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )

        return playbook_dir

    def update_playbook(self, playbook_id: str, update_data: Dict[str, Any]) -> None:
        """Update an existing playbook.

        Args:
            playbook_id: The ID of the playbook to update
            update_data: Dictionary with fields to update

        Raises:
            FileNotFoundError: If playbook doesn't exist
            ValueError: If update data is invalid
        """
        # Find playbook directory
        playbook_dir = self._find_playbook_dir(playbook_id)
        if not playbook_dir:
            raise FileNotFoundError(f"Playbook {playbook_id} not found")

        playbook_file = playbook_dir / "playbook.yaml"

        # Load existing playbook
        with open(playbook_file, "r") as f:
            existing_data = yaml.safe_load(f)

        # Handle queries_content separately
        queries_content = update_data.pop("queries_content", None)
        if queries_content:
            queries_dir = playbook_dir / "queries"
            queries_dir.mkdir(exist_ok=True)

            if "queries" not in existing_data:
                existing_data["queries"] = {}

            for siem, content in queries_content.items():
                filename = self._get_query_filename(siem)
                query_path = queries_dir / filename

                # Write/update query file
                with open(query_path, "w") as f:
                    f.write(content)

                # Update reference
                existing_data["queries"][siem] = f"queries/{filename}"

        # Merge update data
        for key, value in update_data.items():
            if value is not None:
                existing_data[key] = value

        # Update timestamp
        existing_data["updated"] = datetime.now().isoformat()

        # Write updated playbook
        with open(playbook_file, "w") as f:
            yaml.dump(
                existing_data,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )

    def delete_playbook(self, playbook_id: str) -> None:
        """Delete a playbook and its directory.

        Args:
            playbook_id: The ID of the playbook to delete

        Raises:
            FileNotFoundError: If playbook doesn't exist
        """
        playbook_dir = self._find_playbook_dir(playbook_id)
        if not playbook_dir:
            raise FileNotFoundError(f"Playbook {playbook_id} not found")

        # Remove entire directory
        shutil.rmtree(playbook_dir)

    def _find_playbook_dir(self, playbook_id: str) -> Optional[Path]:
        """Find the directory containing a playbook by its ID."""
        for technique_dir in self.playbooks_dir.iterdir():
            if technique_dir.is_dir():
                playbook_file = technique_dir / "playbook.yaml"
                if playbook_file.exists():
                    try:
                        with open(playbook_file, "r") as f:
                            data = yaml.safe_load(f)
                            if data.get("id") == playbook_id:
                                return technique_dir
                    except Exception:
                        continue
        return None

    def _get_query_filename(self, siem: str) -> str:
        """Get the appropriate filename for a SIEM query."""
        extensions = {"splunk": "spl", "elastic": "kql", "sigma": "yml"}
        ext = extensions.get(siem.lower(), "txt")
        return f"{siem.lower()}.{ext}"
