"""Exporter module for extracting queries in SIEM-specific formats."""

import os
from pathlib import Path
from typing import Any, Dict, Optional


class QueryExporter:
    """Export queries for specific SIEM platforms."""

    SUPPORTED_SIEMS = ["splunk", "elastic", "sigma"]

    def __init__(self):
        """Initialize the exporter."""
        pass

    def export_query(
        self,
        playbook_data: Dict[str, Any],
        siem: str,
        output_file: Optional[Path] = None,
    ) -> str:
        """Export a query for a specific SIEM.

        Args:
            playbook_data: Full playbook data dictionary
            siem: SIEM platform (splunk, elastic, sigma)
            output_file: Optional file path to write query to

        Returns:
            Query string

        Raises:
            ValueError: If SIEM not supported or query not available
        """
        siem = siem.lower()

        if siem not in self.SUPPORTED_SIEMS:
            raise ValueError(
                f"SIEM '{siem}' not supported. "
                f"Supported: {', '.join(self.SUPPORTED_SIEMS)}"
            )

        # Get query content
        queries_content = playbook_data.get("queries_content", {})
        query = queries_content.get(siem)

        if not query:
            raise ValueError(
                f"No {siem} query available for playbook {playbook_data.get('id')}"
            )

        # Add header comment with playbook info
        header = self._generate_header(playbook_data, siem)
        full_query = f"{header}\n\n{query}"

        # Write to file if requested
        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w") as f:
                f.write(full_query)

        return full_query

    def _generate_header(self, playbook_data: Dict[str, Any], siem: str) -> str:
        """Generate a header comment for the exported query.

        Args:
            playbook_data: Playbook data
            siem: SIEM platform

        Returns:
            Formatted header comment
        """
        comment_char = "#" if siem == "sigma" else "#"

        header_lines = [
            f"{comment_char} Threat Hunting Query",
            f"{comment_char} Playbook: {playbook_data.get('name')}",
            f"{comment_char} ID: {playbook_data.get('id')}",
            f"{comment_char} MITRE Technique: {playbook_data.get('mitre', {}).get('technique')}",
            f"{comment_char} Tactic: {playbook_data.get('mitre', {}).get('tactic')}",
            f"{comment_char} Severity: {playbook_data.get('severity')}",
            f"{comment_char} Author: {playbook_data.get('author')}",
            f"{comment_char}",
            f"{comment_char} Description: {playbook_data.get('description')}",
        ]

        return "\n".join(header_lines)

    def export_all_queries(
        self, playbook_data: Dict[str, Any], output_dir: Path
    ) -> Dict[str, Path]:
        """Export all available queries for a playbook.

        Args:
            playbook_data: Full playbook data
            output_dir: Directory to write queries to

        Returns:
            Dictionary mapping SIEM to output file path
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        exported = {}
        playbook_id = playbook_data.get("id", "unknown")

        queries_content = playbook_data.get("queries_content", {})

        for siem in queries_content.keys():
            if siem in self.SUPPORTED_SIEMS:
                # Determine file extension
                ext_map = {"splunk": "spl", "elastic": "kql", "sigma": "yml"}
                ext = ext_map.get(siem, "txt")

                # Generate filename
                output_file = output_dir / f"{playbook_id}_{siem}.{ext}"

                # Export query
                try:
                    self.export_query(playbook_data, siem, output_file)
                    exported[siem] = output_file
                except ValueError:
                    # Skip if query not available
                    continue

        return exported

    def get_available_siems(self, playbook_data: Dict[str, Any]) -> list[str]:
        """Get list of SIEMs that have queries available for this playbook.

        Args:
            playbook_data: Playbook data

        Returns:
            List of SIEM names
        """
        queries_content = playbook_data.get("queries_content", {})
        return [
            siem
            for siem in self.SUPPORTED_SIEMS
            if siem in queries_content and queries_content[siem]
        ]
