"""Search module for finding playbooks."""

from typing import Any, Dict, List, Optional

from src.parser import PlaybookParser


class PlaybookSearch:
    """Search interface for playbooks."""

    def __init__(self, parser: Optional[PlaybookParser] = None):
        """Initialize search with a parser.

        Args:
            parser: PlaybookParser instance. Creates new one if None.
        """
        self.parser = parser or PlaybookParser()

    def search(
        self,
        query: Optional[str] = None,
        technique: Optional[str] = None,
        tactic: Optional[str] = None,
        tag: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search playbooks with multiple criteria.

        Args:
            query: Free text search in name/description
            technique: MITRE technique ID (e.g., T1566)
            tactic: MITRE tactic name
            tag: Tag to filter by
            severity: Severity level (critical, high, medium, low)

        Returns:
            List of matching playbooks
        """
        return self.parser.search_playbooks(
            keyword=query,
            technique=technique,
            tactic=tactic,
            tag=tag,
            severity=severity,
        )

    def get_by_id(self, playbook_id: str) -> Dict[str, Any]:
        """Get a specific playbook by ID.

        Args:
            playbook_id: Playbook identifier

        Returns:
            Full playbook data

        Raises:
            FileNotFoundError: If playbook doesn't exist
        """
        return self.parser.load_playbook(playbook_id)

    def list_all(self) -> List[Dict[str, Any]]:
        """List all available playbooks.

        Returns:
            List of all playbooks
        """
        return self.parser.list_all_playbooks()

    def get_by_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get all playbooks for a technique.

        Args:
            technique_id: MITRE ATT&CK technique ID

        Returns:
            List of matching playbooks
        """
        return self.parser.get_playbook_by_technique(technique_id)
