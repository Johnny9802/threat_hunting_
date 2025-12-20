"""Tests for search module."""

import pytest

from src.parser import PlaybookParser
from src.search import PlaybookSearch


class TestPlaybookSearch:
    """Test cases for PlaybookSearch class."""

    @pytest.fixture
    def search(self):
        """Create a search instance for testing."""
        return PlaybookSearch()

    def test_search_initialization(self, search):
        """Test that search initializes correctly."""
        assert search is not None
        assert isinstance(search.parser, PlaybookParser)

    def test_list_all(self, search):
        """Test listing all playbooks."""
        playbooks = search.list_all()

        assert isinstance(playbooks, list)
        assert len(playbooks) >= 3

    def test_get_by_id(self, search):
        """Test getting a playbook by ID."""
        playbook = search.get_by_id("PB-T1566-001")

        assert playbook is not None
        assert playbook["id"] == "PB-T1566-001"

    def test_get_by_id_not_found(self, search):
        """Test getting nonexistent playbook raises error."""
        with pytest.raises(FileNotFoundError):
            search.get_by_id("PB-TXXX-999")

    def test_search_with_query(self, search):
        """Test free-text search."""
        results = search.search(query="credential")

        assert isinstance(results, list)
        # Should find credential dumping playbook
        assert any("credential" in pb["name"].lower() for pb in results)

    def test_search_with_technique(self, search):
        """Test search by technique."""
        results = search.search(technique="T1059")

        assert isinstance(results, list)
        assert all(pb["technique"] == "T1059" for pb in results)

    def test_search_with_tactic(self, search):
        """Test search by tactic."""
        results = search.search(tactic="credential-access")

        assert isinstance(results, list)
        assert all(pb["tactic"] == "credential-access" for pb in results)

    def test_search_with_multiple_criteria(self, search):
        """Test search with multiple filters."""
        results = search.search(tactic="execution", severity="high")

        assert isinstance(results, list)
        for pb in results:
            assert pb["tactic"] == "execution"
            assert pb["severity"] == "high"

    def test_get_by_technique(self, search):
        """Test getting playbooks by technique."""
        playbooks = search.get_by_technique("T1003")

        assert isinstance(playbooks, list)
        assert len(playbooks) >= 1
        assert all(pb["technique"] == "T1003" for pb in playbooks)

    def test_search_no_results(self, search):
        """Test search that returns no results."""
        results = search.search(query="nonexistent_playbook_xyz")

        assert isinstance(results, list)
        assert len(results) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
