"""Tests for playbook parser module."""

from pathlib import Path

import pytest

from src.parser import PlaybookParser


class TestPlaybookParser:
    """Test cases for PlaybookParser class."""

    @pytest.fixture
    def parser(self):
        """Create a parser instance for testing."""
        return PlaybookParser()

    def test_parser_initialization(self, parser):
        """Test that parser initializes correctly."""
        assert parser is not None
        assert parser.playbooks_dir.exists()
        assert parser.schema_path.exists()

    def test_load_playbook(self, parser):
        """Test loading a specific playbook."""
        playbook = parser.load_playbook("PB-T1566-001")

        assert playbook is not None
        assert playbook["id"] == "PB-T1566-001"
        assert playbook["name"] is not None
        assert playbook["mitre"]["technique"] == "T1566"
        assert "queries_content" in playbook

    def test_load_nonexistent_playbook(self, parser):
        """Test that loading nonexistent playbook raises error."""
        with pytest.raises(FileNotFoundError):
            parser.load_playbook("PB-TXXX-999")

    def test_list_all_playbooks(self, parser):
        """Test listing all playbooks."""
        playbooks = parser.list_all_playbooks()

        assert isinstance(playbooks, list)
        assert len(playbooks) >= 3  # We have 3 playbooks

        # Check that each playbook has required fields
        for pb in playbooks:
            assert "id" in pb
            assert "name" in pb
            assert "technique" in pb
            assert "tactic" in pb

    def test_get_playbook_by_technique(self, parser):
        """Test getting playbooks by technique."""
        playbooks = parser.get_playbook_by_technique("T1566")

        assert isinstance(playbooks, list)
        assert len(playbooks) >= 1
        assert all(pb["technique"] == "T1566" for pb in playbooks)

    def test_search_playbooks_by_keyword(self, parser):
        """Test searching playbooks by keyword."""
        results = parser.search_playbooks(keyword="phishing")

        assert isinstance(results, list)
        assert len(results) >= 1
        assert any("phishing" in pb["name"].lower() for pb in results)

    def test_search_playbooks_by_tactic(self, parser):
        """Test searching playbooks by tactic."""
        results = parser.search_playbooks(tactic="execution")

        assert isinstance(results, list)
        assert all(pb["tactic"] == "execution" for pb in results)

    def test_search_playbooks_by_severity(self, parser):
        """Test searching playbooks by severity."""
        results = parser.search_playbooks(severity="critical")

        assert isinstance(results, list)
        for pb in results:
            assert pb["severity"] == "critical"

    def test_playbook_caching(self, parser):
        """Test that playbooks are cached after first load."""
        # Load twice
        playbook1 = parser.load_playbook("PB-T1566-001")
        playbook2 = parser.load_playbook("PB-T1566-001")

        # Should be the same object (cached)
        assert playbook1 is playbook2

    def test_queries_content_loaded(self, parser):
        """Test that query content is loaded correctly."""
        playbook = parser.load_playbook("PB-T1566-001")

        assert "queries_content" in playbook
        queries = playbook["queries_content"]

        # Check that we have queries for different SIEMs
        assert "splunk" in queries or "elastic" in queries or "sigma" in queries

        # Check that queries are strings with content
        for siem, query in queries.items():
            assert isinstance(query, str)
            assert len(query) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
