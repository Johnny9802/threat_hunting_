"""Tests for AI assistant module."""

import os
from unittest.mock import Mock, patch

import pytest

from src.ai_assistant import AIAssistant
from src.parser import PlaybookParser


class TestAIAssistant:
    """Test cases for AIAssistant class."""

    @pytest.fixture
    def ai(self):
        """Create an AI assistant instance for testing."""
        return AIAssistant()

    def test_ai_initialization(self, ai):
        """Test that AI assistant initializes."""
        assert ai is not None
        # May or may not be available depending on env vars
        assert isinstance(ai.is_available(), bool)

    def test_provider_info(self, ai):
        """Test getting provider info."""
        info = ai.get_provider_info()
        assert isinstance(info, str)
        assert len(info) > 0

    @pytest.mark.skipif(
        not os.getenv("GROQ_API_KEY") and not os.getenv("OPENAI_API_KEY"),
        reason="No AI API key configured",
    )
    def test_explain_playbook(self, ai):
        """Test explaining a playbook (requires API key)."""
        if not ai.is_available():
            pytest.skip("AI not available")

        parser = PlaybookParser()
        playbook = parser.load_playbook("PB-T1566-001")

        explanation = ai.explain_playbook(playbook)

        assert isinstance(explanation, str)
        assert len(explanation) > 100  # Should be a substantial explanation

    @pytest.mark.skipif(
        not os.getenv("GROQ_API_KEY") and not os.getenv("OPENAI_API_KEY"),
        reason="No AI API key configured",
    )
    def test_ask_question(self, ai):
        """Test asking a question (requires API key)."""
        if not ai.is_available():
            pytest.skip("AI not available")

        answer = ai.ask_question("What is MITRE ATT&CK?")

        assert isinstance(answer, str)
        assert len(answer) > 50

    def test_ai_not_available_error(self):
        """Test that AI raises error when not configured."""
        # Create AI with no credentials
        with patch.dict(os.environ, {}, clear=True):
            ai = AIAssistant()
            assert not ai.is_available()

            parser = PlaybookParser()
            playbook = parser.load_playbook("PB-T1566-001")

            with pytest.raises(RuntimeError):
                ai.explain_playbook(playbook)

    @patch("src.ai_assistant.OpenAI")
    def test_format_playbook_for_ai(self, mock_openai):
        """Test playbook formatting for AI context."""
        ai = AIAssistant()
        parser = PlaybookParser()
        playbook = parser.load_playbook("PB-T1566-001")

        formatted = ai._format_playbook_for_ai(playbook)

        assert isinstance(formatted, str)
        assert playbook["id"] in formatted
        assert playbook["name"] in formatted
        assert (
            "Hunt Hypothesis" in formatted
            or playbook.get("hunt_hypothesis", "") in formatted
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
