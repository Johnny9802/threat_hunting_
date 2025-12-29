"""Configuration settings for Sigma Translator module."""
import os
from typing import Optional
from functools import lru_cache


class SigmaSettings:
    """Sigma Translator settings loaded from environment variables."""

    def __init__(self):
        # Database - uses shared SQLite with main app
        self.DATABASE_URL: str = os.getenv(
            "SIGMA_DATABASE_URL",
            "sqlite:///./data/sigma_translator.db"
        )

        # Sigma repository path
        self.SIGMA_REPO_PATH: str = os.getenv("SIGMA_REPO_PATH", "./sigma-rules")

        # LLM Configuration
        self.LLM_PROVIDER: str = os.getenv("SIGMA_LLM_PROVIDER", "offline")  # offline, openai, azure, groq
        self.LLM_API_KEY: Optional[str] = os.getenv("SIGMA_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
        self.LLM_API_BASE: Optional[str] = os.getenv("SIGMA_LLM_API_BASE")
        self.LLM_MODEL: str = os.getenv("SIGMA_LLM_MODEL", "gpt-4o-mini")
        self.LLM_TIMEOUT: int = int(os.getenv("SIGMA_LLM_TIMEOUT", "30"))

        # Azure-specific
        self.AZURE_API_VERSION: Optional[str] = os.getenv("AZURE_API_VERSION", "2024-02-15-preview")

        # Debug mode
        self.DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    @property
    def is_llm_available(self) -> bool:
        """Check if LLM is configured and available."""
        return self.LLM_PROVIDER != "offline" and self.LLM_API_KEY is not None


@lru_cache()
def get_sigma_settings() -> SigmaSettings:
    """Get cached settings instance."""
    return SigmaSettings()


sigma_settings = get_sigma_settings()
