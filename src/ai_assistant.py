"""AI Assistant module for threat hunting playbook analysis and generation."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

# System prompt for the AI assistant
SYSTEM_PROMPT = """You are an expert Threat Hunter and Detection Engineer with 10+ years of experience in SOC enterprise environments.

Your expertise includes:
- MITRE ATT&CK framework and tactics/techniques
- Query languages: Splunk SPL, Elastic KQL, Sigma rules
- Windows/Linux forensics and log analysis
- Malware analysis and IOC extraction
- Incident response procedures
- Security monitoring and detection engineering

When explaining playbooks:
1. Explain the attack technique in clear, practical terms
2. Describe what the queries detect and WHY they work
3. List potential false positives and how to reduce them
4. Suggest practical investigation steps
5. Reference specific log sources and fields

When generating query variants:
1. Adapt queries to the target environment/SIEM
2. Maintain the same detection logic
3. Add detailed comments explaining each part
4. Suggest alternative data sources if needed
5. Consider performance and false positive rate

When answering general questions:
1. Be practical and actionable, not theoretical
2. Provide specific examples and code when relevant
3. Reference real-world attack scenarios
4. Suggest detection and response steps
5. Use industry best practices

Format your responses clearly with:
- Bullet points for lists
- Code blocks for queries
- Clear section headers
- Specific field names and values

Always be concise but thorough. Focus on actionable intelligence."""


class AIAssistant:
    """AI-powered assistant for threat hunting playbooks."""

    def __init__(self):
        """Initialize the AI assistant with API credentials."""
        load_dotenv()

        self.provider = os.getenv("AI_PROVIDER", "groq").lower()
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")

        # Initialize client
        self.client: Optional[OpenAI] = None
        self.model: Optional[str] = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the appropriate AI client."""
        if self.provider == "groq" and self.groq_api_key:
            # Use Groq API (OpenAI-compatible)
            self.client = OpenAI(
                api_key=self.groq_api_key, base_url="https://api.groq.com/openai/v1"
            )
            self.model = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")

        elif self.openai_api_key:
            # Fallback to OpenAI
            self.client = OpenAI(api_key=self.openai_api_key)
            self.model = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
            self.provider = "openai"

        else:
            # No API key available
            self.client = None
            self.model = None

    def is_available(self) -> bool:
        """Check if AI assistant is available.

        Returns:
            True if API keys are configured
        """
        return self.client is not None

    def get_provider_info(self) -> str:
        """Get information about the active provider.

        Returns:
            String describing the provider and model
        """
        if not self.is_available():
            return "AI Assistant not configured. Set GROQ_API_KEY or OPENAI_API_KEY in .env file."

        return f"Using {self.provider.upper()} with model {self.model}"

    def explain_playbook(self, playbook_data: Dict[str, Any]) -> str:
        """Explain a playbook in detail.

        Args:
            playbook_data: Full playbook data

        Returns:
            AI-generated explanation

        Raises:
            RuntimeError: If AI is not available
        """
        if not self.is_available():
            raise RuntimeError("AI Assistant not configured")

        # Build context from playbook
        playbook_context = self._format_playbook_for_ai(playbook_data)

        prompt = f"""Explain this threat hunting playbook in detail:

{playbook_context}

Provide:
1. **Attack Overview**: What is this technique and why is it dangerous?
2. **Detection Logic**: Explain how the queries work and what they detect
3. **False Positives**: Common false positives and how to reduce them
4. **Investigation Steps**: Practical next steps when you find a match
5. **Key Indicators**: What to look for in the logs

Be specific and actionable."""

        return self._chat(prompt)

    def ask_question(self, question: str, context: Optional[str] = None) -> str:
        """Ask a free-form question to the AI assistant.

        Args:
            question: User's question
            context: Optional context to include

        Returns:
            AI response

        Raises:
            RuntimeError: If AI is not available
        """
        if not self.is_available():
            raise RuntimeError("AI Assistant not configured")

        prompt = question
        if context:
            prompt = f"Context:\n{context}\n\nQuestion: {question}"

        return self._chat(prompt)

    def suggest_next_steps(
        self, finding: str, playbook_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Suggest investigation steps based on a finding.

        Args:
            finding: Description of what was found
            playbook_data: Optional playbook context

        Returns:
            AI-generated suggestions

        Raises:
            RuntimeError: If AI is not available
        """
        if not self.is_available():
            raise RuntimeError("AI Assistant not configured")

        context = ""
        if playbook_data:
            context = (
                f"\nPlaybook context:\n{self._format_playbook_for_ai(playbook_data)}"
            )

        prompt = f"""A threat hunter found this suspicious activity:
{finding}
{context}

Suggest specific next steps for investigation:
1. **Immediate Actions**: What to check right now
2. **Data to Collect**: What logs/artifacts to gather
3. **Queries to Run**: Specific SIEM queries to run
4. **IOCs to Check**: What indicators to look for
5. **Escalation Criteria**: When to escalate to incident response

Be specific and actionable with exact field names and query examples."""

        return self._chat(prompt)

    def generate_variant(
        self, playbook_data: Dict[str, Any], target_env: str, target_siem: str
    ) -> str:
        """Generate a variant of a playbook for a different environment.

        Args:
            playbook_data: Source playbook data
            target_env: Target environment description (e.g., "Azure AD", "Linux servers")
            target_siem: Target SIEM (splunk, elastic, sigma)

        Returns:
            AI-generated variant query and explanation

        Raises:
            RuntimeError: If AI is not available
        """
        if not self.is_available():
            raise RuntimeError("AI Assistant not configured")

        playbook_context = self._format_playbook_for_ai(playbook_data)

        prompt = f"""Generate a variant of this playbook for a different environment:

Original Playbook:
{playbook_context}

Target Environment: {target_env}
Target SIEM: {target_siem}

Generate:
1. **Adapted Query**: Complete, working query for {target_siem}
2. **Data Sources**: Required logs/data sources in the target environment
3. **Field Mappings**: How fields map from original to target
4. **Detection Logic**: Explain how the detection works in the new environment
5. **Limitations**: Any limitations or gaps in the adapted version

Provide a complete, copy-paste ready query with detailed comments."""

        return self._chat(prompt)

    def _format_playbook_for_ai(self, playbook_data: Dict[str, Any]) -> str:
        """Format playbook data for AI context.

        Args:
            playbook_data: Playbook data

        Returns:
            Formatted string
        """
        lines = [
            f"ID: {playbook_data.get('id')}",
            f"Name: {playbook_data.get('name')}",
            f"Description: {playbook_data.get('description')}",
            f"MITRE Technique: {playbook_data.get('mitre', {}).get('technique')} - {playbook_data.get('mitre', {}).get('tactic')}",
            f"Severity: {playbook_data.get('severity')}",
            f"\nHunt Hypothesis:\n{playbook_data.get('hunt_hypothesis')}",
        ]

        # Add queries
        queries_content = playbook_data.get("queries_content", {})
        if queries_content:
            lines.append("\nQueries:")
            for siem, query in queries_content.items():
                lines.append(f"\n{siem.upper()}:")
                lines.append(query)

        # Add investigation steps
        if playbook_data.get("investigation_steps"):
            lines.append("\nInvestigation Steps:")
            for step in playbook_data["investigation_steps"]:
                lines.append(f"- {step}")

        # Add false positives
        if playbook_data.get("false_positives"):
            lines.append("\nFalse Positives:")
            for fp in playbook_data["false_positives"]:
                lines.append(f"- {fp}")

        return "\n".join(lines)

    def _chat(self, prompt: str) -> str:
        """Send a chat request to the AI.

        Args:
            prompt: User prompt

        Returns:
            AI response text

        Raises:
            RuntimeError: If request fails
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=2000,
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            raise RuntimeError(f"AI request failed: {str(e)}")
