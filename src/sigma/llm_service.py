"""LLM integration service for enhanced conversions."""

import json
from typing import Optional, Dict, Any, List, Tuple
from .config import sigma_settings


class LLMService:
    """Service for LLM-powered enhancements."""

    def __init__(self):
        self._client = None

    @property
    def is_available(self) -> bool:
        """Check if LLM service is available."""
        return sigma_settings.is_llm_available

    @property
    def provider(self) -> str:
        """Get the configured LLM provider."""
        return sigma_settings.LLM_PROVIDER

    @property
    def model(self) -> Optional[str]:
        """Get the configured model name."""
        return sigma_settings.LLM_MODEL if self.is_available else None

    def _get_client(self):
        """Get or create LLM client (synchronous version)."""
        if not self.is_available:
            return None

        if self._client is None:
            try:
                from openai import OpenAI

                if sigma_settings.LLM_PROVIDER == "azure":
                    from openai import AzureOpenAI

                    self._client = AzureOpenAI(
                        api_key=sigma_settings.LLM_API_KEY,
                        api_version=sigma_settings.AZURE_API_VERSION,
                        azure_endpoint=sigma_settings.LLM_API_BASE,
                    )
                elif sigma_settings.LLM_PROVIDER == "groq":
                    self._client = OpenAI(
                        api_key=sigma_settings.LLM_API_KEY,
                        base_url="https://api.groq.com/openai/v1",
                    )
                else:
                    # OpenAI or custom endpoint
                    kwargs = {"api_key": sigma_settings.LLM_API_KEY}
                    if sigma_settings.LLM_API_BASE:
                        kwargs["base_url"] = sigma_settings.LLM_API_BASE
                    self._client = OpenAI(**kwargs)
            except ImportError:
                return None
            except Exception:
                return None

        return self._client

    def suggest_mappings(
        self,
        sigma_fields: List[str],
        available_fields: Optional[List[str]] = None,
        context: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Use LLM to suggest field mappings.

        Args:
            sigma_fields: List of Sigma field names to map
            available_fields: Optional list of available fields in target environment
            context: Optional context about the environment

        Returns:
            Dictionary mapping Sigma fields to suggested target fields
        """
        if not self.is_available:
            return self._offline_mapping_suggestions(sigma_fields)

        client = self._get_client()
        if not client:
            return self._offline_mapping_suggestions(sigma_fields)

        try:
            prompt = self._build_mapping_prompt(sigma_fields, available_fields, context)

            response = client.chat.completions.create(
                model=sigma_settings.LLM_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security detection engineer expert in Splunk and Sigma. Respond only with valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=1000,
            )

            content = response.choices[0].message.content
            # Extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            mappings = json.loads(content.strip())
            return mappings

        except Exception:
            return self._offline_mapping_suggestions(sigma_fields)

    def _build_mapping_prompt(
        self,
        sigma_fields: List[str],
        available_fields: Optional[List[str]] = None,
        context: Optional[str] = None,
    ) -> str:
        """Build prompt for mapping suggestions."""
        prompt = f"""Suggest Splunk field mappings for these Sigma fields: {sigma_fields}

{"Available fields in environment: " + str(available_fields) if available_fields else ""}
{"Context: " + context if context else ""}

Respond with a JSON object mapping each Sigma field to the best Splunk field name.
Consider CIM (Common Information Model) conventions.
If unsure, use the original field name.

Example format:
{{"CommandLine": "process_command_line", "Image": "process_path"}}
"""
        return prompt

    def _offline_mapping_suggestions(self, sigma_fields: List[str]) -> Dict[str, str]:
        """Provide basic mapping suggestions without LLM."""
        # Common mapping heuristics
        heuristics = {
            "commandline": "process_command_line",
            "image": "process_path",
            "parentimage": "parent_process_path",
            "parentcommandline": "parent_process_command_line",
            "user": "user",
            "targetfilename": "file_path",
            "destinationip": "dest_ip",
            "destinationport": "dest_port",
            "sourceip": "src_ip",
            "sourceport": "src_port",
            "targetusername": "user",
            "processid": "process_id",
            "parentprocessid": "parent_process_id",
            "hostname": "host",
            "computername": "host",
            "queryname": "query",
            "targetobject": "registry_path",
            "details": "registry_value",
            "scriptblocktext": "script_block",
        }

        suggestions = {}
        for field in sigma_fields:
            lower_field = field.lower()
            if lower_field in heuristics:
                suggestions[field] = heuristics[lower_field]
            else:
                # Try to find partial matches
                for key, value in heuristics.items():
                    if key in lower_field or lower_field in key:
                        suggestions[field] = value
                        break

        return suggestions

    def generate_detection(
        self,
        description: str,
        log_source: Optional[str] = None,
        level: str = "medium",
        include_false_positives: bool = False,
        include_attack_techniques: bool = False,
    ) -> Tuple[Optional[str], Optional[str], List[str]]:
        """
        Generate Sigma rule and SPL from natural language description.

        Args:
            description: Natural language description of the detection
            log_source: Optional hint about log source
            level: Detection level (low, medium, high, critical)
            include_false_positives: Include false positive guidance
            include_attack_techniques: Include MITRE ATT&CK techniques

        Returns:
            Tuple of (sigma_yaml, spl_query, assumptions)
        """
        if not self.is_available:
            return (
                None,
                None,
                ["LLM not available - this feature requires AI assistance"],
            )

        client = self._get_client()
        if not client:
            return None, None, ["Failed to initialize LLM client"]

        try:
            prompt = self._build_generation_prompt(
                description,
                log_source,
                level,
                include_false_positives,
                include_attack_techniques,
            )

            response = client.chat.completions.create(
                model=sigma_settings.LLM_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a security detection engineer expert in Sigma rules and Splunk SPL.
Generate valid Sigma YAML rules and corresponding Splunk SPL queries.
Always document your assumptions clearly.
Respond with valid JSON containing: sigma_yaml, spl_query, and assumptions (list of strings).""",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=2000,
            )

            content = response.choices[0].message.content

            # Extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            result = json.loads(content.strip())

            return (
                result.get("sigma_yaml"),
                result.get("spl_query"),
                result.get("assumptions", []),
            )

        except Exception as e:
            return None, None, [f"Error generating detection: {str(e)}"]

    def _build_generation_prompt(
        self,
        description: str,
        log_source: Optional[str] = None,
        level: str = "medium",
        include_false_positives: bool = False,
        include_attack_techniques: bool = False,
    ) -> str:
        """Build prompt for detection generation."""
        prompt = f"""Generate a Sigma detection rule and Splunk SPL query for:

Description: {description}

{"Log Source Hint: " + log_source if log_source else "Infer the appropriate log source from the description."}
Level: {level}

Requirements:
1. Create a valid Sigma YAML rule with proper logsource and detection sections
2. Generate the corresponding Splunk SPL query
3. List all assumptions you made
{"4. Include false positive considerations" if include_false_positives else ""}
{"5. Include relevant MITRE ATT&CK techniques" if include_attack_techniques else ""}

Respond with JSON in this exact format:
{{
    "sigma_yaml": "title: ...\\nstatus: experimental\\n...",
    "spl_query": "index=... | where ...",
    "assumptions": ["assumption 1", "assumption 2"]
}}
"""
        return prompt

    def enhance_spl_reverse(
        self,
        spl: str,
        current_sigma: str,
    ) -> Tuple[Optional[str], List[str]]:
        """
        Enhance SPL to Sigma reverse engineering with LLM.

        Args:
            spl: Original SPL query
            current_sigma: Current best-effort Sigma conversion

        Returns:
            Tuple of (enhanced_sigma_yaml, improvements)
        """
        if not self.is_available:
            return current_sigma, []

        client = self._get_client()
        if not client:
            return current_sigma, []

        try:
            prompt = f"""Improve this Sigma rule generated from SPL:

Original SPL:
{spl}

Current Sigma (best effort):
{current_sigma}

Enhance the Sigma rule by:
1. Improving the detection logic
2. Adding appropriate modifiers (contains, startswith, etc.)
3. Suggesting better field names
4. Adding missing metadata

Respond with JSON:
{{
    "enhanced_sigma": "improved YAML here",
    "improvements": ["list of improvements made"]
}}
"""

            response = client.chat.completions.create(
                model=sigma_settings.LLM_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Sigma rule expert. Enhance the rule while maintaining validity.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1500,
            )

            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            result = json.loads(content.strip())
            return result.get("enhanced_sigma", current_sigma), result.get(
                "improvements", []
            )

        except Exception:
            return current_sigma, []


# Singleton instance
llm_service = LLMService()
