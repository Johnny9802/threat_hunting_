"""FastAPI REST API for Threat Hunting Playbook."""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
import os
from pathlib import Path
import re

from pydantic import BaseModel, Field, validator

from src.parser import PlaybookParser
from src.search import PlaybookSearch
from src.exporter import QueryExporter
from src.ai_assistant import AIAssistant
from src.mitre_mapping import MitreMapper

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"


def get_cors_origins():
    """Get allowed origins based on environment.

    Production: Uses explicit whitelist from ALLOWED_ORIGINS environment variable
    Development: Allows localhost and common development origins
    """
    if IS_PRODUCTION:
        # In production, use explicit whitelist from environment variable
        allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
        # Filter out empty strings and strip whitespace
        allowed_origins = [origin.strip() for origin in allowed_origins if origin.strip()]
        if not allowed_origins:
            # Fallback: if no origins configured, deny all (safer than wildcard)
            allowed_origins = []
    else:
        # In development, allow localhost and common development origins
        allowed_origins = [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000"
        ]
    return allowed_origins


# API docs configuration based on environment
# Disable API documentation in production to reduce information disclosure
DOCS_URL = "/docs" if not IS_PRODUCTION else None
REDOC_URL = "/redoc" if not IS_PRODUCTION else None

# Initialize FastAPI app
app = FastAPI(
    title="Threat Hunting Playbook API",
    description="AI-powered REST API for managing threat hunting playbooks",
    version="2.0.0",
    docs_url=DOCS_URL,
    redoc_url=REDOC_URL
)

# CORS middleware with secure configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=False,  # Set to False for public API; only True if authentication needed
    allow_methods=["GET", "POST"],  # Restrict to only necessary methods
    allow_headers=["Content-Type", "Authorization"],  # Only necessary headers
)

# Initialize components
parser = PlaybookParser()
search = PlaybookSearch(parser)
exporter = QueryExporter()
ai = AIAssistant()
mitre = MitreMapper()


# ============================================================================
# PYDANTIC VALIDATION MODELS FOR INPUT VALIDATION
# ============================================================================

class ExplainRequest(BaseModel):
    """Pydantic model for AI explain endpoint validation."""

    playbook_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="The ID of the playbook to explain",
        example="playbook_001"
    )

    @validator('playbook_id')
    def validate_playbook_id(cls, v):
        """Validate playbook_id for security threats."""
        if not v or not isinstance(v, str):
            raise ValueError("playbook_id must be a non-empty string")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'update\s+', r'select\s+.*from',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("playbook_id contains potentially malicious patterns")

        # Allowed characters: alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("playbook_id contains invalid characters. Use only alphanumeric, underscore, hyphen, or dot")

        return v.strip()

    class Config:
        schema_extra = {
            "example": {
                "playbook_id": "playbook_001"
            }
        }


class AskRequest(BaseModel):
    """Pydantic model for AI ask endpoint validation."""

    question: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="The question to ask the AI assistant",
        example="What are the best practices for detecting lateral movement?"
    )

    @validator('question')
    def validate_question(cls, v):
        """Validate question for security threats and content quality."""
        if not v or not isinstance(v, str):
            raise ValueError("question must be a non-empty string")

        # Check for excessive whitespace
        if len(v.split()) < 2:
            raise ValueError("question must contain at least 2 words")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'update\s+',
            r'ignore\s+instructions', r'bypass', r'override',
            r'system\s+prompt', r'jailbreak',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("question contains potentially malicious patterns")

        # Check for excessive special characters (more than 15%)
        special_chars = len(re.findall(r'[^a-zA-Z0-9\s\?\!\.,-]', v))
        if special_chars > len(v) * 0.15:
            raise ValueError("question contains too many special characters")

        return v.strip()

    class Config:
        schema_extra = {
            "example": {
                "question": "What are the best practices for detecting lateral movement?"
            }
        }


class SuggestRequest(BaseModel):
    """Pydantic model for AI suggest endpoint validation."""

    finding: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="The security finding to investigate",
        example="Unusual process execution from temp directory"
    )

    playbook_id: Optional[str] = Field(
        None,
        max_length=255,
        description="Optional playbook ID for context",
        example="playbook_001"
    )

    @validator('finding')
    def validate_finding(cls, v):
        """Validate finding for security threats."""
        if not v or not isinstance(v, str):
            raise ValueError("finding must be a non-empty string")

        # Check for excessive whitespace
        if len(v.split()) < 2:
            raise ValueError("finding must contain at least 2 words")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'update\s+',
            r'ignore\s+instructions', r'bypass', r'override',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("finding contains potentially malicious patterns")

        return v.strip()

    @validator('playbook_id')
    def validate_playbook_id_optional(cls, v):
        """Validate optional playbook_id."""
        if v is None:
            return v

        if not isinstance(v, str) or not v:
            raise ValueError("playbook_id must be a non-empty string when provided")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'update\s+',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("playbook_id contains potentially malicious patterns")

        # Allowed characters: alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("playbook_id contains invalid characters")

        return v.strip()

    class Config:
        schema_extra = {
            "example": {
                "finding": "Unusual process execution from temp directory",
                "playbook_id": "playbook_001"
            }
        }


class GenerateRequest(BaseModel):
    """Pydantic model for AI generate endpoint validation."""

    playbook_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="The ID of the playbook to generate variant for",
        example="playbook_001"
    )

    target_env: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Target environment (e.g., 'production', 'cloud-aws')",
        example="production"
    )

    target_siem: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Target SIEM platform (e.g., 'splunk', 'elasticsearch')",
        example="splunk"
    )

    @validator('playbook_id')
    def validate_playbook_id_gen(cls, v):
        """Validate playbook_id for security threats."""
        if not v or not isinstance(v, str):
            raise ValueError("playbook_id must be a non-empty string")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'update\s+', r'select\s+.*from',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("playbook_id contains potentially malicious patterns")

        # Allowed characters: alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("playbook_id contains invalid characters")

        return v.strip()

    @validator('target_env')
    def validate_target_env(cls, v):
        """Validate target_env for security threats."""
        if not v or not isinstance(v, str):
            raise ValueError("target_env must be a non-empty string")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("target_env contains potentially malicious patterns")

        # Allowed characters: alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("target_env contains invalid characters")

        return v.strip()

    @validator('target_siem')
    def validate_target_siem(cls, v):
        """Validate target_siem for security threats."""
        if not v or not isinstance(v, str):
            raise ValueError("target_siem must be a non-empty string")

        # Check for prompt injection patterns
        injection_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onclick=',
            r'union\s+select', r'drop\s+table',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("target_siem contains potentially malicious patterns")

        # Allowed characters: alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError("target_siem contains invalid characters")

        return v.strip()

    class Config:
        schema_extra = {
            "example": {
                "playbook_id": "playbook_001",
                "target_env": "production",
                "target_siem": "splunk"
            }
        }


# ============================================================================


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Threat Hunting Playbook API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "playbooks": "/api/playbooks",
            "search": "/api/search",
            "ai": "/api/ai"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "ai_available": ai.is_available()
    }


@app.get("/api/playbooks")
async def list_playbooks(
    limit: Optional[int] = Query(None, ge=1, le=100),
    offset: Optional[int] = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    """List all available playbooks."""
    try:
        playbooks = search.list_all()

        # Apply pagination
        if limit:
            playbooks = playbooks[offset:offset + limit]

        return playbooks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str) -> Dict[str, Any]:
    """Get a specific playbook by ID."""
    try:
        playbook = search.get_by_id(playbook_id)
        return playbook
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/search")
async def search_playbooks(
    query: Optional[str] = None,
    technique: Optional[str] = None,
    tactic: Optional[str] = None,
    tag: Optional[str] = None,
    severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Search playbooks by various criteria."""
    try:
        results = search.search(
            query=query,
            technique=technique,
            tactic=tactic,
            tag=tag,
            severity=severity
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/playbooks/{playbook_id}/export/{siem}")
async def export_query(playbook_id: str, siem: str) -> Dict[str, Any]:
    """Export query for specific SIEM."""
    try:
        playbook = search.get_by_id(playbook_id)
        query = exporter.export_query(playbook, siem)

        return {
            "playbook_id": playbook_id,
            "siem": siem,
            "query": query
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mitre/tactics")
async def list_tactics() -> List[str]:
    """List all MITRE ATT&CK tactics."""
    try:
        return mitre.get_all_tactics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mitre/techniques/{technique_id}")
async def get_technique_info(technique_id: str) -> Dict[str, Any]:
    """Get information about a MITRE technique."""
    try:
        return {
            "technique_id": technique_id,
            "name": mitre.get_technique_name(technique_id),
            "tactic": mitre.get_tactic_for_technique(technique_id),
            "url": mitre.get_attack_url(technique_id)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/explain")
async def ai_explain(request: ExplainRequest) -> Dict[str, str]:
    """Get AI explanation of a playbook.

    Request body:
    - playbook_id (str): The ID of the playbook to explain (1-255 chars, alphanumeric)

    Validation:
    - Prevents prompt injection attempts
    - Validates playbook_id format and length
    """
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available. Configure GROQ_API_KEY or OPENAI_API_KEY")

    try:
        playbook = search.get_by_id(request.playbook_id)
        explanation = ai.explain_playbook(playbook)

        return {
            "playbook_id": request.playbook_id,
            "explanation": explanation
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {request.playbook_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/ask")
async def ai_ask(request: AskRequest) -> Dict[str, str]:
    """Ask a question to the AI assistant.

    Request body:
    - question (str): The question for the AI assistant (3-1000 chars, min 2 words)

    Validation:
    - Prevents prompt injection and jailbreak attempts
    - Validates question length and content quality
    - Detects excessive special characters
    """
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        answer = ai.ask_question(request.question)
        return {
            "question": request.question,
            "answer": answer
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/suggest")
async def ai_suggest(request: SuggestRequest) -> Dict[str, str]:
    """Get investigation suggestions based on a finding.

    Request body:
    - finding (str): The security finding to investigate (3-1000 chars, min 2 words)
    - playbook_id (str, optional): Playbook ID for context (max 255 chars)

    Validation:
    - Prevents prompt injection attempts
    - Validates finding and optional playbook_id format
    """
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        playbook_data = None
        if request.playbook_id:
            playbook_data = search.get_by_id(request.playbook_id)

        suggestions = ai.suggest_next_steps(request.finding, playbook_data)

        return {
            "finding": request.finding,
            "playbook_id": request.playbook_id,
            "suggestions": suggestions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/generate")
async def ai_generate(request: GenerateRequest) -> Dict[str, str]:
    """Generate query variant for different environment.

    Request body:
    - playbook_id (str): The ID of the playbook (1-255 chars, alphanumeric)
    - target_env (str): Target environment (2-100 chars, alphanumeric)
    - target_siem (str): Target SIEM platform (2-50 chars, alphanumeric)

    Validation:
    - Prevents prompt injection and SQL injection attempts
    - Validates all field formats and lengths
    - Restricts to safe character sets
    """
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        playbook = search.get_by_id(request.playbook_id)
        variant = ai.generate_variant(playbook, request.target_env, request.target_siem)

        return {
            "playbook_id": request.playbook_id,
            "target_env": request.target_env,
            "target_siem": request.target_siem,
            "variant": variant
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {request.playbook_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats")
async def get_stats() -> Dict[str, Any]:
    """Get statistics about the playbook collection."""
    try:
        playbooks = search.list_all()

        # Count by tactic
        tactics = {}
        severities = {}

        for pb in playbooks:
            tactic = pb.get('tactic', 'unknown')
            severity = pb.get('severity', 'unknown')

            tactics[tactic] = tactics.get(tactic, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1

        return {
            "total_playbooks": len(playbooks),
            "by_tactic": tactics,
            "by_severity": severities,
            "ai_available": ai.is_available(),
            "supported_siems": exporter.SUPPORTED_SIEMS
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
