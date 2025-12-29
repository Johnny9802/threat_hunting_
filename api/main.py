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
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],  # All needed methods for CRUD
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
        import traceback
        error_details = f"{str(e)}\n{traceback.format_exc()}"
        print(f"Error loading playbook {playbook_id}: {error_details}")
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


@app.get("/api/mitre/gaps")
async def get_coverage_gaps() -> Dict[str, Any]:
    """Analyze MITRE ATT&CK coverage gaps and get AI recommendations."""
    try:
        playbooks = search.list_all()

        # Calculate coverage by tactic
        tactic_coverage = {}
        covered_techniques = set()

        for pb in playbooks:
            tactic = pb.get('mitre', {}).get('tactic') or pb.get('tactic', 'unknown')
            technique = pb.get('mitre', {}).get('technique') or pb.get('technique')

            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = {
                    'techniques': set(),
                    'playbooks': 0
                }

            if technique:
                tactic_coverage[tactic]['techniques'].add(technique)
                covered_techniques.add(technique)

            tactic_coverage[tactic]['playbooks'] += 1

        # Convert sets to lists for JSON
        for tactic in tactic_coverage:
            tactic_coverage[tactic]['techniques'] = list(tactic_coverage[tactic]['techniques'])

        # Get AI suggestions for gaps if available
        suggestions = None
        if ai.is_available():
            try:
                # Create prompt for AI
                prompt = f"""Analyze this MITRE ATT&CK coverage data and provide recommendations:

Covered Techniques: {len(covered_techniques)}
Total Techniques in Enterprise: 193
Coverage: {round(len(covered_techniques) / 193 * 100, 1)}%

Tactics Coverage:
{chr(10).join([f"- {tactic}: {len(data['techniques'])} techniques, {data['playbooks']} playbooks" for tactic, data in tactic_coverage.items()])}

Please suggest:
1. Top 3 critical techniques that should be covered based on common attack patterns
2. Which tactics need more playbooks
3. Priority recommendations for improving coverage

Keep response concise and actionable."""

                suggestions = ai.ask_question(prompt)
            except Exception as e:
                print(f"AI suggestions failed: {e}")
                suggestions = None

        return {
            "total_techniques": 193,
            "covered_techniques": len(covered_techniques),
            "coverage_percentage": round(len(covered_techniques) / 193 * 100, 1),
            "tactic_coverage": tactic_coverage,
            "ai_suggestions": suggestions,
            "gaps": {
                "uncovered_count": 193 - len(covered_techniques),
                "tactics_needing_attention": [
                    tactic for tactic, data in tactic_coverage.items()
                    if len(data['techniques']) < 3
                ]
            }
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


# ============================================================================
# PLAYBOOK CRUD ENDPOINTS
# ============================================================================

class CreatePlaybookRequest(BaseModel):
    """Pydantic model for creating a new playbook."""

    id: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Unique playbook ID (e.g., PB-T1566-001)",
        example="PB-T1566-001"
    )
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)

    mitre: Dict[str, Any] = Field(
        ...,
        description="MITRE ATT&CK mapping with technique and tactic"
    )

    severity: str = Field(..., description="Severity level")
    author: str = Field(..., min_length=1, max_length=100)
    data_sources: List[str] = Field(default_factory=list)
    hunt_hypothesis: str = Field(..., min_length=1)
    investigation_steps: List[str] = Field(default_factory=list)
    false_positives: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    queries_content: Optional[Dict[str, str]] = Field(
        None,
        description="Query content for different SIEMs"
    )

    iocs: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    response: Optional[Dict[str, List[str]]] = Field(None)

    @validator('id')
    def validate_id(cls, v):
        """Validate playbook ID format."""
        if not re.match(r'^PB-[A-Z0-9]+-\d+$', v):
            raise ValueError("ID must follow format: PB-TXXXX-NNN")
        return v

    @validator('severity')
    def validate_severity(cls, v):
        """Validate severity level."""
        valid_severities = ['critical', 'high', 'medium', 'low']
        if v.lower() not in valid_severities:
            raise ValueError(f"Severity must be one of: {', '.join(valid_severities)}")
        return v.lower()


class UpdatePlaybookRequest(BaseModel):
    """Pydantic model for updating a playbook."""

    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, min_length=1, max_length=1000)
    mitre: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None
    author: Optional[str] = Field(None, min_length=1, max_length=100)
    data_sources: Optional[List[str]] = None
    hunt_hypothesis: Optional[str] = None
    investigation_steps: Optional[List[str]] = None
    false_positives: Optional[List[str]] = None
    references: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    queries_content: Optional[Dict[str, str]] = None
    iocs: Optional[List[Dict[str, str]]] = None
    response: Optional[Dict[str, List[str]]] = None

    @validator('severity')
    def validate_severity(cls, v):
        """Validate severity level."""
        if v is None:
            return v
        valid_severities = ['critical', 'high', 'medium', 'low']
        if v.lower() not in valid_severities:
            raise ValueError(f"Severity must be one of: {', '.join(valid_severities)}")
        return v.lower()


@app.post("/api/playbooks")
async def create_playbook(request: CreatePlaybookRequest) -> Dict[str, Any]:
    """Create a new playbook.

    Request body: CreatePlaybookRequest

    Returns:
        Created playbook data
    """
    try:
        # Check if playbook already exists
        try:
            existing = search.get_by_id(request.id)
            if existing:
                raise HTTPException(
                    status_code=409,
                    detail=f"Playbook {request.id} already exists"
                )
        except FileNotFoundError:
            pass  # OK, playbook doesn't exist

        # Create playbook directory structure
        from src.playbook_writer import PlaybookWriter
        writer = PlaybookWriter()

        playbook_data = request.dict()
        playbook_data['created'] = datetime.now().isoformat()
        playbook_data['updated'] = datetime.now().isoformat()

        writer.create_playbook(playbook_data)

        # Clear cache
        parser._playbooks_cache.clear()

        # Return created playbook
        return search.get_by_id(request.id)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: str,
    request: UpdatePlaybookRequest
) -> Dict[str, Any]:
    """Update an existing playbook.

    Args:
        playbook_id: The ID of the playbook to update
        request: UpdatePlaybookRequest with fields to update

    Returns:
        Updated playbook data
    """
    try:
        # Check if playbook exists
        existing = search.get_by_id(playbook_id)
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Playbook {playbook_id} not found"
            )

        # Update playbook
        from src.playbook_writer import PlaybookWriter
        writer = PlaybookWriter()

        update_data = request.dict(exclude_unset=True)
        update_data['updated'] = datetime.now().isoformat()

        writer.update_playbook(playbook_id, update_data)

        # Clear cache
        parser._playbooks_cache.clear()

        # Return updated playbook
        return search.get_by_id(playbook_id)

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str) -> Dict[str, str]:
    """Delete a playbook.

    Args:
        playbook_id: The ID of the playbook to delete

    Returns:
        Success message
    """
    try:
        # Check if playbook exists
        existing = search.get_by_id(playbook_id)
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Playbook {playbook_id} not found"
            )

        # Delete playbook
        from src.playbook_writer import PlaybookWriter
        writer = PlaybookWriter()
        writer.delete_playbook(playbook_id)

        # Clear cache
        parser._playbooks_cache.clear()

        return {
            "message": f"Playbook {playbook_id} deleted successfully",
            "playbook_id": playbook_id
        }

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# AI Configuration endpoints
class AIConfigRequest(BaseModel):
    """Pydantic model for AI configuration."""
    provider: str = Field(..., pattern=r'^(groq|openai)$')
    groq_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None


class AITestRequest(BaseModel):
    """Pydantic model for AI test request."""
    provider: str = Field(..., pattern=r'^(groq|openai)$')
    api_key: str = Field(..., min_length=1)


@app.post("/api/config/ai")
async def configure_ai(request: AIConfigRequest) -> Dict[str, str]:
    """Configure AI provider and API keys dynamically."""
    import os

    # Update environment variables
    if request.provider == 'groq' and request.groq_api_key:
        os.environ['GROQ_API_KEY'] = request.groq_api_key
        os.environ['AI_PROVIDER'] = 'groq'
    elif request.provider == 'openai' and request.openai_api_key:
        os.environ['OPENAI_API_KEY'] = request.openai_api_key
        os.environ['AI_PROVIDER'] = 'openai'

    # Reinitialize AI assistant
    global ai
    from src.ai_assistant import AIAssistant
    ai = AIAssistant()

    return {
        "message": "AI configuration updated",
        "provider": request.provider,
        "status": "available" if ai.is_available() else "unavailable"
    }


@app.post("/api/ai/test")
async def test_ai_connection(request: AITestRequest) -> Dict[str, Any]:
    """Test AI connection with provided credentials."""
    import os

    # Temporarily set the API key
    if request.provider == 'groq':
        os.environ['GROQ_API_KEY'] = request.api_key
        os.environ['AI_PROVIDER'] = 'groq'
    else:
        os.environ['OPENAI_API_KEY'] = request.api_key
        os.environ['AI_PROVIDER'] = 'openai'

    # Reinitialize AI assistant
    from src.ai_assistant import AIAssistant
    test_ai = AIAssistant()

    if not test_ai.is_available():
        raise HTTPException(status_code=400, detail="AI service not available with provided credentials")

    try:
        # Simple test query
        response = test_ai.ask_question("Say 'test successful' in exactly 2 words")
        return {
            "status": "success",
            "provider": request.provider,
            "message": "Connection successful"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"AI test failed: {str(e)}")


@app.get("/api/ai/status")
async def get_ai_status() -> Dict[str, Any]:
    """Get current AI configuration status."""
    import os

    return {
        "available": ai.is_available(),
        "provider": os.environ.get('AI_PROVIDER', 'none'),
        "groq_configured": bool(os.environ.get('GROQ_API_KEY')),
        "openai_configured": bool(os.environ.get('OPENAI_API_KEY'))
    }


# ============================================================================
# SIGMA TRANSLATOR ENDPOINTS
# ============================================================================

# Import Sigma Translator components
try:
    from src.sigma import (
        sigma_service,
        converter_service,
        llm_service,
        ConvertSigmaRequest,
        ConvertSPLRequest,
        DescribeRequest,
        ConversionResponse,
        ProfileCreate,
        ProfileUpdate,
        ProfileResponse,
        FieldMappingCreate,
        FieldMappingUpdate,
        FieldMappingResponse,
        BulkMappingImport,
        MappingStatusEnum,
        PrerequisiteInfo,
    )
    from src.sigma.database import sigma_db
    from src.sigma.models import SigmaConversion, ConversionType, FieldMapping, MappingStatus
    SIGMA_AVAILABLE = True
except ImportError as e:
    print(f"Sigma Translator module not available: {e}")
    SIGMA_AVAILABLE = False


if SIGMA_AVAILABLE:
    # Sigma Repository endpoints
    @app.get("/api/sigma/repo")
    async def get_sigma_repo_status() -> Dict[str, Any]:
        """Get Sigma repository status and statistics."""
        return sigma_service.get_repo_stats()

    @app.get("/api/sigma/rules")
    async def list_sigma_rules(
        search: Optional[str] = None,
        product: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0)
    ) -> Dict[str, Any]:
        """List Sigma rules from repository with filtering."""
        rules, total = sigma_service.list_rules(
            search=search,
            product=product,
            service=service,
            category=category,
            limit=limit,
            offset=offset
        )
        return {
            "rules": rules,
            "total": total,
            "limit": limit,
            "offset": offset
        }

    @app.get("/api/sigma/rules/{path:path}")
    async def get_sigma_rule(path: str) -> Dict[str, Any]:
        """Get content of a specific Sigma rule."""
        result = sigma_service.get_rule_content(path)
        if not result:
            raise HTTPException(status_code=404, detail="Rule not found")
        return result

    @app.get("/api/sigma/filters")
    async def get_sigma_filters() -> Dict[str, List[str]]:
        """Get available filter options from the repository."""
        return sigma_service.get_filters()

    class ValidateSigmaRequest(BaseModel):
        yaml_content: str = Field(..., description="YAML content to validate")

    @app.post("/api/sigma/validate")
    async def validate_sigma_yaml(request: ValidateSigmaRequest) -> Dict[str, Any]:
        """Validate Sigma YAML content."""
        rule, error = sigma_service.parse_yaml(request.yaml_content)
        if error:
            return {"valid": False, "error": error}
        return {
            "valid": True,
            "title": rule.get("title"),
            "fields": sigma_service.extract_fields(rule),
            "logsource": sigma_service.get_logsource_info(rule)
        }

    # Conversion endpoints
    @app.post("/api/sigma/convert/sigma-to-spl")
    async def convert_sigma_to_spl(request: ConvertSigmaRequest) -> Dict[str, Any]:
        """Convert Sigma YAML to Splunk SPL query."""
        # Parse and validate YAML
        rule, error = sigma_service.parse_yaml(request.sigma_yaml)
        if error:
            raise HTTPException(status_code=400, detail=error)

        # Get profile and mappings
        custom_mappings = {}
        profile_name = "Default"
        use_cim = False
        index_override = request.index_override
        sourcetype_override = request.sourcetype_override

        if request.profile_id:
            profile = sigma_db.get_profile(request.profile_id)
            if profile:
                profile_name = profile.name
                use_cim = request.cim_override if request.cim_override is not None else profile.cim_enabled
                if not index_override:
                    index_override = profile.index_name if profile.index_name != "*" else None
                custom_mappings = sigma_db.get_mappings_dict(profile.id)

        # Perform conversion
        spl, mappings, prerequisites, gaps, health_checks = converter_service.convert_sigma_to_spl(
            rule=rule,
            custom_mappings=custom_mappings,
            use_cim=use_cim,
            index_override=index_override,
            sourcetype_override=sourcetype_override,
            time_range=request.time_range,
        )

        # Save to history
        import json
        conversion = SigmaConversion(
            name=rule.get("title", "Untitled Rule"),
            conversion_type=ConversionType.SIGMA_TO_SPL,
            profile_id=request.profile_id,
            input_content=request.sigma_yaml,
            output_spl=spl,
            prerequisites=json.dumps(prerequisites.model_dump()),
            gap_analysis=json.dumps([g.model_dump() for g in gaps]),
            health_checks=json.dumps([h.model_dump() for h in health_checks]),
            llm_used=False,
        )
        sigma_db.save_conversion(conversion)

        return {
            "id": conversion.id,
            "name": conversion.name,
            "spl": spl,
            "sigma_yaml": request.sigma_yaml,
            "prerequisites": prerequisites.model_dump(),
            "mappings": [m.model_dump() for m in mappings],
            "gaps": [g.model_dump() for g in gaps],
            "health_checks": [h.model_dump() for h in health_checks],
            "llm_used": False,
        }

    @app.post("/api/sigma/convert/spl-to-sigma")
    async def convert_spl_to_sigma(request: ConvertSPLRequest) -> Dict[str, Any]:
        """Convert Splunk SPL query to Sigma YAML (best effort)."""
        if not request.spl_query.strip():
            raise HTTPException(status_code=400, detail="SPL query cannot be empty")

        # Basic reverse conversion
        sigma_yaml, correlation_notes = converter_service.reverse_spl_to_sigma(
            spl=request.spl_query,
            title=request.title,
            level=request.level,
            status=request.status,
            author=request.author,
            description=request.description,
        )

        # Try to enhance with LLM if available
        if llm_service.is_available:
            enhanced_sigma, improvements = llm_service.enhance_spl_reverse(
                spl=request.spl_query,
                current_sigma=sigma_yaml,
            )
            if enhanced_sigma:
                sigma_yaml = enhanced_sigma
                if improvements:
                    correlation_notes = (correlation_notes or "") + "\n\nLLM Improvements:\n" + "\n".join(
                        f"- {i}" for i in improvements
                    )

        # Parse the generated sigma to get prerequisites
        rule, _ = sigma_service.parse_yaml(sigma_yaml)
        if rule:
            _, mappings, prerequisites, gaps, health_checks = converter_service.convert_sigma_to_spl(
                rule=rule,
                custom_mappings={},
                use_cim=False,
            )
        else:
            prerequisites = PrerequisiteInfo(
                log_source={},
                event_ids=[],
                channels=[],
                configuration=[],
            )
            mappings = []
            gaps = []
            health_checks = []

        # Save to history
        import json
        conversion = SigmaConversion(
            name=request.title,
            conversion_type=ConversionType.SPL_TO_SIGMA,
            input_content=request.spl_query,
            output_sigma=sigma_yaml,
            output_spl=request.spl_query,
            correlation_notes=correlation_notes,
            llm_used=llm_service.is_available,
        )
        sigma_db.save_conversion(conversion)

        return {
            "id": conversion.id,
            "name": request.title,
            "spl": request.spl_query,
            "sigma_yaml": sigma_yaml,
            "prerequisites": prerequisites.model_dump() if hasattr(prerequisites, 'model_dump') else {},
            "mappings": [m.model_dump() for m in mappings] if mappings else [],
            "gaps": [g.model_dump() for g in gaps] if gaps else [],
            "health_checks": [h.model_dump() for h in health_checks] if health_checks else [],
            "correlation_notes": correlation_notes,
            "llm_used": llm_service.is_available,
        }

    @app.post("/api/sigma/convert/describe")
    async def generate_from_description(request: DescribeRequest) -> Dict[str, Any]:
        """Generate Sigma rule and SPL from natural language description."""
        if not llm_service.is_available:
            raise HTTPException(
                status_code=503,
                detail="This feature requires LLM. Configure API keys in settings.",
            )

        # Generate detection
        sigma_yaml, spl_query, assumptions = llm_service.generate_detection(
            description=request.description,
            log_source=request.log_source,
            level=request.level,
            include_false_positives=request.include_false_positives,
            include_attack_techniques=request.include_attack_techniques,
        )

        if not sigma_yaml:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate detection. {assumptions[0] if assumptions else ''}",
            )

        # Parse generated sigma
        rule, error = sigma_service.parse_yaml(sigma_yaml)
        if error:
            raise HTTPException(
                status_code=500,
                detail=f"Generated invalid Sigma: {error}",
            )

        # Get prerequisites and mappings
        _, mappings, prerequisites, gaps, health_checks = converter_service.convert_sigma_to_spl(
            rule=rule,
            custom_mappings={},
            use_cim=False,
        )

        # If SPL wasn't generated, convert from Sigma
        if not spl_query:
            spl_query, _, _, _, _ = converter_service.convert_sigma_to_spl(
                rule=rule,
                custom_mappings={},
                use_cim=False,
            )

        # Format assumptions as notes
        correlation_notes = None
        if assumptions:
            correlation_notes = "Assumptions Made:\n" + "\n".join(f"- {a}" for a in assumptions)

        # Save to history
        import json
        conversion = SigmaConversion(
            name=rule.get("title", "Generated Detection"),
            conversion_type=ConversionType.TEXT_TO_SIGMA,
            input_content=request.description,
            output_sigma=sigma_yaml,
            output_spl=spl_query,
            correlation_notes=correlation_notes,
            llm_used=True,
        )
        sigma_db.save_conversion(conversion)

        return {
            "id": conversion.id,
            "name": conversion.name,
            "spl": spl_query,
            "sigma_yaml": sigma_yaml,
            "prerequisites": prerequisites.model_dump(),
            "mappings": [m.model_dump() for m in mappings],
            "gaps": [g.model_dump() for g in gaps],
            "health_checks": [h.model_dump() for h in health_checks],
            "correlation_notes": correlation_notes,
            "llm_used": True,
        }

    # Profile Management endpoints
    @app.get("/api/sigma/profiles")
    async def list_profiles() -> List[Dict[str, Any]]:
        """List all Sigma profiles."""
        profiles = sigma_db.get_profiles()
        return [p.to_dict() for p in profiles]

    @app.post("/api/sigma/profiles")
    async def create_profile(request: ProfileCreate) -> Dict[str, Any]:
        """Create a new Sigma profile."""
        from src.sigma.models import Profile as ProfileModel
        profile = ProfileModel(
            name=request.name,
            description=request.description,
            index_name=request.index_name,
            sourcetype=request.sourcetype,
            cim_enabled=request.cim_enabled,
        )
        if request.macros:
            profile.set_macros(request.macros)
        created = sigma_db.create_profile(profile)
        return created.to_dict()

    @app.get("/api/sigma/profiles/{profile_id}")
    async def get_profile(profile_id: int) -> Dict[str, Any]:
        """Get a specific Sigma profile."""
        profile = sigma_db.get_profile(profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        return profile.to_dict()

    @app.patch("/api/sigma/profiles/{profile_id}")
    async def update_profile(profile_id: int, request: ProfileUpdate) -> Dict[str, Any]:
        """Update a Sigma profile."""
        updates = request.model_dump(exclude_unset=True)
        if 'macros' in updates and updates['macros'] is not None:
            import json
            updates['macros'] = json.dumps(updates['macros'])
        profile = sigma_db.update_profile(profile_id, updates)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        return profile.to_dict()

    @app.delete("/api/sigma/profiles/{profile_id}")
    async def delete_profile(profile_id: int) -> Dict[str, str]:
        """Delete a Sigma profile."""
        if sigma_db.delete_profile(profile_id):
            return {"message": "Profile deleted successfully"}
        raise HTTPException(status_code=404, detail="Profile not found")

    # Field Mapping endpoints
    @app.get("/api/sigma/profiles/{profile_id}/mappings")
    async def get_profile_mappings(profile_id: int) -> List[Dict[str, Any]]:
        """Get all field mappings for a profile."""
        mappings = sigma_db.get_mappings_for_profile(profile_id)
        return [m.to_dict() for m in mappings]

    @app.post("/api/sigma/profiles/{profile_id}/mappings")
    async def create_mapping(profile_id: int, request: FieldMappingCreate) -> Dict[str, Any]:
        """Create a new field mapping."""
        mapping = FieldMapping(
            profile_id=profile_id,
            sigma_field=request.sigma_field,
            target_field=request.target_field,
            status=MappingStatus(request.status.value) if request.status else MappingStatus.OK,
            category=request.category,
            notes=request.notes,
        )
        created = sigma_db.create_mapping(mapping)
        return created.to_dict()

    @app.patch("/api/sigma/profiles/{profile_id}/mappings/{mapping_id}")
    async def update_mapping(profile_id: int, mapping_id: int, request: FieldMappingUpdate) -> Dict[str, Any]:
        """Update a field mapping."""
        updates = request.model_dump(exclude_unset=True)
        if 'status' in updates and updates['status']:
            updates['status'] = updates['status'].value
        mapping = sigma_db.update_mapping(mapping_id, updates)
        if not mapping:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return mapping.to_dict()

    @app.delete("/api/sigma/profiles/{profile_id}/mappings/{mapping_id}")
    async def delete_mapping(profile_id: int, mapping_id: int) -> Dict[str, str]:
        """Delete a field mapping."""
        if sigma_db.delete_mapping(mapping_id):
            return {"message": "Mapping deleted successfully"}
        raise HTTPException(status_code=404, detail="Mapping not found")

    @app.post("/api/sigma/profiles/{profile_id}/mappings/bulk")
    async def bulk_import_mappings(profile_id: int, request: BulkMappingImport) -> Dict[str, Any]:
        """Bulk import field mappings for a profile."""
        mappings = []
        for m in request.mappings:
            mapping = FieldMapping(
                profile_id=profile_id,
                sigma_field=m.sigma_field,
                target_field=m.target_field,
                status=MappingStatus(m.status.value) if m.status else MappingStatus.OK,
                category=m.category,
                notes=m.notes,
            )
            mappings.append(mapping)
        count = sigma_db.bulk_import_mappings(profile_id, mappings)
        return {"imported": count}

    @app.post("/api/sigma/profiles/{profile_id}/mappings/suggest")
    async def suggest_mappings(profile_id: int, fields: List[str]) -> Dict[str, str]:
        """Get AI-suggested field mappings."""
        suggestions = llm_service.suggest_mappings(fields)
        return suggestions

    # Conversion History endpoints
    @app.get("/api/sigma/history")
    async def get_conversion_history(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        conversion_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get conversion history."""
        conversions = sigma_db.get_conversions(limit=limit, offset=offset, conversion_type=conversion_type)
        return {
            "conversions": [c.to_dict() for c in conversions],
            "limit": limit,
            "offset": offset
        }

    @app.get("/api/sigma/history/{conversion_id}")
    async def get_conversion_detail(conversion_id: int) -> Dict[str, Any]:
        """Get details of a specific conversion."""
        conversion = sigma_db.get_conversion(conversion_id)
        if not conversion:
            raise HTTPException(status_code=404, detail="Conversion not found")
        return conversion.to_dict()

    @app.delete("/api/sigma/history/{conversion_id}")
    async def delete_conversion(conversion_id: int) -> Dict[str, str]:
        """Delete a conversion from history."""
        if sigma_db.delete_conversion(conversion_id):
            return {"message": "Conversion deleted successfully"}
        raise HTTPException(status_code=404, detail="Conversion not found")

    @app.get("/api/sigma/history/stats")
    async def get_conversion_stats() -> Dict[str, Any]:
        """Get conversion statistics."""
        return sigma_db.get_conversion_stats()

    # Sigma LLM Status
    @app.get("/api/sigma/llm/status")
    async def get_sigma_llm_status() -> Dict[str, Any]:
        """Get Sigma Translator LLM status."""
        return {
            "available": llm_service.is_available,
            "provider": llm_service.provider,
            "model": llm_service.model,
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
