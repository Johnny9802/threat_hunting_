"""FastAPI REST API for Threat Hunting Playbook."""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
import os
from pathlib import Path

from src.parser import PlaybookParser
from src.search import PlaybookSearch
from src.exporter import QueryExporter
from src.ai_assistant import AIAssistant
from src.mitre_mapping import MitreMapper

# Initialize FastAPI app
app = FastAPI(
    title="Threat Hunting Playbook API",
    description="AI-powered REST API for managing threat hunting playbooks",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
parser = PlaybookParser()
search = PlaybookSearch(parser)
exporter = QueryExporter()
ai = AIAssistant()
mitre = MitreMapper()


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
async def ai_explain(playbook_id: str) -> Dict[str, str]:
    """Get AI explanation of a playbook."""
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available. Configure GROQ_API_KEY or OPENAI_API_KEY")

    try:
        playbook = search.get_by_id(playbook_id)
        explanation = ai.explain_playbook(playbook)

        return {
            "playbook_id": playbook_id,
            "explanation": explanation
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/ask")
async def ai_ask(question: str) -> Dict[str, str]:
    """Ask a question to the AI assistant."""
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        answer = ai.ask_question(question)
        return {
            "question": question,
            "answer": answer
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/suggest")
async def ai_suggest(finding: str, playbook_id: Optional[str] = None) -> Dict[str, str]:
    """Get investigation suggestions based on a finding."""
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        playbook_data = None
        if playbook_id:
            playbook_data = search.get_by_id(playbook_id)

        suggestions = ai.suggest_next_steps(finding, playbook_data)

        return {
            "finding": finding,
            "playbook_id": playbook_id,
            "suggestions": suggestions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/generate")
async def ai_generate(
    playbook_id: str,
    target_env: str,
    target_siem: str
) -> Dict[str, str]:
    """Generate query variant for different environment."""
    if not ai.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        playbook = search.get_by_id(playbook_id)
        variant = ai.generate_variant(playbook, target_env, target_siem)

        return {
            "playbook_id": playbook_id,
            "target_env": target_env,
            "target_siem": target_siem,
            "variant": variant
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
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
