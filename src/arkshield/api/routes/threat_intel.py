import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Body
from arkshield.api import server

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

@router.get("/shared-threats")
async def intel_shared_threats(skip: int = 0, limit: int = 50):
    """Phase 140: Return cross-tenant shared threat intelligence with pagination."""
    safe_skip = max(0, int(skip)) if str(skip).isdigit() else 0
    safe_limit = max(1, min(int(limit), 500)) if str(limit).isdigit() else 50
    items = list(server._shared_threats)[safe_skip : safe_skip + safe_limit]
    return {
        "count": len(server._shared_threats),
        "skip": safe_skip,
        "limit": safe_limit,
        "items": items
    }


@router.post("/share-threat")
async def intel_share_threat(payload: Dict[str, Any] = Body(default_factory=dict)):
    """Phase 140: Share threat indicator with tenants."""
    threat = {
        "id": f"st-{uuid.uuid4().hex[:8]}",
        "indicator": payload.get("indicator", "unknown-ioc"),
        "type": payload.get("type", "domain"),
        "severity": payload.get("severity", "high"),
        "shared_at": datetime.now(timezone.utc).isoformat(),
    }
    server._shared_threats.append(threat)
    return {"status": "shared", "threat": threat}
