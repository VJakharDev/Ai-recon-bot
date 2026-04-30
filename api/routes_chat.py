"""
api/routes_chat.py — Conversational chat endpoint with scan context.
POST /api/chat          — Chat with AI about a scan (streaming SSE)
GET  /api/chat/{id}     — Get chat history for a scan
DELETE /api/chat/{id}   — Clear chat history
"""

import json
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from models.schema import ChatRequest, ChatMessage
from core.memory import get_scan, get_chat_history, save_message, clear_chat_history
from core.llm import llm_engine

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/chat", summary="Chat with AI about a scan")
async def chat(request: ChatRequest):
    """
    Stream an AI response about a scan via Server-Sent Events.
    The client should consume text/event-stream.
    """
    scan = get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("complete", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not ready for chat (status: {scan.status})"
        )

    history = get_chat_history(request.scan_id, limit=20)

    # Save user message
    user_msg = ChatMessage(role="user", content=request.message)
    save_message(request.scan_id, user_msg)

    async def stream_response():
        full_response = ""
        try:
            async for chunk in llm_engine.stream_chat(
                message=request.message,
                scan=scan,
                history=history,
            ):
                full_response += chunk
                # SSE format
                yield f"data: {json.dumps({'content': chunk, 'done': False})}\n\n"

            # Save assistant response
            assistant_msg = ChatMessage(role="assistant", content=full_response)
            save_message(request.scan_id, assistant_msg)

            # Send done signal
            yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"

        except Exception as e:
            logger.error(f"[chat] Stream error: {e}")
            yield f"data: {json.dumps({'content': f'Error: {str(e)}', 'done': True})}\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/chat/sync", summary="Non-streaming chat (for testing)")
async def chat_sync(request: ChatRequest):
    """Non-streaming version of chat — returns full response at once."""
    scan = get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    history = get_chat_history(request.scan_id, limit=20)

    user_msg = ChatMessage(role="user", content=request.message)
    save_message(request.scan_id, user_msg)

    response = await llm_engine.chat(
        message=request.message, scan=scan, history=history
    )

    assistant_msg = ChatMessage(role="assistant", content=response)
    save_message(request.scan_id, assistant_msg)

    return {
        "scan_id": request.scan_id,
        "message": response,
        "role": "assistant",
    }


@router.get("/chat/{scan_id}", summary="Get chat history")
async def get_history(scan_id: str):
    """Retrieve the full chat history for a scan."""
    if not get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    history = get_chat_history(scan_id, limit=100)
    return {
        "scan_id": scan_id,
        "messages": [m.model_dump() for m in history],
        "count": len(history),
    }


@router.delete("/chat/{scan_id}", summary="Clear chat history")
async def clear_history(scan_id: str):
    """Clear all chat messages for a scan."""
    if not get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    clear_chat_history(scan_id)
    return {"success": True, "scan_id": scan_id}
