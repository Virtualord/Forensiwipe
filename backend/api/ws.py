"""
api/ws.py — WebSocket endpoint for real-time operation progress.

WS /ws/operations/{operation_id}

The frontend connects here immediately after receiving an operation_id
from /api/erase/start.  Progress events are pushed as JSON frames.
The connection closes automatically when the operation reaches a terminal state.

Fallback: if WebSockets are unavailable, the frontend can poll
GET /api/operations/{operation_id} instead.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.core import tasks as task_store
from backend.core.models import OperationStatus, ProgressEvent

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.ws")

_TERMINAL_STATUSES = frozenset({
    OperationStatus.COMPLETED,
    OperationStatus.FAILED,
    OperationStatus.CANCELLED,
})


@router.websocket("/operations/{operation_id}")
async def operation_progress(websocket: WebSocket, operation_id: str) -> None:
    """
    Stream real-time progress events for a specific operation.

    Each frame is a JSON-encoded ProgressEvent.
    The connection is closed by the server when the operation finishes.
    """
    await websocket.accept()
    logger.info("ws_connected op=%s client=%s", operation_id, websocket.client)

    # Verify the operation exists
    op = await task_store.get_operation(operation_id)
    if op is None:
        await websocket.send_json({"error": f"Operation '{operation_id}' not found."})
        await websocket.close(code=4004)
        return

    # If operation is already in a terminal state, send the final state and close.
    if op.status in _TERMINAL_STATUSES:
        await websocket.send_json({
            "operation_id": operation_id,
            "stage": op.current_stage,
            "progress": op.progress,
            "message": op.message or "Operation already completed.",
            "status": op.status,
        })
        await websocket.close()
        return

    # Register a listener to forward events to this WebSocket connection.
    send_queue: asyncio.Queue[ProgressEvent] = asyncio.Queue()

    async def _on_event(event: ProgressEvent) -> None:
        await send_queue.put(event)

    task_store.add_listener(operation_id, _on_event)

    try:
        while True:
            try:
                event = await asyncio.wait_for(send_queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a keep-alive ping
                try:
                    await websocket.send_json({"type": "ping", "operation_id": operation_id})
                except WebSocketDisconnect:
                    break
                continue

            try:
                await websocket.send_json(event.model_dump(mode="json"))
            except WebSocketDisconnect:
                logger.info("ws_disconnected op=%s", operation_id)
                break

            # Close when terminal state is reached.
            if event.status in _TERMINAL_STATUSES:
                logger.info("ws_closing op=%s terminal_status=%s", operation_id, event.status)
                try:
                    await websocket.close()
                except Exception:
                    pass
                break

    except WebSocketDisconnect:
        logger.info("ws_client_disconnected op=%s", operation_id)
    except Exception as exc:
        logger.exception("ws_error op=%s exc=%s", operation_id, exc)
    finally:
        task_store.remove_listener(operation_id, _on_event)
        logger.info("ws_listener_removed op=%s", operation_id)
