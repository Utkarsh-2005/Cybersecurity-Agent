"""WebSocket server for streaming live PANDA execution events to the frontend."""

import asyncio
import json
import threading
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from panda.multiagent.pipeline import run_panda_assessment
from panda.multiagent.utils import register_event_callback, unregister_event_callback

ws_router = APIRouter()


@ws_router.websocket("/ws/run")
async def websocket_run(websocket: WebSocket):
    await websocket.accept()
    
    # Wait for the configuration payload from the client
    try:
        config_msg = await websocket.receive_text()
        config = json.loads(config_msg)
    except Exception:
        await websocket.close(code=1003, reason="Invalid config payload")
        return

    target_url = config.get("target_url", "http://127.0.0.1:8000")
    allow_write = config.get("allow_write", False)

    # Queue to pass events from the background thread to the async websocket handler
    event_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    loop = asyncio.get_running_loop()

    def event_callback(event: dict[str, Any]) -> None:
        # We need to put the event into the queue.
        # Since this callback is called from a background thread, we use call_soon_threadsafe
        loop.call_soon_threadsafe(event_queue.put_nowait, event)

    register_event_callback(event_callback)

    def run_pipeline() -> None:
        try:
            run_panda_assessment(target_url=target_url, allow_write=allow_write)
        except Exception as e:
            # Let the frontend know if the pipeline crashed completely
            loop.call_soon_threadsafe(
                event_queue.put_nowait,
                {"type": "error", "agent": "system", "action": "crash", "detail": str(e)}
            )
        finally:
            # Signal the end of the stream
            loop.call_soon_threadsafe(event_queue.put_nowait, None)

    # Run the assessment in a background thread
    pipeline_thread = threading.Thread(target=run_pipeline)
    pipeline_thread.start()

    try:
        while True:
            # Get event from the background thread
            event = await event_queue.get()
            if event is None:
                break # Pipeline finished
            
            # Send event to the frontend
            await websocket.send_json(event)
    except WebSocketDisconnect:
        print("[ws] Client disconnected")
    except Exception as e:
        print(f"[ws] Error sending event: {e}")
    finally:
        unregister_event_callback(event_callback)
