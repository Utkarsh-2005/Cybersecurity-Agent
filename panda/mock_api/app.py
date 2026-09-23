"""FastAPI app initialisation, middleware, and exception handler."""

import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from panda.multiagent.ws_server import ws_router

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AcmeCorp User Management API",
    version="2.1.0",
    description="Internal API for managing AcmeCorp employee accounts and reports.",
)

app.include_router(ws_router)

# Serve the main frontend page
@app.get("/")
async def serve_frontend():
    return FileResponse(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "index.html"))

# Security misconfiguration: wildcard CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# ---------------------------------------------------------------------------
# Middleware — adds info-leak headers to every response
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_server_headers(request: Request, call_next):
    response = await call_next(request)
    # Security misconfiguration: leaking server and framework info
    response.headers["Server"] = "uvicorn/0.30.0"
    response.headers["X-Powered-By"] = "FastAPI/0.115.0"
    # Missing recommended security headers (agent should notice absence)
    # No X-Content-Type-Options
    # No X-Frame-Options
    # No Strict-Transport-Security
    return response


# ---------------------------------------------------------------------------
# Global exception handler — verbose errors (info leak)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def verbose_error_handler(request: Request, exc: Exception):
    """Return detailed error info — a common real-world misconfiguration."""
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": str(exc),
            "path": str(request.url.path),
            "traceback": tb[-3:],  # last 3 frames of stack trace
        },
    )
