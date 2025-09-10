from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.routers import router
from app.database import engine
from app.models import Base
import logging
from app.settings import settings

DESCRIPTION = """
Service PKI pour la gestion des clés et certificats.
Fournit des API sécurisées pour générer, révoquer, faire tourner et consulter les clés.
"""
VERSION = "1.0.0"

app = FastAPI(
    title="PKI Service",
    description=DESCRIPTION,
    version=VERSION
)
app.add_middleware(GZipMiddleware, minimum_size=500)

# Security middleware - Trusted hosts
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.localhost"]
)

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("pki-service")

# Configuration CORS sécurisée
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS.split(",") if settings.ALLOWED_ORIGINS != "*" else ["https://localhost:3000", "https://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Trace-ID"]
)

@app.on_event("startup")
async def startup_event():
    logger.info("Démarrage du service PKI...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Tables de la base de données créées avec succès.")
    except Exception as e:
        logger.error(f"Erreur lors de la création des tables : {str(e)}")
    logger.info("Service PKI prêt à recevoir des requêtes.")

app.include_router(router)

# Health and readiness endpoints
@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}

@app.get("/ready", include_in_schema=False)
async def ready() -> dict:
    return {"status": "ready"}

# Minimal trace id middleware and metrics
@app.middleware("http")
async def trace_and_metrics(request: Request, call_next):
    trace_id = request.headers.get("x-trace-id") or __import__("uuid").uuid4().hex
    if not hasattr(app.state, "request_count"):
        app.state.request_count = 0
    app.state.request_count += 1
    response = await call_next(request)
    response.headers["x-trace-id"] = trace_id
    return response

@app.get("/metrics", include_in_schema=False, response_class=PlainTextResponse)
async def metrics() -> str:
    total = getattr(app.state, "request_count", 0)
    lines = [
        "# HELP service_requests_total Total requests",
        "# TYPE service_requests_total counter",
        f"service_requests_total{{service=\"pki\"}} {total}",
        "# HELP service_info Service static info",
        "# TYPE service_info gauge",
        f"service_info{{service=\"pki\",version=\"{VERSION}\"}} 1",
    ]
    return "\n".join(lines) + "\n"