"""
Module principal de l'application PKI Service.

Ce module configure et initialise l'application FastAPI pour le service PKI,
incluant les middlewares de sécurité, la configuration CORS, le logging,
et les endpoints de santé et métriques.

Architecture:
- FastAPI avec middlewares de sécurité (CORS, TrustedHost, GZip)
- Logging structuré avec niveaux configurables
- Endpoints de monitoring (/health, /ready, /metrics)
- Middleware de tracing avec x-trace-id
- Initialisation automatique de la base de données

Scénarios:
- Nominal: Application démarre correctement, middlewares actifs, DB initialisée
- Alternatif: Erreur de configuration → logs d'erreur, application non fonctionnelle
- Alternatif: Erreur DB → logs d'erreur, endpoints de santé disponibles mais fonctionnalités limitées
"""

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.routers import router
from app.database import engine, check_database_connection
from app.models import Base
import logging
import uuid
from app.settings import settings

# Configuration de l'application
DESCRIPTION = """
🔐 **PKI Service - Infrastructure de Gestion de Clés Cryptographiques**

Service microservice sécurisé pour la génération, le stockage chiffré, la révocation,
la rotation et la consultation de paires de clés cryptographiques (RSA, ECDSA, Ed25519).

**Fonctionnalités principales:**
- 🔑 Génération de clés avec validation et chiffrement Fernet
- 🛡️ Stockage sécurisé avec expiration et révocation
- 🔄 Rotation automatique des clés
- 📊 Statistiques et monitoring complet
- 🔒 Authentification JWT et autorisation par rôles
- 📈 Métriques Prometheus et observabilité

**Sécurité:**
- Clés privées chiffrées avec Fernet
- Authentification JWT obligatoire
- CORS configuré et TrustedHost activé
- Logs structurés avec tracing
- Validation stricte des entrées

**Architecture:**
- FastAPI asynchrone avec SQLAlchemy 2.0
- PostgreSQL pour la persistance
- Redis pour le cache (optionnel)
- Celery pour les tâches asynchrones
- Alembic pour les migrations
"""
VERSION = "1.0.0"

# Initialisation de l'application FastAPI
app = FastAPI(
    title="PKI Service",
    description=DESCRIPTION,
    version=VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configuration du logging structuré
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.WARNING),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("pki-service")

# Middleware de compression GZip (optimisation performance)
app.add_middleware(GZipMiddleware, minimum_size=500)

# Middleware de sécurité - Hosts de confiance
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.localhost", "*.angara.vertex-cam.com"]
)

# Configuration CORS sécurisée
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins_list(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Trace-ID", "X-Request-ID"]
)

@app.on_event("startup")
async def startup_event():
    """
    Gère les événements de démarrage de l'application.
    Initialise la base de données et vérifie sa connexion.
    
    Scénarios:
    - Nominal: La base de données est initialisée et les tables sont créées/vérifiées.
    - Alternatif: Une erreur se produit lors de l'initialisation de la base de données,
      le service ne démarre pas correctement.
    """
    logger.info("Démarrage du service PKI...")
    try:
        # Initialisation de la base de données (création des tables si elles n'existent pas)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Tables de la base de données créées/vérifiées avec succès.")
        
        # Vérification de la connexion à la base de données
        if not await check_database_connection():
            raise ConnectionError("La connexion à la base de données a échoué au démarrage.")
        
        logger.info("Service PKI prêt à recevoir des requêtes.")
    except Exception as e:
        logger.critical(f"Échec critique au démarrage du service PKI: {str(e)}")
        # En production, on pourrait vouloir quitter l'application ici
        # sys.exit(1) # Décommenter pour forcer l'arrêt en cas d'échec critique

# Inclusion des routes de l'API
app.include_router(router)

# Endpoints de santé et de préparation
@app.get("/health", include_in_schema=False, tags=["Monitoring"])
async def health() -> dict:
    """
    Endpoint de santé (liveness probe).
    
    Vérifie que l'application est en vie et répond aux requêtes.
    Utilisé par Kubernetes et les load balancers pour détecter
    si le service doit être redémarré.
    
    Returns:
        dict: Statut de santé de l'application
        
    Scénarios:
    - Nominal: Retourne {"status": "ok"} si l'application fonctionne
    - Alternatif: Timeout ou erreur → le service est considéré comme down
    """
    return {"status": "ok", "service": "pki", "version": VERSION}

@app.get("/ready", include_in_schema=False, tags=["Monitoring"])
async def ready() -> dict:
    """
    Endpoint de préparation (readiness probe).
    
    Vérifie que l'application est prête à recevoir du trafic.
    Différent de /health car il peut vérifier des dépendances
    comme la base de données, Redis, etc.
    
    Returns:
        dict: Statut de préparation de l'application
        
    Scénarios:
    - Nominal: Retourne {"status": "ready"} si toutes les dépendances sont OK
    - Alternatif: DB inaccessible → {"status": "not_ready"} → pas de trafic
    """
    try:
        # Vérification de la connexion à la base de données
        db_ready = await check_database_connection()
        if db_ready:
            return {"status": "ready", "service": "pki", "version": VERSION}
        else:
            return {"status": "not_ready", "reason": "database_unavailable"}
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de préparation: {str(e)}")
        return {"status": "not_ready", "reason": "check_failed"}

# Middleware de tracing et métriques
@app.middleware("http")
async def trace_and_metrics(request: Request, call_next):
    """
    Middleware de tracing et collecte de métriques.
    
    Ajoute un trace ID à chaque requête pour le suivi des logs
    et collecte des métriques de base (nombre de requêtes).
    
    Args:
        request: Requête HTTP entrante
        call_next: Fonction pour traiter la requête suivante
        
    Returns:
        Response: Réponse HTTP avec headers de tracing
        
    Scénarios:
    - Nominal: Trace ID ajouté, métriques incrémentées, réponse retournée
    - Alternatif: Erreur dans le middleware → trace ID manquant dans les logs
    """
    # Génération ou récupération du trace ID
    trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())
    
    # Initialisation du compteur de requêtes si nécessaire
    if not hasattr(app.state, "request_count"):
        app.state.request_count = 0
    app.state.request_count += 1
    
    # Traitement de la requête
    response = await call_next(request)
    
    # Ajout du trace ID dans les headers de réponse
    response.headers["x-trace-id"] = trace_id
    
    # Log de la requête avec trace ID
    logger.info(f"Request {request.method} {request.url.path} - Trace ID: {trace_id}")
    
    return response

@app.get("/metrics", include_in_schema=False, response_class=PlainTextResponse, tags=["Monitoring"])
async def metrics() -> str:
    """
    Endpoint de métriques Prometheus.
    
    Fournit des métriques au format Prometheus pour le monitoring
    de l'application. Inclut le nombre total de requêtes et
    des informations statiques sur le service.
    
    Returns:
        str: Métriques au format Prometheus
        
    Scénarios:
    - Nominal: Retourne les métriques au format Prometheus
    - Alternatif: Erreur de collecte → métriques partielles ou vides
    """
    total_requests = getattr(app.state, "request_count", 0)
    
    # Format Prometheus
    lines = [
        "# HELP service_requests_total Total number of HTTP requests",
        "# TYPE service_requests_total counter",
        f"service_requests_total{{service=\"pki-service\",version=\"{VERSION}\"}} {total_requests}",
        "",
        "# HELP service_info Service static information",
        "# TYPE service_info gauge",
        f"service_info{{service=\"pki-service\",version=\"{VERSION}\"}} 1",
        "",
        "# HELP service_uptime_seconds Service uptime in seconds",
        "# TYPE service_uptime_seconds gauge",
        f"service_uptime_seconds{{service=\"pki-service\"}} {getattr(app.state, 'startup_time', 0)}",
    ]
    
    return "\n".join(lines) + "\n"