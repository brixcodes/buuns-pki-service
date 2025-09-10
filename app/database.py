"""
Configuration et gestion de la base de données pour le PKI Service
Gère les connexions asynchrones, le pool de connexions et les sessions
"""

import logging
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, create_async_engine, 
    async_sessionmaker, AsyncConnection
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text, event
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError
from app.settings import settings
import asyncio
import time

# Configuration du logging
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION DU MOTEUR ====================

def create_database_engine() -> AsyncEngine:
    """
    Crée et configure le moteur de base de données asynchrone
    
    Returns:
        AsyncEngine: Moteur de base de données configuré
        
    Scenarios:
        - Nominal: Moteur créé avec succès
        - Alternatif: Erreur de configuration ou connexion
    """
    try:
        # Configuration avancée du moteur
        engine_config = {
            "echo": settings.is_development_mode(),
            "future": True,
            "pool_size": 10,
            "max_overflow": 20,
            "pool_timeout": 30,
            "pool_recycle": 1800,
            "pool_pre_ping": True,
            "connect_args": {
                "command_timeout": 60,
                "server_settings": {
                    "application_name": "pki_service",
                    "timezone": "UTC"
                }
            }
        }
        
        engine = create_async_engine(
            settings.DATABASE_URL,
            **engine_config
        )
        
        # Ajout d'événements pour le monitoring
        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Configure les paramètres de connexion"""
            logger.debug("Nouvelle connexion à la base de données établie")
        
        @event.listens_for(engine.sync_engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log lors de l'emprunt d'une connexion du pool"""
            logger.debug("Connexion empruntée du pool")
        
        @event.listens_for(engine.sync_engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            """Log lors du retour d'une connexion au pool"""
            logger.debug("Connexion retournée au pool")
        
        logger.info("Moteur de base de données créé avec succès")
        return engine
        
    except Exception as e:
        logger.error(f"Erreur lors de la création du moteur de base de données: {str(e)}")
        raise

# Création du moteur global
engine: AsyncEngine = create_database_engine()

# ==================== CONFIGURATION DES SESSIONS ====================

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

# ==================== GESTION DES SESSIONS ====================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Générateur de session de base de données avec gestion d'erreurs
    
    Yields:
        AsyncSession: Session de base de données
        
    Scenarios:
        - Nominal: Session créée et fermée correctement
        - Alternatif: Erreur de connexion ou de session
    """
    session = None
    try:
        session = AsyncSessionLocal()
        logger.debug("Session de base de données créée")
        yield session
        
    except SQLAlchemyError as e:
        logger.error(f"Erreur SQLAlchemy dans la session: {str(e)}")
        if session:
            await session.rollback()
        raise
        
    except Exception as e:
        logger.error(f"Erreur inattendue dans la session: {str(e)}")
        if session:
            await session.rollback()
        raise
        
    finally:
        if session:
            try:
                await session.close()
                logger.debug("Session de base de données fermée")
            except Exception as e:
                logger.error(f"Erreur lors de la fermeture de la session: {str(e)}")

@asynccontextmanager
async def get_db_transaction() -> AsyncGenerator[AsyncSession, None]:
    """
    Contexte de transaction avec rollback automatique en cas d'erreur
    
    Yields:
        AsyncSession: Session de base de données en transaction
        
    Scenarios:
        - Nominal: Transaction commitée avec succès
        - Alternatif: Transaction rollbackée en cas d'erreur
    """
    session = None
    try:
        session = AsyncSessionLocal()
        logger.debug("Transaction de base de données démarrée")
        yield session
        await session.commit()
        logger.debug("Transaction de base de données commitée")
        
    except Exception as e:
        logger.error(f"Erreur dans la transaction, rollback: {str(e)}")
        if session:
            await session.rollback()
        raise
        
    finally:
        if session:
            try:
                await session.close()
                logger.debug("Transaction de base de données fermée")
            except Exception as e:
                logger.error(f"Erreur lors de la fermeture de la transaction: {str(e)}")

# ==================== UTILITAIRES DE BASE DE DONNÉES ====================

async def check_database_connection() -> bool:
    """
    Vérifie la connexion à la base de données
    
    Returns:
        bool: True si la connexion est établie
        
    Scenarios:
        - Nominal: Connexion réussie
        - Alternatif: Connexion échouée
    """
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            result.fetchone()
        logger.info("Connexion à la base de données vérifiée avec succès")
        return True
        
    except Exception as e:
        logger.error(f"Échec de la vérification de connexion à la base de données: {str(e)}")
        return False

async def get_database_info() -> dict:
    """
    Récupère les informations sur la base de données
    
    Returns:
        dict: Informations sur la base de données
        
    Scenarios:
        - Nominal: Informations récupérées avec succès
        - Alternatif: Erreur lors de la récupération
    """
    try:
        async with engine.begin() as conn:
            # Version PostgreSQL
            version_result = await conn.execute(text("SELECT version()"))
            version = version_result.fetchone()[0]
            
            # Taille de la base de données
            size_result = await conn.execute(text("""
                SELECT pg_size_pretty(pg_database_size(current_database()))
            """))
            size = size_result.fetchone()[0]
            
            # Nombre de connexions actives
            connections_result = await conn.execute(text("""
                SELECT count(*) FROM pg_stat_activity 
                WHERE datname = current_database()
            """))
            connections = connections_result.fetchone()[0]
            
            info = {
                "version": version,
                "size": size,
                "active_connections": connections,
                "database_name": settings.DATABASE_URL.split('/')[-1].split('?')[0]
            }
            
            logger.info(f"Informations de base de données récupérées: {info}")
            return info
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des informations de base de données: {str(e)}")
        return {"error": str(e)}

async def execute_raw_sql(query: str, params: Optional[dict] = None) -> list:
    """
    Exécute une requête SQL brute
    
    Args:
        query: Requête SQL à exécuter
        params: Paramètres de la requête
        
    Returns:
        list: Résultats de la requête
        
    Scenarios:
        - Nominal: Requête exécutée avec succès
        - Alternatif: Erreur SQL ou de connexion
    """
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text(query), params or {})
            rows = result.fetchall()
            logger.debug(f"Requête SQL exécutée: {query[:100]}...")
            return [dict(row._mapping) for row in rows]
            
    except SQLAlchemyError as e:
        logger.error(f"Erreur SQL lors de l'exécution de la requête: {str(e)}")
        raise
        
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'exécution de la requête: {str(e)}")
        raise

# ==================== GESTION DU CYCLE DE VIE ====================

async def close_database_connections():
    """
    Ferme toutes les connexions à la base de données
    
    Scenarios:
        - Nominal: Connexions fermées avec succès
        - Alternatif: Erreur lors de la fermeture
    """
    try:
        await engine.dispose()
        logger.info("Toutes les connexions à la base de données fermées")
        
    except Exception as e:
        logger.error(f"Erreur lors de la fermeture des connexions: {str(e)}")
        raise

# ==================== MONITORING ET MÉTRIQUES ====================

async def get_connection_pool_status() -> dict:
    """
    Récupère le statut du pool de connexions
    
    Returns:
        dict: Statut du pool de connexions
        
    Scenarios:
        - Nominal: Statut récupéré avec succès
        - Alternatif: Erreur lors de la récupération
    """
    try:
        pool = engine.pool
        status = {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "invalid": pool.invalid()
        }
        
        logger.debug(f"Statut du pool de connexions: {status}")
        return status
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut du pool: {str(e)}")
        return {"error": str(e)}

# ==================== INITIALISATION ====================

async def initialize_database():
    """
    Initialise la base de données et vérifie la connexion
    
    Scenarios:
        - Nominal: Base de données initialisée avec succès
        - Alternatif: Erreur d'initialisation
    """
    try:
        # Vérification de la connexion
        if not await check_database_connection():
            raise Exception("Impossible de se connecter à la base de données")
        
        # Récupération des informations
        db_info = await get_database_info()
        logger.info(f"Base de données initialisée: {db_info.get('database_name', 'inconnue')}")
        
        # Statut du pool
        pool_status = await get_connection_pool_status()
        logger.info(f"Pool de connexions: {pool_status}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {str(e)}")
        raise