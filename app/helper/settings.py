"""
Configuration centralisée pour le PKI Service
Gère tous les paramètres de sécurité, base de données et services externes
"""

import logging
from pathlib import Path
from typing import Optional, List
from pydantic import field_validator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
import re

# Configuration du logging
logger = logging.getLogger(__name__)

# Chargement du fichier .env
# Recherche prioritaire: racine du projet puis dossier app/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).resolve().parent.parent
_env_candidates = [
    PROJECT_ROOT / ".env",
    APP_DIR / ".env",
]
ENV_FILE_PATH = next((p for p in _env_candidates if p.exists()), _env_candidates[0])
load_dotenv(ENV_FILE_PATH)
logger.info(f"Fichier .env chargé depuis: {ENV_FILE_PATH}")

class Settings(BaseSettings):
    """
    Configuration centralisée du PKI Service
    
    Cette classe gère tous les paramètres de configuration nécessaires au bon fonctionnement
    du service PKI, incluant la sécurité, la base de données, Redis et les services externes.
    
    Attributes:
        DATABASE_URL (str): URL de connexion à la base de données PostgreSQL
        REDIS_HOST (str): Adresse IP ou hostname du serveur Redis
        REDIS_PORT (int): Port du serveur Redis (défaut: 6379)
        REDIS_DB (int): Numéro de base de données Redis à utiliser
        REDIS_PASSWORD (Optional[str]): Mot de passe Redis (optionnel)
        HSM_DEVICE (str): Chemin vers le périphérique HSM
        HSM_PIN (str): PIN pour accéder au HSM
        HSM_KEY_HANDLE (int): Handle de la clé dans le HSM
        JWT_SECRET (str): Clé secrète pour la signature JWT
        FERNET_KEY (str): Clé Fernet pour le chiffrement des clés privées
        ALLOWED_ORIGINS (str): Origines CORS autorisées
        LOG_LEVEL (str): Niveau de logging (DEBUG, INFO, WARNING, ERROR)
        MAX_KEY_LIFETIME_DAYS (int): Durée maximale de vie d'une clé en jours
        KEY_ROTATION_THRESHOLD_DAYS (int): Seuil de rotation automatique des clés
    """
    
    # ==================== BASE DE DONNÉES ====================
    DATABASE_URL: str = Field(
        ...,
        description="URL de connexion à la base de données PostgreSQL",
        examples=["postgresql+asyncpg://user:password@localhost:5432/pki_db"]
    )
    
    # ==================== REDIS ====================
    REDIS_HOST: str = Field(
        default="localhost",
        description="Adresse IP ou hostname du serveur Redis"
    )
    REDIS_PORT: int = Field(
        default=6379,
        ge=1,
        le=65535,
        description="Port du serveur Redis"
    )
    REDIS_DB: int = Field(
        default=0,
        ge=0,
        le=15,
        description="Numéro de base de données Redis"
    )
    REDIS_PASSWORD: Optional[str] = Field(
        default=None,
        description="Mot de passe Redis (optionnel)"
    )
    
    # ==================== SÉCURITÉ ====================
    HSM_DEVICE: str = Field(
        ...,
        description="Chemin vers le périphérique HSM",
        examples=["/dev/hsm", "\\\\.\\HSM"]
    )
    HSM_PIN: str = Field(
        ...,
        min_length=4,
        max_length=32,
        description="PIN pour accéder au HSM"
    )
    HSM_KEY_HANDLE: int = Field(
        default=1,
        ge=1,
        le=65535,
        description="Handle de la clé dans le HSM"
    )
    JWT_SECRET: str = Field(
        ...,
        min_length=32,
        description="Clé secrète pour la signature JWT (minimum 32 caractères)"
    )
    FERNET_KEY: str = Field(
        ...,
        description="Clé Fernet pour le chiffrement des clés privées"
    )
    
    # ==================== CORS ET SÉCURITÉ WEB ====================
    ALLOWED_ORIGINS: str = Field(
        default="*",
        description="Origines CORS autorisées (séparées par des virgules)"
    )
    
    # ==================== CONFIGURATION AVANCÉE ====================
    LOG_LEVEL: str = Field(
        default="WARNING",
        description="Niveau de logging"
    )
    MAX_KEY_LIFETIME_DAYS: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Durée maximale de vie d'une clé en jours"
    )
    KEY_ROTATION_THRESHOLD_DAYS: int = Field(
        default=30,
        ge=1,
        le=90,
        description="Seuil de rotation automatique des clés en jours"
    )
    
    # ==================== CONFIGURATION PYDANTIC ====================
    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH,
        env_file_encoding="utf-8",
        case_sensitive=False,
        validate_assignment=True,
        extra="forbid"
    )
    
    # ==================== VALIDATEURS ====================
    
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        """
        Valide l'URL de la base de données
        
        Args:
            value: URL de la base de données
            
        Returns:
            str: URL validée
            
        Raises:
            ValueError: Si l'URL est invalide ou manquante
            
        Scenarios:
            - Nominal: URL PostgreSQL valide avec asyncpg
            - Alternatif: URL manquante ou malformée
        """
        if not value:
            logger.error("DATABASE_URL manquante dans la configuration")
            raise ValueError("DATABASE_URL doit être définie")
        
        if not re.match(r'^postgresql\+asyncpg://', value):
            logger.warning("DATABASE_URL ne semble pas être une URL PostgreSQL avec asyncpg")
        
        logger.info("URL de base de données validée avec succès")
        return value
    
    @field_validator("HSM_DEVICE", "HSM_PIN", "JWT_SECRET", "FERNET_KEY", mode="before")
    @classmethod
    def validate_secrets(cls, value: str, info) -> str:
        """
        Valide les paramètres de sécurité critiques
        
        Args:
            value: Valeur du paramètre
            field: Champ Pydantic
            
        Returns:
            str: Valeur validée
            
        Raises:
            ValueError: Si la valeur est manquante ou invalide
            
        Scenarios:
            - Nominal: Paramètre de sécurité valide
            - Alternatif: Paramètre manquant ou trop court
        """
        field_name = getattr(info, "field_name", None)
        if not value:
            logger.error(f"Paramètre de sécurité manquant: {field_name}")
            raise ValueError(f"{field_name} doit être défini pour la sécurité")
        
        if field_name == "JWT_SECRET" and len(value) < 32:
            logger.error("JWT_SECRET trop courte (minimum 32 caractères)")
            raise ValueError("JWT_SECRET doit contenir au moins 32 caractères")
        
        if field_name == "HSM_PIN" and len(value) < 4:
            logger.error("HSM_PIN trop courte (minimum 4 caractères)")
            raise ValueError("HSM_PIN doit contenir au moins 4 caractères")
        
        logger.info(f"Paramètre de sécurité validé: {field_name}")
        return value
    
    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def validate_cors_origins(cls, value: str) -> str:
        """
        Valide les origines CORS
        
        Args:
            value: Origines CORS séparées par des virgules
            
        Returns:
            str: Origines validées
            
        Scenarios:
            - Nominal: Origines valides ou "*"
            - Alternatif: Origines malformées
        """
        if value == "*":
            logger.warning("CORS configuré pour accepter toutes les origines")
            return value
        
        origins = [origin.strip() for origin in value.split(",")]
        for origin in origins:
            if not re.match(r'^https?://', origin):
                logger.warning(f"Origine CORS suspecte: {origin}")
        
        logger.info(f"Origines CORS validées: {len(origins)} origine(s)")
        return value
    
    def get_allowed_origins_list(self) -> List[str]:
        """
        Retourne la liste des origines CORS autorisées
        
        Returns:
            List[str]: Liste des origines autorisées
        """
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
    
    def is_development_mode(self) -> bool:
        """
        Détermine si le service est en mode développement
        
        Returns:
            bool: True si en mode développement
        """
        return self.LOG_LEVEL.upper() == "DEBUG"
    
    def get_database_config(self) -> dict:
        """
        Retourne la configuration de la base de données
        
        Returns:
            dict: Configuration de la base de données
        """
        return {
            "url": self.DATABASE_URL,
            "pool_size": 10,
            "max_overflow": 20,
            "pool_timeout": 10,
            "pool_recycle": 1800,
            "echo": self.is_development_mode()
        }
    
    def get_redis_config(self) -> dict:
        """
        Retourne la configuration Redis
        
        Returns:
            dict: Configuration Redis
        """
        return {
            "host": self.REDIS_HOST,
            "port": self.REDIS_PORT,
            "db": self.REDIS_DB,
            "password": self.REDIS_PASSWORD,
            "max_connections": 100,
            "socket_timeout": 5
        }

# Instance globale des paramètres
settings = Settings()

# Validation finale
try:
    logger.info("Configuration PKI Service chargée avec succès")
    logger.info(f"Base de données: {settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else 'configurée'}")
    logger.info(f"Redis: {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    logger.info(f"HSM: {settings.HSM_DEVICE}")
    logger.info(f"Origines CORS: {len(settings.get_allowed_origins_list())} origine(s)")
except Exception as e:
    logger.error(f"Erreur lors du chargement de la configuration: {str(e)}")
    raise