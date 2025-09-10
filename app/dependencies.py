"""
Dépendances et helpers sécurité pour le PKI Service
Inclut l'initialisation Fernet (depuis settings) et l'authentification JWT.
"""

from cryptography.fernet import Fernet
import logging
from app.settings import settings

logger = logging.getLogger(__name__)

# Initialisation Fernet depuis settings (source unique de vérité)
try:
    _fernet_key = settings.FERNET_KEY
    fernet = Fernet(_fernet_key.encode() if isinstance(_fernet_key, str) else _fernet_key)
    logger.info("Clé Fernet chargée avec succès depuis settings")
except Exception as e:
    logger.error(f"Erreur lors du chargement de la clé Fernet : {str(e)}")
    raise ValueError("Clé Fernet invalide dans la configuration")


def encrypt_private_key(data: bytes) -> bytes:
    """Chiffre la clé privée avec Fernet (AES-128, HMAC, TTL facultatif)."""
    return fernet.encrypt(data)


def decrypt_private_key(token: bytes) -> bytes:
    """Déchiffre la clé privée avec Fernet."""
    return fernet.decrypt(token)
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.settings import settings
import redis.asyncio as redis
import logging
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager
import asyncio

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    max_retries = 3
    retry_delay = 1
    for attempt in range(max_retries):
        try:
            client = await redis.from_url(
                f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}",
                password=settings.REDIS_PASSWORD,
                decode_responses=True,
                max_connections=100,
                socket_timeout=5,
            )
            await client.ping()
            logger.info("Connexion à Redis réussie")
            yield client
            await client.close()
            return
        except redis.RedisError as e:
            logger.error(f"Échec de la connexion à Redis (tentative {attempt + 1}) : {str(e)}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Unable to connect to Redis"
                )

def get_current_user(required_role: Optional[str] = None):
    async def _get_user(token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=["HS256"]
            )
            user = payload.get("sub")
            roles = payload.get("roles", [])
            if user is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur non authentifié")
            if required_role and required_role not in roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès interdit : rôle insuffisant")
            return {"user": user, "roles": roles}
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    return _get_user

