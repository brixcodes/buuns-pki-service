"""
Routes HTTP du PKI Service
Expose des endpoints documentés pour gérer les paires de clés.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas import KeyPairCreate, KeyPairOut, RevokeRequest, RotateRequest
from app.services import PKIService
from app.dependencies import get_current_user
from app.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/keys", tags=["keys"])


@router.post("/generate", response_model=KeyPairOut, status_code=status.HTTP_201_CREATED)
async def generate_keys(
    create: KeyPairCreate,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user())
):
    """
    Génère une nouvelle paire de clés.

    Scénario nominal:
    - L'utilisateur authentifié demande la création d'une paire de clés. Le service génère
      une clé privée et publique, chiffre la clé privée et retourne la ressource créée.

    Cas alternatifs:
    - Paramètres invalides -> 400
    - Erreur interne lors de la création -> 500
    """
    service = PKIService(db)
    # Utilise les paramètres optionnels du client, tout en générant la clé côté serveur
    return await service.create_key_pair(
        key_type=create.key_type,
        key_size=create.key_size,
        curve_name=create.curve_name,
        expiry_days=create.expiry_days,
    )


@router.get("/{key_id}", response_model=KeyPairOut)
async def get_public_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user())
):
    """
    Récupère une paire de clés par ID.

    Scénario nominal:
    - Retourne la paire si elle existe et est valide (non révoquée, non expirée).

    Cas alternatifs:
    - ID invalide -> 400
    - Non trouvée -> 404
    - Expirée ou révoquée -> 410
    """
    service = PKIService(db)
    key = await service.get_key_pair(key_id, increment_usage=False)
    return key


@router.post("/revoke", response_model=KeyPairOut)
async def revoke(
    req: RevokeRequest,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user("admin"))
):
    """
    Révoque une clé existante.

    Scénario nominal:
    - Marque la clé comme révoquée avec une raison.

    Cas alternatifs:
    - Clé déjà révoquée -> 400
    - Clé introuvable -> 404
    """
    service = PKIService(db)
    return await service.revoke_key(req.key_id, req.reason, user_id=user["user"])


@router.post("/rotate", response_model=KeyPairOut)
async def rotate(
    req: RotateRequest,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user("admin"))
):
    """
    Effectue la rotation d'une clé (révoque l'ancienne, crée une nouvelle avec même profil).

    Scénario nominal:
    - Révocation puis création d'une nouvelle clé avec même type et taille, même durée restante.

    Cas alternatifs:
    - Clé révoquée -> 400
    - Clé introuvable -> 404
    - Erreur de création -> 500
    """
    service = PKIService(db)
    return await service.rotate_key(req.key_id, user_id=user["user"])