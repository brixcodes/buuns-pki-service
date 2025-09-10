"""
Schémas Pydantic pour le PKI Service
Valide et documente les payloads d'entrée/sortie des routes.
"""

from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class KeyPairBase(BaseModel):
    """Base commune pour les représentations de paires de clés."""
    public_key: str = Field(..., description="Clé publique PEM")
    expiry: datetime = Field(..., description="Date d'expiration de la clé")
    key_type: Literal["RSA", "ECDSA", "Ed25519"] | None = Field(None, description="Type de clé")
    key_size: int | None = Field(None, description="Taille de la clé (RSA)")


class KeyPairCreate(BaseModel):
    """
    Paramètres optionnels pour la création côté serveur.
    Les clés sont générées côté serveur; ces champs pilotent le type souhaité.
    """
    key_type: Literal["RSA", "ECDSA", "Ed25519"] = Field("RSA")
    key_size: int | None = Field(None, ge=1024, le=8192)
    curve_name: Literal["P-256", "P-384", "P-521"] | None = None
    expiry_days: int = Field(365, ge=1, le=3650)


class KeyPairOut(KeyPairBase):
    id: str = Field(..., description="Identifiant unique de la paire de clés")
    created_at: datetime = Field(..., description="Date de création")
    updated_at: datetime | None = Field(None, description="Dernière mise à jour")
    revoked: bool = Field(..., description="Statut de révocation")
    reason: Optional[str] = Field(None, description="Raison de révocation")
    usage_count: int | None = Field(None, description="Compteur d'utilisation")

    class Config:
        from_attributes = True


class RevokeRequest(BaseModel):
    key_id: str = Field(..., description="ID de la clé à révoquer")
    reason: str = Field(..., min_length=3, max_length=500, description="Raison de la révocation")


class RotateRequest(BaseModel):
    key_id: str = Field(..., description="ID de la clé à faire tourner")