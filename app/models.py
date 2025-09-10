"""
Modèles de données pour le PKI Service
Définit la structure des tables pour la gestion des clés cryptographiques
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any
import logging

from sqlalchemy import (
    Column, String, DateTime, Boolean, Text, Integer, Index, CheckConstraint
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import declarative_base, validates

logger = logging.getLogger(__name__)

Base = declarative_base(cls=AsyncAttrs)


class KeyPair(Base):
    """
    Table des paires de clés cryptographiques.

    - La clé publique est stockée en PEM.
    - La clé privée est chiffrée (Fernet) puis encodée en hex pour stockage.
    - Des métadonnées et informations de statut permettent le suivi du cycle de vie.
    """

    __tablename__ = "key_pairs"

    # Champs principaux
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    public_key = Column(Text, nullable=False, comment="Clé publique PEM")
    private_key_enc = Column(Text, nullable=False, comment="Clé privée chiffrée (hex)")
    expiry = Column(DateTime(timezone=True), nullable=False, comment="Expiration")
    revoked = Column(Boolean, default=False, nullable=False, comment="Révoquée")
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    reason = Column(String(500), nullable=True, comment="Raison de révocation")

    # Champs avancés
    key_type = Column(String(20), nullable=False, default="RSA", comment="Type de clé")
    key_size = Column(Integer, nullable=False, default=2048, comment="Taille de clé en bits")
    usage_count = Column(Integer, nullable=False, default=0, comment="Compteur d'utilisation")
    last_used_at = Column(DateTime(timezone=True), nullable=True, comment="Dernière utilisation")
    key_metadata = Column(Text, nullable=True, comment="Métadonnées JSON")

    __table_args__ = (
        Index("idx_key_pairs_revoked", "revoked"),
        Index("idx_key_pairs_expiry", "expiry"),
        Index("idx_key_pairs_created_at", "created_at"),
        Index("idx_key_pairs_key_type", "key_type"),
        CheckConstraint("key_size IN (1024, 2048, 3072, 4096, 8192)", name="chk_key_size"),
        CheckConstraint("length(public_key) > 100", name="chk_public_key_len"),
        CheckConstraint("length(private_key_enc) > 100", name="chk_private_key_len"),
    )

    # Validations simples côté modèle
    @validates("public_key")
    def _validate_public_key(self, _key: str, value: str) -> str:
        if not value or len(value) < 100:
            raise ValueError("Clé publique invalide")
        return value

    @validates("private_key_enc")
    def _validate_private_key_enc(self, _key: str, value: str) -> str:
        if not value or len(value) < 100:
            raise ValueError("Clé privée chiffrée invalide")
        # Doit être de l'hex valide
        bytes.fromhex(value)
        return value

    # Méthodes utilitaires
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expiry

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    def days_until_expiry(self) -> int:
        return (self.expiry - datetime.now(timezone.utc)).days

    def increment_usage(self) -> None:
        self.usage_count += 1
        self.last_used_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def revoke(self, reason: str) -> None:
        if self.revoked:
            raise ValueError("La clé est déjà révoquée")
        self.revoked = True
        self.reason = reason
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "expiry": self.expiry.isoformat() if self.expiry else None,
            "revoked": self.revoked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "reason": self.reason,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

    def __repr__(self) -> str:
        status = "REVOKED" if self.revoked else ("EXPIRED" if self.is_expired() else "VALID")
        return f"<KeyPair id={self.id} type={self.key_type} size={self.key_size} status={status}>"