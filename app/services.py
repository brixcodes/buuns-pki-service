"""
Service PKI pour la gestion des clés cryptographiques
Gère la création, récupération, révocation et rotation des paires de clés
"""

import uuid
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func, desc, asc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.models import KeyPair
from app.utils import (
    generate_ml_dsa_keys, validate_public_key, validate_private_key,
    generate_key_fingerprint, get_supported_key_types, estimate_key_generation_time
)
from app.dependencies import encrypt_private_key, decrypt_private_key
from app.settings import settings
from fastapi import HTTPException, status
import logging

# Configuration du logging
logger = logging.getLogger(__name__)

class PKIService:
    """
    Service PKI pour la gestion des clés cryptographiques
    
    Ce service gère toutes les opérations liées aux clés cryptographiques :
    - Génération de nouvelles paires de clés
    - Récupération et validation des clés existantes
    - Révocation et rotation des clés
    - Monitoring et statistiques des clés
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialise le service PKI
        
        Args:
            db: Session de base de données asynchrone
        """
        self.db = db
        self.logger = logging.getLogger(__name__)
        self.supported_key_types = get_supported_key_types()
    
    # ==================== CRÉATION DE CLÉS ====================
    
    async def create_key_pair(
        self, 
        key_type: str = "RSA",
        key_size: Optional[int] = None,
        curve_name: Optional[str] = None,
        expiry_days: int = 365,
        metadata: Optional[Dict[str, Any]] = None
    ) -> KeyPair:
        """
        Crée une nouvelle paire de clés cryptographiques
        
        Args:
            key_type: Type de clé (RSA, ECDSA, Ed25519)
            key_size: Taille de la clé pour RSA (1024, 2048, 3072, 4096, 8192)
            curve_name: Nom de la courbe pour ECDSA (P-256, P-384, P-521)
            expiry_days: Nombre de jours avant expiration
            metadata: Métadonnées optionnelles pour la clé
            
        Returns:
            KeyPair: Paire de clés créée
            
        Raises:
            HTTPException: Si la création échoue
            
        Scenarios:
            - Nominal: Paire de clés créée avec succès
            - Alternatif: Paramètres invalides, erreur de génération, erreur de base de données
        """
        start_time = time.time()
        
        try:
            # Validation des paramètres
            self._validate_key_creation_params(key_type, key_size, curve_name, expiry_days)
            
            # Génération des clés
            generation_params = self._prepare_generation_params(key_type, key_size, curve_name)
            pub_bytes, priv_bytes = generate_ml_dsa_keys(key_type, **generation_params)
            
            # Validation des clés générées
            pub_info = validate_public_key(pub_bytes)
            priv_info = validate_private_key(priv_bytes)
            
            # Chiffrement de la clé privée
            priv_enc = encrypt_private_key(priv_bytes)
            
            # Calcul de la date d'expiration
            expiry = datetime.now(timezone.utc) + timedelta(days=expiry_days)
            
            # Création de l'objet KeyPair
            key_pair = KeyPair(
                public_key=pub_bytes.decode('utf-8'),
                private_key_enc=priv_enc.hex(),
                expiry=expiry,
                key_type=key_type.upper(),
                key_size=key_size or self._get_default_key_size(key_type),
                key_metadata=self._serialize_metadata(metadata) if metadata else None
            )
            
            # Sauvegarde en base de données
            self.db.add(key_pair)
            await self.db.commit()
            await self.db.refresh(key_pair)
            
            # Mise à jour des métriques
            generation_time = time.time() - start_time
            key_pair.increment_usage()  # Compte la création comme une utilisation
            await self.db.commit()

            self.logger.info(
                f"Paire de clés créée avec succès - "
                f"ID: {key_pair.id}, Type: {key_type}, "
                f"Taille: {key_pair.key_size}, Temps: {generation_time:.2f}s"
            )
            
            return key_pair
            
        except HTTPException:
            await self.db.rollback()
            raise
        except SQLAlchemyError as e:
            await self.db.rollback()
            self.logger.error(f"Erreur SQLAlchemy lors de la création de la paire de clés: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur de base de données lors de la création de la paire de clés"
            )
        except Exception as e:
            await self.db.rollback()
            self.logger.error(f"Erreur inattendue lors de la création de la paire de clés: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur lors de la création de la paire de clés: {str(e)}"
            )
    
    async def create_batch_key_pairs(
        self, 
        count: int, 
        key_type: str = "RSA",
        **kwargs
    ) -> List[KeyPair]:
        """
        Crée plusieurs paires de clés en lot
        
        Args:
            count: Nombre de paires de clés à créer
            key_type: Type de clé
            **kwargs: Paramètres additionnels
            
        Returns:
            List[KeyPair]: Liste des paires de clés créées
            
        Scenarios:
            - Nominal: Toutes les paires de clés créées avec succès
            - Alternatif: Erreur lors de la création d'une ou plusieurs clés
        """
        if count <= 0 or count > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le nombre de clés doit être entre 1 et 100"
            )
        
        created_keys = []
        failed_count = 0
        
        for i in range(count):
            try:
                key_pair = await self.create_key_pair(key_type=key_type, **kwargs)
                created_keys.append(key_pair)
            except Exception as e:
                failed_count += 1
                self.logger.error(f"Échec de création de la clé {i+1}/{count}: {str(e)}")
        
        self.logger.info(f"Création en lot terminée: {len(created_keys)}/{count} clés créées")
        
        if failed_count > 0:
            raise HTTPException(
                status_code=status.HTTP_207_MULTI_STATUS,
                detail=f"Création partielle: {len(created_keys)}/{count} clés créées, {failed_count} échecs"
            )
        
        return created_keys
    
    # ==================== RÉCUPÉRATION DE CLÉS ====================
    
    async def get_key_pair(self, key_id: str, increment_usage: bool = True) -> KeyPair:
        """
        Récupère une paire de clés par son ID
        
        Args:
            key_id: Identifiant de la paire de clés
            increment_usage: Si True, incrémente le compteur d'utilisation
            
        Returns:
            KeyPair: Paire de clés trouvée
            
        Raises:
            HTTPException: Si la clé n'est pas trouvée
            
        Scenarios:
            - Nominal: Clé trouvée et retournée
            - Alternatif: Clé introuvable, clé expirée, clé révoquée
        """
        try:
            # Validation de l'ID
            if not self._is_valid_uuid(key_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Format d'ID de clé invalide"
                )
            
            # Recherche de la clé
            result = await self.db.execute(
                select(KeyPair).filter(KeyPair.id == key_id)
            )
            key_pair = result.scalar_one_or_none()
            
            if not key_pair:
                self.logger.warning(f"Paire de clés introuvable (ID: {key_id})")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Paire de clés introuvable"
                )
            
            # Vérification du statut de la clé
            if key_pair.is_expired():
                self.logger.warning(f"Tentative d'accès à une clé expirée (ID: {key_id})")
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="La clé a expiré"
                )
            
            if key_pair.revoked:
                self.logger.warning(f"Tentative d'accès à une clé révoquée (ID: {key_id})")
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="La clé a été révoquée"
                )
            
            # Incrémentation du compteur d'utilisation si demandé
            if increment_usage:
                key_pair.increment_usage()
                await self.db.commit()
            
            self.logger.debug(f"Paire de clés récupérée (ID: {key_id})")
            return key_pair
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la paire de clés (ID: {key_id}): {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la récupération de la paire de clés"
            )

    async def get_public_key(self, key_id: str) -> str:
        """
        Récupère uniquement la clé publique
        
        Args:
            key_id: Identifiant de la paire de clés
            
        Returns:
            str: Clé publique en format PEM
            
        Scenarios:
            - Nominal: Clé publique retournée
            - Alternatif: Clé introuvable ou invalide
        """
        key_pair = await self.get_key_pair(key_id, increment_usage=False)
        return key_pair.public_key
    
    async def get_private_key(self, key_id: str) -> bytes:
        """
        Récupère et déchiffre la clé privée
        
        Args:
            key_id: Identifiant de la paire de clés
            
        Returns:
            bytes: Clé privée déchiffrée
            
        Scenarios:
            - Nominal: Clé privée déchiffrée et retournée
            - Alternatif: Clé introuvable, erreur de déchiffrement
        """
        key_pair = await self.get_key_pair(key_id)
        
        try:
            private_key_enc = bytes.fromhex(key_pair.private_key_enc)
            private_key = decrypt_private_key(private_key_enc)
            return private_key
        except Exception as e:
            self.logger.error(f"Erreur lors du déchiffrement de la clé privée (ID: {key_id}): {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors du déchiffrement de la clé privée"
            )
    
    async def list_key_pairs(
        self, 
        limit: int = 50, 
        offset: int = 0,
        key_type: Optional[str] = None,
        revoked_only: bool = False,
        expired_only: bool = False,
        valid_only: bool = False
    ) -> Tuple[List[KeyPair], int]:
        """
        Liste les paires de clés avec filtres
        
        Args:
            limit: Nombre maximum de résultats
            offset: Décalage pour la pagination
            key_type: Filtrer par type de clé
            revoked_only: Afficher uniquement les clés révoquées
            expired_only: Afficher uniquement les clés expirées
            valid_only: Afficher uniquement les clés valides
            
        Returns:
            Tuple[List[KeyPair], int]: (liste des clés, nombre total)
            
        Scenarios:
            - Nominal: Liste des clés retournée avec pagination
            - Alternatif: Paramètres de pagination invalides
        """
        try:
            # Validation des paramètres
            if limit <= 0 or limit > 1000:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La limite doit être entre 1 et 1000"
                )
            
            if offset < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="L'offset doit être positif"
                )
            
            # Construction de la requête
            query = select(KeyPair)
            count_query = select(func.count(KeyPair.id))
            
            # Application des filtres
            filters = []
            
            if key_type:
                filters.append(KeyPair.key_type == key_type.upper())
            
            if revoked_only:
                filters.append(KeyPair.revoked == True)
            elif expired_only:
                filters.append(KeyPair.expiry < datetime.now(timezone.utc))
            elif valid_only:
                filters.append(
                    and_(
                        KeyPair.revoked == False,
                        KeyPair.expiry > datetime.now(timezone.utc)
                    )
                )
            
            if filters:
                query = query.where(and_(*filters))
                count_query = count_query.where(and_(*filters))
            
            # Tri par date de création (plus récent en premier)
            query = query.order_by(desc(KeyPair.created_at))
            
            # Pagination
            query = query.offset(offset).limit(limit)
            
            # Exécution des requêtes
            result = await self.db.execute(query)
            keys = result.scalars().all()
            
            count_result = await self.db.execute(count_query)
            total_count = count_result.scalar()
            
            self.logger.debug(f"Liste des clés récupérée: {len(keys)}/{total_count}")
            return keys, total_count
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la liste des clés: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la récupération de la liste des clés"
            )
    
    # ==================== RÉVOCATION ET ROTATION ====================
    
    async def revoke_key(self, key_id: str, reason: str, user_id: Optional[str] = None) -> KeyPair:
        """
        Révoque une paire de clés
        
        Args:
            key_id: Identifiant de la paire de clés
            reason: Raison de la révocation
            user_id: ID de l'utilisateur qui révoque la clé
            
        Returns:
            KeyPair: Paire de clés révoquée
            
        Scenarios:
            - Nominal: Clé révoquée avec succès
            - Alternatif: Clé déjà révoquée, clé introuvable
        """
        try:
            # Validation des paramètres
            if not reason or len(reason.strip()) < 3:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La raison de révocation doit contenir au moins 3 caractères"
                )
            
            # Récupération de la clé
            key_pair = await self.get_key_pair(key_id, increment_usage=False)
            
            # Vérification si déjà révoquée
            if key_pair.revoked:
                self.logger.warning(f"Tentative de révocation d'une clé déjà révoquée (ID: {key_id})")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La clé est déjà révoquée"
                )
            
            # Révocation
            key_pair.revoke(reason.strip())
            
            # Ajout des métadonnées de révocation
            import json
            metadata = {}
            if key_pair.key_metadata:
                try:
                    metadata = json.loads(key_pair.key_metadata)
                except Exception:
                    metadata = {}
            metadata.update({
                "revocation": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user_id": user_id,
                    "reason": reason.strip()
                }
            })
            key_pair.key_metadata = self._serialize_metadata(metadata)
            
            await self.db.commit()
            await self.db.refresh(key_pair)
            
            self.logger.info(f"Clé révoquée (ID: {key_id}) - Raison: {reason}")
            return key_pair
            
        except HTTPException:
            await self.db.rollback()
            raise
        except Exception as e:
            await self.db.rollback()
            self.logger.error(f"Erreur lors de la révocation de la clé (ID: {key_id}): {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la révocation de la clé"
            )

    async def rotate_key(self, key_id: str, user_id: Optional[str] = None) -> KeyPair:
        """
        Effectue la rotation d'une paire de clés
        
        Args:
            key_id: Identifiant de la paire de clés à faire tourner
            user_id: ID de l'utilisateur qui effectue la rotation
            
        Returns:
            KeyPair: Nouvelle paire de clés créée
            
        Scenarios:
            - Nominal: Rotation effectuée avec succès
            - Alternatif: Clé déjà révoquée, erreur de création
        """
        try:
            # Récupération de l'ancienne clé
            old_key = await self.get_key_pair(key_id, increment_usage=False)
            
            # Vérification si la clé peut être tournée
            if old_key.revoked:
                self.logger.warning(f"Tentative de rotation d'une clé révoquée (ID: {key_id})")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Impossible de faire la rotation d'une clé révoquée"
                )
            
            # Révocation de l'ancienne clé
            await self.revoke_key(key_id, "Rotation automatique", user_id)
            
            # Calcul de la durée restante
            remaining_days = max(1, old_key.days_until_expiry())
            
            # Création de la nouvelle clé avec les mêmes paramètres
            new_key = await self.create_key_pair(
                key_type=old_key.key_type,
                key_size=old_key.key_size,
                expiry_days=remaining_days,
                metadata={
                    "rotation": {
                        "from_key_id": key_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "user_id": user_id
                    }
                }
            )
            
            self.logger.info(
                f"Rotation de clé effectuée - "
                f"Ancienne: {key_id}, Nouvelle: {new_key.id}, "
                f"Durée restante: {remaining_days} jours"
            )
            
            return new_key
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation de la clé (ID: {key_id}): {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la rotation de la clé"
            )
    
    # ==================== STATISTIQUES ET MONITORING ====================
    
    async def get_key_statistics(self) -> Dict[str, Any]:
        """
        Récupère les statistiques des clés
        
        Returns:
            Dict[str, Any]: Statistiques des clés
            
        Scenarios:
            - Nominal: Statistiques récupérées avec succès
            - Alternatif: Erreur de base de données
        """
        try:
            # Requêtes de statistiques
            total_query = select(func.count(KeyPair.id))
            active_query = select(func.count(KeyPair.id)).where(
                and_(
                    KeyPair.revoked == False,
                    KeyPair.expiry > datetime.now(timezone.utc)
                )
            )
            revoked_query = select(func.count(KeyPair.id)).where(KeyPair.revoked == True)
            expired_query = select(func.count(KeyPair.id)).where(
                KeyPair.expiry < datetime.now(timezone.utc)
            )
            
            # Exécution des requêtes
            total_result = await self.db.execute(total_query)
            total_count = total_result.scalar()
            
            active_result = await self.db.execute(active_query)
            active_count = active_result.scalar()
            
            revoked_result = await self.db.execute(revoked_query)
            revoked_count = revoked_result.scalar()
            
            expired_result = await self.db.execute(expired_query)
            expired_count = expired_result.scalar()
            
            # Statistiques par type de clé
            type_query = select(
                KeyPair.key_type,
                func.count(KeyPair.id).label('count')
            ).group_by(KeyPair.key_type)
            
            type_result = await self.db.execute(type_query)
            type_stats = {row.key_type: row.count for row in type_result}
            
            statistics = {
                "total_keys": total_count,
                "active_keys": active_count,
                "revoked_keys": revoked_count,
                "expired_keys": expired_count,
                "by_type": type_stats,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
            self.logger.debug(f"Statistiques des clés récupérées: {statistics}")
            return statistics
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la récupération des statistiques"
            )
    
    async def get_expiring_keys(self, days_ahead: int = 30) -> List[KeyPair]:
        """
        Récupère les clés qui vont expirer dans les prochains jours
        
        Args:
            days_ahead: Nombre de jours à l'avance
            
        Returns:
            List[KeyPair]: Liste des clés qui vont expirer
            
        Scenarios:
            - Nominal: Liste des clés expirantes retournée
            - Alternatif: Paramètre invalide
        """
        try:
            if days_ahead <= 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Le nombre de jours doit être positif"
                )
            
            expiry_threshold = datetime.now(timezone.utc) + timedelta(days=days_ahead)
            
            query = select(KeyPair).where(
                and_(
                    KeyPair.expiry <= expiry_threshold,
                    KeyPair.expiry > datetime.now(timezone.utc),
                    KeyPair.revoked == False
                )
            ).order_by(asc(KeyPair.expiry))
            
            result = await self.db.execute(query)
            expiring_keys = result.scalars().all()
            
            self.logger.info(f"Clés expirantes trouvées: {len(expiring_keys)} dans les {days_ahead} prochains jours")
            return expiring_keys
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des clés expirantes: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors de la récupération des clés expirantes"
            )
    
    # ==================== MÉTHODES UTILITAIRES PRIVÉES ====================
    
    def _validate_key_creation_params(
        self, 
        key_type: str, 
        key_size: Optional[int], 
        curve_name: Optional[str], 
        expiry_days: int
    ) -> None:
        """Valide les paramètres de création de clé"""
        if key_type.upper() not in self.supported_key_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Type de clé non supporté: {key_type}"
            )
        
        if expiry_days <= 0 or expiry_days > settings.MAX_KEY_LIFETIME_DAYS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Durée d'expiration invalide. Doit être entre 1 et {settings.MAX_KEY_LIFETIME_DAYS} jours"
            )
        
        if key_type.upper() == "RSA" and key_size:
            if key_size not in self.supported_key_types["RSA"]["sizes"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Taille de clé RSA non supportée: {key_size}"
                )
        
        if key_type.upper() == "ECDSA" and curve_name:
            if curve_name not in self.supported_key_types["ECDSA"]["curves"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Courbe ECDSA non supportée: {curve_name}"
                )
    
    def _prepare_generation_params(
        self, 
        key_type: str, 
        key_size: Optional[int], 
        curve_name: Optional[str]
    ) -> Dict[str, Any]:
        """Prépare les paramètres pour la génération de clés"""
        params = {}
        
        if key_type.upper() == "RSA" and key_size:
            params["key_size"] = key_size
        elif key_type.upper() == "ECDSA" and curve_name:
            params["curve_name"] = curve_name
        
        return params
    
    def _get_default_key_size(self, key_type: str) -> int:
        """Retourne la taille par défaut pour un type de clé"""
        if key_type.upper() == "RSA":
            return self.supported_key_types["RSA"]["default_size"]
        return 0  # Pour les clés non-RSA
    
    def _serialize_metadata(self, metadata: Dict[str, Any]) -> str:
        """Sérialise les métadonnées en JSON"""
        import json
        return json.dumps(metadata, ensure_ascii=False)
    
    def _is_valid_uuid(self, uuid_string: str) -> bool:
        """Vérifie si une chaîne est un UUID valide"""
        try:
            uuid.UUID(uuid_string)
            return True
        except ValueError:
            return False