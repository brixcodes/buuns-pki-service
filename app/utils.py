"""
Utilitaires cryptographiques pour le PKI Service
Gère la génération, validation et manipulation des clés cryptographiques
"""

import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any, Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import logging
from fastapi import HTTPException, status

# Configuration du logging
logger = logging.getLogger(__name__)

# ==================== CONSTANTES ====================

# Types de clés supportés
SUPPORTED_KEY_TYPES = {
    "RSA": {
        "sizes": [1024, 2048, 3072, 4096, 8192],
        "default_size": 2048,
        "description": "Rivest-Shamir-Adleman"
    },
    "ECDSA": {
        "curves": ["P-256", "P-384", "P-521"],
        "default_curve": "P-256",
        "description": "Elliptic Curve Digital Signature Algorithm"
    },
    "Ed25519": {
        "description": "Edwards Curve Digital Signature Algorithm"
    }
}

# Exposants publics RSA recommandés
RSA_PUBLIC_EXPONENTS = [65537, 3]

# ==================== GÉNÉRATION DE CLÉS ====================

def generate_rsa_key_pair(key_size: int = 2048, public_exponent: int = 65537) -> Tuple[bytes, bytes]:
    """
    Génère une paire de clés RSA
    
    Args:
        key_size: Taille de la clé en bits (1024, 2048, 3072, 4096, 8192)
        public_exponent: Exposant public (65537 recommandé)
        
    Returns:
        Tuple[bytes, bytes]: (clé_publique_pem, clé_privée_pem)
        
    Raises:
        HTTPException: Si la génération échoue
        
    Scenarios:
        - Nominal: Paire de clés générée avec succès
        - Alternatif: Taille de clé non supportée ou erreur de génération
    """
    try:
        # Validation des paramètres
        if key_size not in SUPPORTED_KEY_TYPES["RSA"]["sizes"]:
            logger.error(f"Taille de clé RSA non supportée: {key_size}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Taille de clé RSA non supportée. Tailles supportées: {SUPPORTED_KEY_TYPES['RSA']['sizes']}"
            )
        
        if public_exponent not in RSA_PUBLIC_EXPONENTS:
            logger.warning(f"Exposant public RSA non standard: {public_exponent}")
        
        # Génération de la clé privée
        start_time = time.time()
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        generation_time = time.time() - start_time
        
        # Extraction de la clé publique
        public_key = private_key.public_key()
        
        # Sérialisation en PEM
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        logger.info(f"Paire de clés RSA générée - Taille: {key_size} bits, Temps: {generation_time:.2f}s")
        logger.debug(f"Clé publique: {len(pub_bytes)} bytes, Clé privée: {len(priv_bytes)} bytes")
        
        return pub_bytes, priv_bytes
        
    except Exception as e:
        logger.error(f"Échec de la génération des clés RSA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération des clés RSA: {str(e)}"
        )

def generate_ecdsa_key_pair(curve_name: str = "P-256") -> Tuple[bytes, bytes]:
    """
    Génère une paire de clés ECDSA
    
    Args:
        curve_name: Nom de la courbe elliptique (P-256, P-384, P-521)
        
    Returns:
        Tuple[bytes, bytes]: (clé_publique_pem, clé_privée_pem)
        
    Raises:
        HTTPException: Si la génération échoue
        
    Scenarios:
        - Nominal: Paire de clés générée avec succès
        - Alternatif: Courbe non supportée ou erreur de génération
    """
    try:
        # Validation de la courbe
        if curve_name not in SUPPORTED_KEY_TYPES["ECDSA"]["curves"]:
            logger.error(f"Courbe ECDSA non supportée: {curve_name}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Courbe ECDSA non supportée. Courbes supportées: {SUPPORTED_KEY_TYPES['ECDSA']['curves']}"
            )
        
        # Sélection de la courbe
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1()
        }
        
        # Génération de la clé privée
        start_time = time.time()
        private_key = ec.generate_private_key(
            curve_map[curve_name],
            backend=default_backend()
        )
        generation_time = time.time() - start_time
        
        # Extraction de la clé publique
        public_key = private_key.public_key()
        
        # Sérialisation en PEM
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        logger.info(f"Paire de clés ECDSA générée - Courbe: {curve_name}, Temps: {generation_time:.2f}s")
        logger.debug(f"Clé publique: {len(pub_bytes)} bytes, Clé privée: {len(priv_bytes)} bytes")
        
        return pub_bytes, priv_bytes
        
    except Exception as e:
        logger.error(f"Échec de la génération des clés ECDSA: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération des clés ECDSA: {str(e)}"
        )

def generate_ed25519_key_pair() -> Tuple[bytes, bytes]:
    """
    Génère une paire de clés Ed25519
    
    Returns:
        Tuple[bytes, bytes]: (clé_publique_pem, clé_privée_pem)
        
    Raises:
        HTTPException: Si la génération échoue
        
    Scenarios:
        - Nominal: Paire de clés générée avec succès
        - Alternatif: Erreur de génération
    """
    try:
        # Génération de la clé privée
        start_time = time.time()
        private_key = ed25519.Ed25519PrivateKey.generate()
        generation_time = time.time() - start_time
        
        # Extraction de la clé publique
        public_key = private_key.public_key()
        
        # Sérialisation en PEM
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        logger.info(f"Paire de clés Ed25519 générée - Temps: {generation_time:.2f}s")
        logger.debug(f"Clé publique: {len(pub_bytes)} bytes, Clé privée: {len(priv_bytes)} bytes")
        
        return pub_bytes, priv_bytes
        
    except Exception as e:
        logger.error(f"Échec de la génération des clés Ed25519: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération des clés Ed25519: {str(e)}"
        )

def generate_ml_dsa_keys(key_type: str = "RSA", **kwargs) -> Tuple[bytes, bytes]:
    """
    Génère une paire de clés selon le type spécifié (compatibilité avec l'ancien code)
    
    Args:
        key_type: Type de clé à générer (RSA, ECDSA, Ed25519)
        **kwargs: Paramètres spécifiques au type de clé
        
    Returns:
        Tuple[bytes, bytes]: (clé_publique_pem, clé_privée_pem)
        
    Scenarios:
        - Nominal: Paire de clés générée selon le type
        - Alternatif: Type de clé non supporté
    """
    try:
        if key_type.upper() == "RSA":
            key_size = kwargs.get("key_size", SUPPORTED_KEY_TYPES["RSA"]["default_size"])
            return generate_rsa_key_pair(key_size=key_size)
        
        elif key_type.upper() == "ECDSA":
            curve_name = kwargs.get("curve_name", SUPPORTED_KEY_TYPES["ECDSA"]["default_curve"])
            return generate_ecdsa_key_pair(curve_name=curve_name)
        
        elif key_type.upper() == "ED25519":
            return generate_ed25519_key_pair()
        
        else:
            logger.error(f"Type de clé non supporté: {key_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Type de clé non supporté: {key_type}. Types supportés: {list(SUPPORTED_KEY_TYPES.keys())}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la génération des clés {key_type}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération des clés {key_type}: {str(e)}"
        )

# ==================== VALIDATION DE CLÉS ====================

def validate_public_key(public_key_pem: bytes) -> Dict[str, Any]:
    """
    Valide une clé publique PEM
    
    Args:
        public_key_pem: Clé publique en format PEM
        
    Returns:
        Dict[str, Any]: Informations sur la clé validée
        
    Raises:
        HTTPException: Si la clé est invalide
        
    Scenarios:
        - Nominal: Clé publique valide
        - Alternatif: Clé publique invalide ou corrompue
    """
    try:
        # Chargement de la clé publique
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        # Sérialisation pour vérification
        serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Informations sur la clé
        key_info = {
            "type": type(public_key).__name__,
            "size": getattr(public_key, 'key_size', None),
            "curve": getattr(public_key, 'curve', None),
            "valid": True,
            "fingerprint": hashlib.sha256(serialized).hexdigest()[:16]
        }
        
        logger.debug(f"Clé publique validée: {key_info}")
        return key_info
        
    except Exception as e:
        logger.error(f"Clé publique invalide: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Clé publique invalide: {str(e)}"
        )

def validate_private_key(private_key_pem: bytes) -> Dict[str, Any]:
    """
    Valide une clé privée PEM
    
    Args:
        private_key_pem: Clé privée en format PEM
        
    Returns:
        Dict[str, Any]: Informations sur la clé validée
        
    Raises:
        HTTPException: Si la clé est invalide
        
    Scenarios:
        - Nominal: Clé privée valide
        - Alternatif: Clé privée invalide ou corrompue
    """
    try:
        # Chargement de la clé privée
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Extraction de la clé publique correspondante
        public_key = private_key.public_key()
        
        # Sérialisation pour vérification
        priv_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pub_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Informations sur la clé
        key_info = {
            "type": type(private_key).__name__,
            "size": getattr(private_key, 'key_size', None),
            "curve": getattr(private_key, 'curve', None),
            "valid": True,
            "private_fingerprint": hashlib.sha256(priv_serialized).hexdigest()[:16],
            "public_fingerprint": hashlib.sha256(pub_serialized).hexdigest()[:16]
        }
        
        logger.debug(f"Clé privée validée: {key_info}")
        return key_info
        
    except Exception as e:
        logger.error(f"Clé privée invalide: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Clé privée invalide: {str(e)}"
        )

# ==================== UTILITAIRES CRYPTOGRAPHIQUES ====================

def generate_key_fingerprint(key_data: bytes) -> str:
    """
    Génère l'empreinte d'une clé
    
    Args:
        key_data: Données de la clé
        
    Returns:
        str: Empreinte SHA-256 de la clé
        
    Scenarios:
        - Nominal: Empreinte générée avec succès
        - Alternatif: Erreur lors du calcul
    """
    try:
        fingerprint = hashlib.sha256(key_data).hexdigest()
        logger.debug(f"Empreinte générée: {fingerprint[:16]}...")
        return fingerprint
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération de l'empreinte: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération de l'empreinte: {str(e)}"
        )

def generate_secure_random(length: int = 32) -> bytes:
    """
    Génère des données aléatoires sécurisées
    
    Args:
        length: Longueur en bytes
        
    Returns:
        bytes: Données aléatoires sécurisées
        
    Scenarios:
        - Nominal: Données aléatoires générées
        - Alternatif: Longueur invalide
    """
    try:
        if length <= 0 or length > 1024:
            logger.error(f"Longueur invalide pour les données aléatoires: {length}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Longueur doit être entre 1 et 1024 bytes"
            )
        
        random_data = secrets.token_bytes(length)
        logger.debug(f"Données aléatoires générées: {length} bytes")
        return random_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la génération de données aléatoires: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération de données aléatoires: {str(e)}"
        )

# ==================== FONCTIONS DE COMPATIBILITÉ ====================

def get_supported_key_types() -> Dict[str, Any]:
    """
    Retourne les types de clés supportés
    
    Returns:
        Dict[str, Any]: Types de clés supportés avec leurs paramètres
    """
    return SUPPORTED_KEY_TYPES.copy()

def estimate_key_generation_time(key_type: str, **kwargs) -> float:
    """
    Estime le temps de génération d'une clé
    
    Args:
        key_type: Type de clé
        **kwargs: Paramètres de la clé
        
    Returns:
        float: Temps estimé en secondes
    """
    # Estimations basées sur des tests empiriques
    estimates = {
        "RSA": {
            1024: 0.1,
            2048: 0.5,
            3072: 2.0,
            4096: 8.0,
            8192: 60.0
        },
        "ECDSA": {
            "P-256": 0.1,
            "P-384": 0.2,
            "P-521": 0.3
        },
        "Ed25519": 0.1
    }
    
    if key_type.upper() == "RSA":
        key_size = kwargs.get("key_size", 2048)
        return estimates["RSA"].get(key_size, 1.0)
    elif key_type.upper() == "ECDSA":
        curve = kwargs.get("curve_name", "P-256")
        return estimates["ECDSA"].get(curve, 0.2)
    elif key_type.upper() == "ED25519":
        return estimates["Ed25519"]
    else:
        return 1.0