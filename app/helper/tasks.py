"""
Tâches asynchrones pour le PKI Service (Celery)
Configure le broker/backend Redis et expose une instance de Celery prête.
"""

from celery import Celery
from app.helper.settings import settings


def build_redis_url() -> str:
    """
    Construit l'URL Redis pour Celery.

    - Nominal: Retourne une URL avec ou sans mot de passe.
    - Alternatif: Valeurs manquantes -> utilise les défauts de settings.
    """
    host = settings.REDIS_HOST
    port = settings.REDIS_PORT
    db = settings.REDIS_DB
    pwd = settings.REDIS_PASSWORD
    if pwd:
        return f"redis://:{pwd}@{host}:{port}/{db}"
    return f"redis://{host}:{port}/{db}"


celery_app = Celery(
    "service_tasks",
    broker=build_redis_url(),
    backend=build_redis_url(),
)

# Exemple de tâche (documentation de référence)
@celery_app.task(name="pki.rotate_keys_due")
def rotate_keys_due() -> str:
    """
    Tâche planifiée pour illustrer l'intégration (à implémenter selon besoins).
    Retourne une chaîne indicative.
    """
    return "Rotation check executed"
