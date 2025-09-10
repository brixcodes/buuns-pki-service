# PKI Service – Documentation complète (Livre de bord)

Ce document décrit en profondeur le microservice PKI (Public Key Infrastructure) de l’application Schools. Il détaille l’architecture, le rôle des fichiers, le fonctionnement des fonctions avec scénarios nominaux et cas alternatifs, les routes exposées, ainsi que les considérations de sécurité, d’observabilité et d’exploitation.


## 1) Vision d’ensemble

- Objectif: fournir un référentiel centralisé, sécurisé et auditable des paires de clés cryptographiques pour l’écosystème de microservices (Signature, Stéganographie, Vérification, etc.).
- Responsabilités:
  - Générer des paires de clés (RSA, ECDSA, Ed25519)
  - Chiffrer les clés privées avant stockage (Fernet)
  - Gérer le cycle de vie (expiration, révocation, rotation)
  - Exposer des API documentées et sécurisées
  - Fournir des statistiques et des capacités de reporting


## 2) Architecture technique

- Framework HTTP: FastAPI (asynchrone)
- ORM & Migrations: SQLAlchemy 2.x (async) + Alembic
- Base de données: PostgreSQL (pilote asyncpg)
- Crypto: `cryptography` (RSA, ECDSA, Ed25519), Fernet (chiffrement symétrique)
- Authentification: JWT (python-jose)
- Observabilité: endpoints `/health`, `/ready`, `/metrics`
- Sécurité Web: CORS, TrustedHost, GZip
- Tâches asynchrones (optionnel): Celery + Redis

Arborescence (fichiers clés):
- app/
  - main.py
  - settings.py
  - database.py
  - models.py
  - schemas.py
  - services.py
  - routers.py
  - dependencies.py
  - tasks.py
- migrations/ (Alembic)
- README.md (ce document)


## 3) Configuration & Démarrage

Extrait minimal attendu dans `pki-service/.env`:
```
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/pki_db
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
JWT_SECRET=change-this-very-long-secret-at-least-32-chars
FERNET_KEY=PASTE_GENERATED_FERNET_KEY_HERE
ALLOWED_ORIGINS=https://localhost:3000,https://127.0.0.1:3000
LOG_LEVEL=WARNING
```
Générer une clé Fernet (à la racine du monorepo):
```
python F:\Schools\generate_fernet_key.py
```
Copiez la valeur dans le `.env` de chaque service, puis supprimez `fernet_key.txt`.

Démarrer en local (service seul):
```
cd F:\Schools\pki-service
. .\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 0.0.0.0 --port 8001 --ssl-keyfile F:\Schools\certs\key.pem --ssl-certfile F:\Schools\certs\cert.pem
```

Migrations DB:
```
cd F:\Schools\pki-service
. .\venv\Scripts\Activate.ps1
alembic revision --autogenerate -m "optimisations"
alembic upgrade head
```


## 4) Rôle de chaque fichier et fonctions principales

### 4.1) `app/main.py`
- Rôle: point d’entrée FastAPI, middlewares (GZip, TrustedHost, CORS), hooks de démarrage, endpoints santé/metrics.
- Fonctions:
  - App & middlewares: instancie FastAPI, configure GZip/CORS/TrustedHost.
    - Nominal: service démarre, CORS/TrustedHost actifs, GZip > 500 bytes.
    - Alternatifs: origines CORS mal configurées → warnings; HOST non autorisé → 400.
  - `startup_event`: crée les tables si absentes.
    - Nominal: base prête, logs d’info.
    - Alternatifs: échec DB → log error, service reste disponible mais non initialisé.
  - Endpoints:
    - `GET /health`: vivacité simple.
    - `GET /ready`: prêt opérationnel (après init).
    - `GET /metrics`: compteur de requêtes + info version (Prometheus-like light).

### 4.2) `app/settings.py`
- Rôle: configuration Pydantic (chargée depuis `.env`) + validateurs.
- Champs clés: `DATABASE_URL`, `REDIS_*`, `JWT_SECRET`, `FERNET_KEY`, `ALLOWED_ORIGINS`, `LOG_LEVEL`, `MAX_KEY_LIFETIME_DAYS`, etc.
- Fonctions utilitaires: `get_allowed_origins_list()`, `get_database_config()`, `get_redis_config()`, `is_development_mode()`.
  - Nominal: valeurs valides, logs de contrôle.
  - Alternatifs: variables manquantes ou invalides → `ValueError` explicites au chargement.

### 4.3) `app/database.py`
- Rôle: création du moteur async SQLAlchemy, gestion des sessions/transactions, diagnostics.
- Fonctions:
  - `create_database_engine()`: moteur configuré (pool, timeouts, pre_ping, etc.).
  - `get_db()`: générateur de session avec rollback/close robustes.
  - `get_db_transaction()`: contexte transactionnel (commit/rollback automatiques).
  - Diagnostics: `check_database_connection()`, `get_database_info()`, `get_connection_pool_status()`.
  - Nominal: sessions stables, diagnostics OK.
  - Alternatifs: pertes de connexions/erreurs SQL → rollback et exceptions propres, logs détaillés.

### 4.4) `app/models.py`
- Rôle: modèle SQLAlchemy pour la table `key_pairs`.
- Colonnes principales: `id`, `public_key` (PEM), `private_key_enc` (hex), `expiry`, `revoked`, `reason`, `created_at`, `updated_at`, `last_used_at`, `key_type`, `key_size`, `usage_count`, `key_metadata`.
- Contraintes: index (revoked, expiry, created_at, key_type) et checks (tailles/longueurs minimales).
- Méthodes:
  - `is_expired()`, `is_valid()`, `days_until_expiry()`
  - `increment_usage()` (met à jour usage_count / last_used_at / updated_at)
  - `revoke(reason)` (contrôle doublon de révocation)
- Nominal: validation simple côté modèle, état cohérent.
- Alternatifs: valeurs invalides (clés trop courtes, hex invalide) → `ValueError` immédiate.

### 4.5) `app/schemas.py`
- Rôle: schémas Pydantic pour I/O API.
- Classes:
  - `KeyPairCreate`: options côté client (key_type, key_size, curve_name, expiry_days).
  - `KeyPairOut`: représentation de sortie (id, public_key, expiry, key_type, key_size, created_at, updated_at, revoked, reason, usage_count).
  - `RevokeRequest`, `RotateRequest`.
- Nominal: validation de types/contraintes (limites sur tailles, chaînes, etc.).
- Alternatifs: champs manquants/invalides → erreurs 422 Pydantic renvoyées automatiquement.

### 4.6) `app/utils.py`
- Rôle: utilitaires cryptographiques.
- Fonctions principales:
  - Génération de paires: `generate_rsa_key_pair()`, `generate_ecdsa_key_pair()`, `generate_ed25519_key_pair()`.
  - Compatibilité: `generate_ml_dsa_keys(key_type, **kwargs)` (routeur de génération).
  - Validation: `validate_public_key()`, `validate_private_key()`.
  - Utilitaires: `generate_key_fingerprint()`, `generate_secure_random()`.
  - Nominal: clés valides, PEM corrects, empreintes calculées.
  - Alternatifs: tailles/courbes non supportées → 400; erreurs crypto → 500 (HTTPException documentées).

### 4.7) `app/dependencies.py`
- Rôle: dépendances transverses (Fernet, JWT, Redis).
- Fonctions:
  - Initialisation Fernet depuis `settings.FERNET_KEY` (source unique de vérité).
  - `encrypt_private_key(data)`, `decrypt_private_key(token)`.
  - `get_current_user(required_role=None)`: décode JWT, vérifie rôles.
  - `get_redis()`: client Redis avec retry/backoff.
  - Nominal: clé Fernet chargée, JWT valide, Redis ping OK.
  - Alternatifs: clé absente → ValueError; JWT invalide → 401; rôle insuffisant → 403; Redis down → 503.

### 4.8) `app/services.py`
- Rôle: logique métier centrale.
- Méthodes principales de `PKIService`:
  - `create_key_pair(key_type, key_size, curve_name, expiry_days, metadata=None)`:
    - Génère clés (utils), valide PEM, chiffre la clé privée (Fernet), persiste `KeyPair`.
    - Incrémente `usage_count` (commit) et journalise.
    - Nominal: 201 via route, objet complet retourné.
    - Alternatifs: params invalides → 400; erreur DB → 500; erreurs crypto → 500.
  - `create_batch_key_pairs(count, key_type, **kwargs)`:
    - Crée N paires; renvoie 207 en cas de succès partiel.
  - `get_key_pair(key_id, increment_usage=True)`:
    - Retourne la paire si non révoquée/expirée; incrémente usage si demandé.
    - Alternatifs: UUID invalide → 400; introuvable → 404; expirée/révoquée → 410.
  - `get_public_key(key_id)` / `get_private_key(key_id)` (déchiffrement via Fernet).
    - Alternatifs: déchiffrement échoue → 500.
  - `list_key_pairs(limit, offset, key_type, revoked_only, expired_only, valid_only)` → (liste, total)
  - `revoke_key(key_id, reason, user_id=None)` → met `revoked=true`, ajoute trace de révocation dans `key_metadata`.
  - `rotate_key(key_id, user_id=None)` → révoque l’ancienne + crée une nouvelle avec même profil et durée restante.
  - Reporting: `get_key_statistics()`, `get_expiring_keys(days_ahead)`.

### 4.9) `app/routers.py`
- Rôle: exposition HTTP des opérations.
- Endpoints (préfixe `/keys`):
  - `POST /keys/generate` (JWT)
    - Body `KeyPairCreate`: `{ key_type?: "RSA"|"ECDSA"|"Ed25519", key_size?: int, curve_name?: "P-256"|"P-384"|"P-521", expiry_days?: int }`
    - 201 → `KeyPairOut`
    - Nominal: crée et renvoie la paire.
    - Alternatifs: 400/500 selon la cause.
  - `GET /keys/{key_id}` (JWT)
    - 200 → `KeyPairOut`; 410 si révocation/expiration; 404 si inconnu; 400 si ID invalide.
  - `POST /keys/revoke` (JWT rôle admin)
    - Body `RevokeRequest { key_id, reason }` → 200 `KeyPairOut`.
    - Alternatifs: déjà révoquée → 400; inconnu → 404.
  - `POST /keys/rotate` (JWT rôle admin)
    - Body `RotateRequest { key_id }` → 200 `KeyPairOut` (nouvelle paire).
    - Alternatifs: clé déjà révoquée → 400; inconnu → 404; erreur création → 500.

### 4.10) `app/tasks.py`
- Rôle: configuration Celery (optionnelle) + exemple de tâche.
- Expose `celery_app` et une tâche illustrative `rotate_keys_due()`.

### 4.11) `migrations/`
- Contient la configuration et les versions Alembic pour l’évolution du schéma.
- Au démarrage, `Base.metadata.create_all()` garantit l’existence des tables.


## 5) Sécurité
- Clé privée toujours chiffrée (Fernet). La FERNET_KEY est partagée (identique) entre services.
- JWT requis; endpoints sensibles (`revoke`, `rotate`) réservés aux rôles autorisés.
- CORS restreint aux origines définies; TrustedHost limite les hôtes acceptés.
- TLS/HTTPS recommandé (certificats fournis via scripts de démarrage global).

Bonnes pratiques (prod): stocker FERNET_KEY/JWT_SECRET dans un secret manager; rotation régulière des secrets; audit des usages et des révocations; sauvegardes DB.


## 6) Observabilité
- `GET /health`: simple vivacité.
- `GET /ready`: service prêt (post-init).
- `GET /metrics`: compteur de requêtes + info version (compatible scraping Prometheus).
- Logs structurés (structlog/standard logging) avec niveaux et tracés (`x-trace-id`).


## 7) Scénarios complets (nominal / alternatifs)

### 7.1) Génération de clés
- Nominal:
  1. Client envoie `POST /keys/generate` avec JWT.
  2. Service valide les paramètres, génère la paire, chiffre la clé privée, stocke, incrémente l’usage.
  3. Retour 201 avec `KeyPairOut`.
- Alternatifs:
  - Paramètre non supporté (ex: taille RSA invalide) → 400.
  - Erreur DB (connexion, contrainte) → 500.
  - Échec crypto (rare) → 500.

### 7.2) Consultation d’une clé
- Nominal: `GET /keys/{id}` → 200 avec données si valide.
- Alternatifs:
  - ID mal formé → 400.
  - Inconnue → 404.
  - Expirée/Révoquée → 410 (gone).

### 7.3) Révocation
- Nominal: `POST /keys/revoke` (admin) → 200; statut `revoked=true`, raison journalisée.
- Alternatifs: déjà révoquée → 400; inconnue → 404.

### 7.4) Rotation
- Nominal: `POST /keys/rotate` (admin) → 200; ancienne révoquée + nouvelle générée avec même profil.
- Alternatifs: clé déjà révoquée → 400; inconnue → 404; erreur création → 500.


## 8) Dépannage
- « Attribute name 'metadata' is reserved »:
  - Résolu: champ renommé en `key_metadata` dans `models.py`.
- « FERNET_KEY manquante »:
  - Ajouter la variable dans `pki-service/.env` et dans tous les autres services.
- « DATABASE_URL invalide »:
  - Respecter `postgresql+asyncpg://user:password@host:port/dbname`.
- Alembic / migrations:
  - Activer le venv, puis `alembic revision --autogenerate -m "msg"` et `alembic upgrade head`.


## 9) Annexes / Recommandations
- Performance:
  - Ajuster pool_size / timeouts en fonction de la charge.
  - Ajouter des index si de nouveaux filtres de recherche apparaissent.
- Sécurité renforcée:
  - Envisager HSM/KMS en production (au-delà de Fernet) pour la clé privée.
  - Journaliser les actions d’administration (révocation/rotation) avec identifiants utilisateurs.

---

Ce service PKI est conçu pour être robuste, extensible et sécurisé, tout en restant simple à opérer. Il sert de fondation cryptographique fiable pour l’ensemble de l’architecture Schools.
