# 🔐 PKI Service – Infrastructure Complète de Gestion de Clés Cryptographiques

## 🌟 Aperçu du Projet

Le **PKI Service** est un microservice critique basé sur **FastAPI** qui constitue le cœur de l'infrastructure cryptographique de l'écosystème. Il fournit une plateforme sécurisée, scalable et robuste pour la **génération**, le **stockage chiffré**, la **révocation**, la **rotation** et la **consultation** de paires de clés cryptographiques. 

Ce service est la **fondation de confiance** de l'architecture, consommé par les services de signature, stéganographie et vérification pour garantir l'intégrité, l'authenticité et la non-répudiation des opérations cryptographiques.

### 🎯 Fonctionnalités Clés

#### 🔑 Génération de Clés Cryptographiques
- **RSA** : Tailles supportées 1024, 2048, 3072, 4096, 8192 bits
- **ECDSA** : Courbes P-256, P-384, P-521 (NIST)
- **Ed25519** : Signature elliptique moderne et performante
- **Validation automatique** : Vérification des paramètres et formats
- **Génération par lot** : Création de multiples paires de clés

#### 🛡️ Stockage Sécurisé
- **Chiffrement Fernet** : Clés privées chiffrées avec clé symétrique
- **Format PEM** : Clés publiques en format standard
- **Encodage hexadécimal** : Stockage sécurisé des clés chiffrées
- **Métadonnées enrichies** : Informations de création, utilisation, rotation

#### 🔄 Gestion du Cycle de Vie
- **Expiration automatique** : Durée de vie configurable (1-365 jours)
- **Révocation sécurisée** : Désactivation avec raison documentée
- **Rotation intelligente** : Remplacement automatique avec préservation des métadonnées
- **Audit trail** : Traçabilité complète des opérations

#### ✅ Validation et Vérification
- **Validation PEM** : Vérification de la structure des clés
- **Contrôles de taille** : Validation des paramètres cryptographiques
- **Empreintes digitales** : Génération d'identifiants uniques
- **Tests d'intégrité** : Vérification de la cohérence des paires

#### 📊 Statistiques et Monitoring
- **Métriques détaillées** : Totaux, répartition par type, statuts
- **Alertes d'expiration** : Notifications proactives
- **Tableaux de bord** : Visualisation des tendances
- **Rapports d'audit** : Historique des opérations

#### 👀 Observabilité Avancée
- **Endpoints de santé** : `/health`, `/ready`, `/metrics`
- **Métriques Prometheus** : Intégration avec systèmes de monitoring
- **Logs structurés** : Traçabilité avec `x-trace-id`
- **Monitoring en temps réel** : Surveillance des performances

#### 🔒 Sécurité Web
- **Authentification JWT** : Tokens sécurisés avec expiration
- **Autorisation par rôles** : Contrôle d'accès granulaire
- **CORS configuré** : Protection contre les attaques cross-origin
- **TrustedHost** : Validation des hôtes autorisés
- **HTTPS obligatoire** : Chiffrement des communications

---

## 🏗️ Architecture Détaillée

Le PKI Service suit une architecture **modulaire, orientée services** avec opérations asynchrones, migrations de schéma et observabilité intégrée.

### 🏛️ Stack Technologique

#### 🌐 Couche Application
- **FastAPI** : Framework web moderne et performant avec support asynchrone natif
- **Pydantic** : Validation stricte des données d'entrée et de sortie
- **Uvicorn** : Serveur ASGI haute performance pour le déploiement

#### 🗄️ Couche Données
- **SQLAlchemy 2.0** : ORM asynchrone avec support des pools de connexions
- **Alembic** : Système de migrations de base de données versionné
- **PostgreSQL** : Base de données relationnelle robuste et performante
- **asyncpg** : Driver PostgreSQL asynchrone optimisé

#### 🔐 Couche Cryptographique
- **cryptography** : Bibliothèque de référence pour les opérations cryptographiques
- **Fernet** : Chiffrement symétrique AES 128 pour les clés privées
- **JWT** : Tokens d'authentification sécurisés avec expiration

#### 🧵 Couche Asynchrone
- **Celery** : Système de tâches asynchrones distribuées
- **Redis** : Broker et backend pour Celery (optionnel)
- **asyncio** : Support natif des opérations asynchrones

#### 📊 Couche Observabilité
- **Prometheus** : Collecte et stockage des métriques
- **Structured Logging** : Logs JSON avec corrélation des traces
- **Health Checks** : Endpoints de surveillance de la santé

### 📂 Architecture des Fichiers

```
pki-service/
├── app/                           # 🏠 Module principal de l'application
│   ├── main.py                    # 🚀 Point d'entrée FastAPI, middlewares, monitoring
│   ├── settings.py                # ⚙️ Configuration centralisée avec validation Pydantic
│   ├── database.py                # 🗄️ Gestion des connexions DB, sessions, transactions
│   ├── models.py                  # 📋 Modèles SQLAlchemy (KeyPair avec métadonnées)
│   ├── schemas.py                 # 📝 Schémas Pydantic pour validation I/O
│   ├── services.py                # 🏢 Logique métier (CRUD, statistiques, rotation)
│   ├── routers.py                 # 🛤️ Routes HTTP avec documentation OpenAPI
│   ├── dependencies.py            # 🔗 Injection de dépendances (JWT, Fernet, Redis)
│   └── tasks.py                   # 🧵 Configuration Celery et tâches asynchrones
├── migrations/                    # 📦 Migrations Alembic versionnées
│   ├── env.py                     # 🔧 Configuration environnement Alembic
│   └── versions/                  # 📚 Historique des migrations
│       └── 2b2f7d15fda1_optimisations.py
├── alembic.ini                    # ⚙️ Configuration Alembic
├── requirements.txt               # 📦 Dépendances Python
├── .env                          # 🔐 Variables d'environnement (non versionné)
├── .gitignore                    # 🚫 Fichiers ignorés par Git
└── README.md                     # 📖 Documentation complète
```

### 🔄 Flux de Données

#### 1. **Génération de Clés**
```
Client Request → JWT Validation → PKIService.create_key_pair() 
→ Utils.generate_*_key_pair() → Fernet Encryption → Database Insert 
→ Response with Public Key
```

#### 2. **Consultation de Clés**
```
Client Request → JWT Validation → PKIService.get_key_pair() 
→ Database Query → Usage Count Increment → Response
```

#### 3. **Révocation de Clés**
```
Admin Request → Role Validation → PKIService.revoke_key() 
→ Database Update → Audit Log → Response
```

#### 4. **Rotation de Clés**
```
Admin Request → Role Validation → PKIService.rotate_key() 
→ Revoke Old + Create New → Preserve Metadata → Response
```

### 🛡️ Architecture de Sécurité

#### 🔐 Chiffrement des Clés Privées
- **Algorithme** : Fernet (AES 128 en mode CBC)
- **Clé de chiffrement** : Partagée entre tous les services
- **Stockage** : Encodage hexadécimal en base de données
- **Rotation** : Possible via mise à jour de la clé Fernet

#### 🔑 Authentification et Autorisation
- **JWT Tokens** : Signature HMAC-SHA256 avec expiration
- **Rôles** : Admin pour opérations sensibles (révocation, rotation)
- **Validation** : Middleware de vérification sur chaque route protégée
- **Audit** : Traçabilité des actions sensibles

#### 🌐 Sécurité Web
- **CORS** : Origines autorisées configurées
- **TrustedHost** : Validation des hôtes autorisés
- **HTTPS** : Chiffrement des communications (obligatoire en production)
- **Rate Limiting** : Protection contre les attaques par déni de service

---

## ⚙️ Installation & Configuration Complète

### 📋 Prérequis Système

#### 🐍 Environnement Python
- **Python** : 3.10 ou supérieur (recommandé 3.11+)
- **pip** : Gestionnaire de paquets Python
- **virtualenv** : Environnement virtuel isolé

#### 🗄️ Base de Données
- **PostgreSQL** : Version 13 ou supérieure
- **Extensions** : Aucune extension spéciale requise
- **Privilèges** : Utilisateur avec droits CREATE, INSERT, UPDATE, DELETE

#### 🔄 Services Optionnels
- **Redis** : Version 6.0+ (pour Celery et cache)
- **Certificats SSL** : Pour HTTPS en production

### 🚀 Installation Détaillée

#### 1. **Préparation de l'Environnement**
```bash
# Cloner le repository (si applicable)
git clone <repository-url>
cd pki-service

# Créer et activer l'environnement virtuel
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

#### 2. **Installation des Dépendances**
```bash
# Installation des dépendances principales
pip install -r requirements.txt

# Vérification de l'installation
pip list | grep -E "(fastapi|sqlalchemy|alembic|cryptography)"
```

#### 3. **Configuration de l'Environnement**

Créez le fichier `.env` dans le répertoire `pki-service/` :

```env
# ===========================================
# CONFIGURATION PKI SERVICE
# ===========================================

# Application
APP_NAME=PKI Service
APP_VERSION=1.0.0
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=INFO

# Base de données PostgreSQL
DATABASE_URL=postgresql+asyncpg://pki_user:secure_password@localhost:5432/pki_db
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600

# Redis (optionnel - pour Celery et cache)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
REDIS_URL=redis://localhost:6379/0

# Sécurité JWT
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Chiffrement Fernet (CRITIQUE - doit être identique dans tous les services)
FERNET_KEY=PASTE_GENERATED_FERNET_KEY_HERE

# CORS et Sécurité
ALLOWED_ORIGINS=https://localhost:3000,https://127.0.0.1:3000,https://angara.vertex-cam.com
ALLOWED_HOSTS=localhost,127.0.0.1,*.angara.vertex-cam.com

# Limites et Contraintes
MAX_KEY_LIFETIME_DAYS=365
MIN_KEY_LIFETIME_DAYS=1
DEFAULT_KEY_LIFETIME_DAYS=365

# Monitoring et Observabilité
ENABLE_METRICS=true
METRICS_PATH=/metrics
HEALTH_CHECK_PATH=/health
READINESS_CHECK_PATH=/ready

# Celery (optionnel)
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/1
CELERY_TASK_SERIALIZER=json
CELERY_RESULT_SERIALIZER=json
CELERY_ACCEPT_CONTENT=["json"]
```

#### 4. **Génération de la Clé Fernet**

⚠️ **CRITIQUE** : La clé Fernet doit être identique dans tous les services !

```bash
# Générer une nouvelle clé Fernet
python F:\Schools\generate_fernet_key.py

# Copier la clé générée dans fernet_key.txt vers tous les .env
# Puis SUPPRIMER fernet_key.txt pour des raisons de sécurité
```

#### 5. **Configuration de la Base de Données**

```bash
# Créer la base de données PostgreSQL
createdb -U postgres pki_db

# Créer l'utilisateur (optionnel)
psql -U postgres -c "CREATE USER pki_user WITH PASSWORD 'secure_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pki_db TO pki_user;"
```

#### 6. **Migrations Alembic**

```bash
# Activer l'environnement virtuel
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

# Naviguer vers le répertoire du service
cd F:\Schools\pki-service

# Générer la migration initiale
alembic revision --autogenerate -m "Initial migration - KeyPair table"

# Appliquer les migrations
alembic upgrade head

# Vérifier le statut
alembic current
alembic history
```

#### 7. **Démarrage du Service**

##### Mode Développement (HTTP)
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

##### Mode Production (HTTPS)
```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8001 \
  --ssl-keyfile F:\Schools\certs\key.pem \
  --ssl-certfile F:\Schools\certs\cert.pem \
  --workers 4
```

##### Avec Docker (Recommandé)
```bash
# Construire l'image
docker build -t pki-service .

# Lancer le conteneur
docker run -d \
  --name pki-service \
  -p 8001:8001 \
  --env-file .env \
  pki-service
```

### 🔍 Vérification de l'Installation

#### 1. **Tests de Connectivité**
```bash
# Vérifier la santé du service
curl -k https://localhost:8001/health

# Vérifier la préparation
curl -k https://localhost:8001/ready

# Vérifier les métriques
curl -k https://localhost:8001/metrics
```

#### 2. **Tests d'API**
```bash
# Accéder à la documentation Swagger
# https://localhost:8001/docs

# Test d'authentification (si configuré)
curl -X POST https://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

#### 3. **Vérification de la Base de Données**
```bash
# Se connecter à PostgreSQL
psql -U pki_user -d pki_db

# Vérifier les tables
\dt

# Vérifier la structure de la table key_pairs
\d key_pairs
```

---

## 🔎 Rôle des Fichiers & Fonctions (avec scénarios)

### `app/main.py`
- Instancie FastAPI; middlewares: `GZipMiddleware`, `TrustedHostMiddleware`, `CORSMiddleware`.
- `startup_event()`: crée les tables si absentes.
- `GET /health`, `GET /ready`, `GET /metrics`.
- Scénarios:
  - Nominal: service prêt; CORS/TrustedHost actifs.
  - Alternatifs: échec DB → log error (service reste joignable mais non initialisé).

### `app/settings.py`
- Charge `.env`, valide (Pydantic) et expose des helpers.
- Champs critiques: `DATABASE_URL`, `JWT_SECRET`, `FERNET_KEY`, `ALLOWED_ORIGINS`…
- Scénarios:
  - Nominal: configuration chargée, logs d’info.
  - Alternatifs: valeurs manquantes/invalides → `ValueError` explicites au démarrage.

### `app/database.py`
- Moteur async (`create_async_engine`) avec `pool_pre_ping`, timeouts, recycle.
- `get_db()`: session generator (rollback/close robustes).
- `get_db_transaction()`: contexte transactionnel (commit/rollback auto).
- Diagnostics: `check_database_connection()`, `get_database_info()`, `get_connection_pool_status()`.
- Scénarios:
  - Nominal: sessions stables, diagnostics OK.
  - Alternatifs: erreur SQL/connexion → rollback + logs + HTTP 500 côté service métier.

### `app/models.py` (KeyPair)
- Colonnes: `id`, `public_key` (PEM), `private_key_enc` (hex Fernet), `expiry`, `revoked`, `reason`,
  `created_at`, `updated_at`, `last_used_at`, `key_type`, `key_size`, `usage_count`, `key_metadata`.
- Index: `revoked`, `expiry`, `created_at`, `key_type`; checks tailles/longueurs.
- Méthodes utilitaires: `is_expired`, `is_valid`, `days_until_expiry`, `increment_usage`, `revoke`.
- Scénarios:
  - Nominal: cohérence des champs et transitions d’état.
  - Alternatifs: valeur invalide → `ValueError` immédiate (protège la DB).

### `app/schemas.py`
- Pydantic I/O:
  - `KeyPairCreate` (options: `key_type`, `key_size`, `curve_name`, `expiry_days`).
  - `KeyPairOut` (sortie enrichie: dates/tailles/statut).
  - `RevokeRequest`, `RotateRequest`.
- Scénarios:
  - Nominal: validation stricte.
  - Alternatifs: 422 automatique si payload mal formé.

### `app/services.py` (PKIService)
- Métier central, exceptions propres (`HTTPException`) & logs.
- Fonctions principales:
  - `create_key_pair(key_type, key_size, curve_name, expiry_days, metadata=None)`
    - Génère (utils), valide PEM, chiffre la clé privée (Fernet), insère `KeyPair`, incrémente `usage_count`.
    - Nominal: renvoie l’objet; temps de génération loggé.
    - Alternatifs: tailles/courbes non supportées → 400; erreur crypto/DB → 500.
  - `create_batch_key_pairs(count, key_type, **kwargs)`
    - Crée N paires; renvoie 207 en succès partiel.
  - `get_key_pair(key_id, increment_usage=True)`
    - 200 si valide; 410 si révoquée/expirée; 404 si inconnue; 400 si UUID invalide.
  - `get_public_key(key_id)`, `get_private_key(key_id)` (déchiffre via Fernet)
    - Alternatifs: échec déchiffrement → 500.
  - `list_key_pairs(limit, offset, filters…)` → (liste, total)
  - `revoke_key(key_id, reason, user_id=None)`
    - Marque `revoked=true`, ajoute trace dans `key_metadata`.
  - `rotate_key(key_id, user_id=None)`
    - Révoque ancienne + crée nouvelle avec même profil et durée restante.
  - Reporting: `get_key_statistics()`, `get_expiring_keys(days_ahead)`.

### `app/routers.py` (/keys)
- Routes documentées, statuts corrects, dépendances JWT/rôles.
- Scénarios gérés route par route (voir section API ci-dessous).

### `app/dependencies.py`
- Initialisation **Fernet** depuis `settings.FERNET_KEY` (source unique), helpers `encrypt_private_key`/`decrypt_private_key`.
- Auth JWT: `get_current_user(required_role=None)` (401/403 selon cas).
- Redis helper (retry/backoff) si utilisé.

### `app/tasks.py`
- `celery_app` configuré avec Redis (broker/backend), exemple `rotate_keys_due()`.

---

## 🌐 API Endpoints (avec scénarios)

Base URL: `https://localhost:8001`

### Système
- `GET /health` 💚: vivacité.
- `GET /ready` ✅: prêt opérationnel.
- `GET /metrics` 📈: métriques basiques Prometheus-like.

### Clés (`/keys`)
- `POST /keys/generate` (JWT) 🆕
  - Body `KeyPairCreate`: `{ key_type?, key_size?, curve_name?, expiry_days? }`
  - Réponses: `201 KeyPairOut` | `400` (params invalides) | `500` (erreur interne)
  - Nominal: génère clé, chiffre privée, persiste, retourne.
- `GET /keys/{key_id}` (JWT) 🔎
  - Réponses: `200 KeyPairOut` | `400` (id invalide) | `404` (inconnue) | `410` (expirée/révoquée)
  - Nominal: retourne la paire si valide.
- `POST /keys/revoke` (JWT rôle admin) 🚫
  - Body: `{ key_id, reason }`
  - Réponses: `200 KeyPairOut` | `400` (déjà révoquée/raison trop courte) | `404`
  - Nominal: met `revoked=true`, trace dans `key_metadata`.
- `POST /keys/rotate` (JWT rôle admin) ♻️
  - Body: `{ key_id }`
  - Réponses: `200 KeyPairOut (nouvelle)` | `400` (clé révoquée) | `404` | `500`
  - Nominal: révocation + nouvelle clé avec même profil.

#### Exemples curl
```bash
# Générer une clé RSA 2048 pendant 180 jours
curl -k -X POST https://localhost:8001/keys/generate \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"key_type":"RSA","key_size":2048,"expiry_days":180}'

# Récupérer une clé
curl -k https://localhost:8001/keys/<KEY_ID> -H "Authorization: Bearer <JWT>"

# Révoquer
curl -k -X POST https://localhost:8001/keys/revoke \
  -H "Authorization: Bearer <ADMIN_JWT>" -H "Content-Type: application/json" \
  -d '{"key_id":"<KEY_ID>","reason":"Rotation planifiée"}'

# Rotation
curl -k -X POST https://localhost:8001/keys/rotate \
  -H "Authorization: Bearer <ADMIN_JWT>" -H "Content-Type: application/json" \
  -d '{"key_id":"<KEY_ID>"}'
```

---

## 🔒 Sécurité
- Clé privée chiffrée via **Fernet** (clé partagée, identique dans tous les services).
- **JWT** requis; actions sensibles (`revoke`, `rotate`) réservées aux rôles autorisés.
- **CORS** contrôlé (origines configurables), **TrustedHost** activé.
- **HTTPS** recommandé (certificats fournis au lancement global).
- **Logs** structurés; propagation `x-trace-id`.

Bonnes pratiques (prod): secrets via secret manager (Vault/AWS SM), rotation des secrets, audit des actions admin, sauvegardes DB.

---

## 📊 Observabilité & Monitoring
- `/metrics`: compteur de requêtes + info version (scrapable par Prometheus).
- Logs (INFO/WARNING/ERROR) orientés diagnostic.
- Diagnostics DB: `get_database_info()`, `get_connection_pool_status()` utilisables dans des endpoints internes si besoin.

---

## 🧪 Scénarios détaillés (métier)

### Génération (`create_key_pair`)
- Nominal: paramètres valides → génération (utils) → PEM valides → chiffrement privé (Fernet) → insert → incrément usage → 201.
- Alternatifs:
  - `key_type` inconnu / `key_size`/`curve_name` non supportés → 400.
  - Erreur crypto (rare) ou DB → 500.

### Consultation (`get_key_pair`)
- Nominal: UUID valide et clé valide → 200, usage éventuellement incrémenté.
- Alternatifs: UUID mal formé (400), introuvable (404), expirée/révoquée (410).

### Révocation (`revoke_key`)
- Nominal: raison ≥ 3 chars → `revoked=true`, `reason` défini, `key_metadata` enrichi.
- Alternatifs: déjà révoquée (400), introuvable (404).

### Rotation (`rotate_key`)
- Nominal: récupère ancienne (non révoquée), révoque + crée nouvelle avec même type/taille et durée restante → 200.
- Alternatifs: déjà révoquée (400), introuvable (404), échec création (500).

---

## 🛠️ Dépannage
- « `Attribute name 'metadata' is reserved` » → Champ renommé en `key_metadata`.
- « `FERNET_KEY` manquante » → Vérifiez `pki-service/.env` et harmonisation inter-services.
- « `DATABASE_URL` invalide » → Utilisez `postgresql+asyncpg://user:password@host:port/db`.
- Alembic: activer venv puis `alembic revision --autogenerate -m "msg"` et `alembic upgrade head`.

---

## 📞 Contact & Contribution
- Contributions bienvenues (PR, issues, suggestions).
- Équipe technique: `nanyangbrice.devops@gmail.com`.

---

## ✅ Checklist Qualité
- [x] Documentation exhaustive
- [x] Sécurité (JWT, Fernet, CORS, TrustedHost, HTTPS)
- [x] Observabilité (metrics/health/ready, logs)
- [x] Robustesse (transactions, rollback, validations, exceptions)
- [x] Extensibilité (types de clés, métadonnées, statistiques)
