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

### 📂 Architecture des Fichiers (mise à jour)

```
pki-service/
├── app/
│   ├── main.py                    # 🚀 Point d'entrée FastAPI, middlewares, monitoring
│   ├── api/
│   │   ├── models.py              # 📋 Modèles SQLAlchemy (KeyPair)
│   │   ├── schemas.py             # 📝 Schémas Pydantic I/O
│   │   ├── services.py            # 🏢 Logique métier (CRUD, stats, rotation)
│   │   └── routers.py             # 🛤️ Routes HTTP ("/keys")
│   ├── config/
│   │   ├── database.py            # 🗄️ Moteur/Session async + diagnostics
│   │   └── dependencies.py        # 🔗 JWT, Fernet, Redis helpers
│   └── helper/
│       ├── settings.py            # ⚙️ Configuration centralisée (Pydantic)
│       ├── tasks.py               # 🧵 Tâches Celery (optionnel)
│       └── utils.py               # 🔧 Utilitaires crypto (génération/validation)
├── migrations/
│   ├── env.py
│   ├── README
│   └── versions/
│       ├── 0cc356759c5f_create_key_pairs_table.py
│       └── 2b2f7d15fda1_optimisations.py
├── alembic.ini
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

### 🔄 Flux de Données

#### 1. **Génération de Clés**
```
Client → JWT → PKIService.create_key_pair() → utils.generate_* → Fernet (encrypt) → DB → Response
```

#### 2. **Consultation de Clés**
```
Client → JWT → PKIService.get_key_pair() → DB → Response
```

#### 3. **Révocation de Clés**
```
Admin → JWT rôle admin → PKIService.revoke_key() → DB update + metadata → Response
```

#### 4. **Rotation de Clés**
```
Admin → JWT rôle admin → revoke_key → create_key_pair (même profil) → Response
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
- **Validation** : Dépendance `get_current_user` sur chaque route protégée
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
pip install -r requirements.txt
```

#### 3. **Configuration de l'Environnement (.env)**

Le service charge automatiquement le fichier `.env` avec cette priorité:
1. Racine du projet `pki-service/.env`
2. Dossier application `pki-service/app/.env`

Variables critiques (extrait):
```env
# Base de données PostgreSQL
DATABASE_URL=postgresql+asyncpg://pki_user:secure_password@localhost:5432/pki_buuns

# Sécurité
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long
FERNET_KEY=PASTE_GENERATED_FERNET_KEY_HERE

# Redis (optionnel)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# CORS
ALLOWED_ORIGINS=https://localhost:3000,https://127.0.0.1:3000
LOG_LEVEL=INFO

# Dev auth (optionnel pour /auth/token)
DEV_USER=admin
DEV_PASSWORD=admin
```

Générez une clé Fernet:
```bash
python - << 'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

#### 4. **Configuration de la Base de Données**
```bash
createdb -U postgres pki_buuns
psql -U postgres -c "CREATE USER pki_user WITH PASSWORD 'secure_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pki_buuns TO pki_user;"
```

#### 5. **Migrations Alembic**
```bash
alembic upgrade head
```

#### 6. **Démarrage du Service**

Développement:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Production (HTTPS exemple):
```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8001 \
  --ssl-keyfile /path/to/key.pem \
  --ssl-certfile /path/to/cert.pem \
  --workers 4
```

Docker:
```bash
docker build -t pki-service .
docker run -d --name pki-service -p 8001:8001 --env-file .env pki-service
```

### 🔍 Vérification
```bash
curl -k https://localhost:8001/health
curl -k https://localhost:8001/ready
curl -k https://localhost:8001/metrics
```

---

## 🌐 API (extrait)
Base URL: `https://localhost:8001`

- `POST /keys/generate` (JWT) – crée une paire de clés
- `GET /keys/{key_id}` (JWT) – récupère une paire de clés
- `POST /keys/revoke` (JWT admin) – révoque une clé
- `POST /keys/rotate` (JWT admin) – rotation d'une clé

Exemples:
```bash
curl -k -X POST https://localhost:8001/keys/generate \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"key_type":"RSA","key_size":2048,"expiry_days":180}'
```

---

## 🔒 Sécurité
- Clé privée chiffrée via **Fernet** (clé partagée, identique dans tous les services)
- **JWT** requis; actions sensibles réservées aux rôles autorisés
- **CORS** contrôlé, **TrustedHost** activé
- Secrets en prod: utiliser un secret manager (Vault, AWS SM), rotation, audit

---

## 📊 Observabilité
- Endpoints: `/health`, `/ready`, `/metrics`
- Logs structurés; propagation `x-trace-id`

---

## 🧪 Scénarios (métier) – résumé
- Génération: validation → génération → chiffrement → insert → 201
- Consultation: 200 | 400 | 404 | 410
- Révocation: 200 | 400 | 404
- Rotation: 200 | 400 | 500

---

## 🛠️ Dépannage
- « `FERNET_KEY` manquante » → Vérifiez `.env` (même valeur dans tous les services)
- « `DATABASE_URL` invalide » → Utilisez `postgresql+asyncpg://user:password@host:port/db`
- Alembic: activer venv puis `alembic upgrade head`

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
