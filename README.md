# 🔐 PKI Service – Infrastructure de Gestion de Clés (Documentation complète)

## 🌟 Aperçu du Projet

Le **PKI Service** est un microservice basé sur **FastAPI** qui fournit une infrastructure sécurisée pour la **génération**, le **stockage chiffré**, la **révocation**, la **rotation** et la **consultation** de paires de clés cryptographiques. Il constitue la fondation de confiance de l’écosystème, consommé par les services de signature, stéganographie et vérification.

### 🎯 Fonctionnalités Clés
- **Génération de clés** 🔑: RSA (1024–8192), ECDSA (P-256, P-384, P-521), Ed25519.
- **Stockage sécurisé** 🛡️: Clé privée chiffrée via Fernet (hex), clé publique en PEM.
- **Cycle de vie** 🔄: Expiration, révocation (avec raison), rotation (ancienne révoquée + nouvelle créée).
- **Validation** ✅: Vérifications PEM/tailles/courbes; empreintes; scénarios nominaux/cas alternatifs gérés.
- **Statistiques** 📊: Totaux, statut (actives, révoquées, expirées), répartition par type.
- **Observabilité** 👀: Endpoints `/health`, `/ready`, `/metrics` (Prometheus-like).
- **Sécurité Web** 🔒: JWT, CORS, TrustedHost, HTTPS, logs structurés, `x-trace-id`.

---

## 🏗️ Architecture

Le service suit une architecture **modulaire, orientée services** avec opérations asynchrones et migrations de schéma.

- **FastAPI** 🌐: Serveur HTTP performant et asynchrone.
- **SQLAlchemy 2 (async)** 🗄️ + **Alembic**: Modélisation et migrations DB.
- **PostgreSQL** 🐘: Stockage persistant des clés et états.
- **cryptography** 🔐: Génération et validation des clés (RSA/ECDSA/Ed25519).
- **Fernet** 🧩: Chiffrement de la clé privée.
- **JWT** 🔑: AuthN/AuthZ (rôle admin pour actions sensibles).
- **Celery + Redis (optionnel)** 🧵: Tâches asynchrones planifiées.

### 📂 Arborescence Simplifiée
```
pki-service/
├── app/
│   ├── main.py            # FastAPI app, middlewares, santé/metrics
│   ├── settings.py        # Config .env validée (DB/Redis/JWT/Fernet/CORS)
│   ├── database.py        # Moteur async, sessions, transactions, diagnostics
│   ├── models.py          # Modèle SQLAlchemy (KeyPair)
│   ├── schemas.py         # Pydantic (KeyPairCreate/Out, Revoke/Rotate)
│   ├── services.py        # Métier: create/list/stats/revoke/rotate
│   ├── routers.py         # Routes HTTP documentées (/keys)
│   ├── dependencies.py    # Fernet, JWT (rôles), Redis helper
│   └── tasks.py           # Celery app (+ tâche d’exemple)
├── migrations/            # Alembic (env.py, versions/)
├── alembic.ini            # Configuration Alembic
└── README.md              # Ce document
```

---

## ⚙️ Installation & Démarrage

### 📋 Prérequis
- Python 3.10+
- PostgreSQL 13+
- (Optionnel) Redis si Celery utilisé

### 🚀 Étapes
1) Créez et activez un virtualenv, puis installez les dépendances.
2) Créez `pki-service/.env` (voir modèle ci-dessous).
3) Appliquez les migrations.
4) Démarrez le service.

#### `.env` minimal
```env
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
Générez une FERNET_KEY à la racine du repo:
```bash
python F:\Schools\generate_fernet_key.py
```
Copiez la valeur dans le `.env` de chaque service, puis supprimez `fernet_key.txt`.

#### Migrations (Alembic)
```bash
cd F:\Schools\pki-service
. .\venv\Scripts\Activate.ps1
alembic revision --autogenerate -m "initial"
alembic upgrade head
```

#### Lancer le service
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 \
  --ssl-keyfile F:\Schools\certs\key.pem \
  --ssl-certfile F:\Schools\certs\cert.pem
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
