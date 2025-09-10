import asyncio
from logging.config import fileConfig
import os
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from dotenv import load_dotenv

from app.settings import settings
from app.models import Base, KeyPair
target_metadata = Base.metadata


# === Chargement env & config ===
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Adjusted to reach project root
os.sys.path.insert(0, str(BASE_DIR))  # Insert at beginning to prioritize project modules
load_dotenv(BASE_DIR / ".env")

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
    
try:
    database_url = settings.DATABASE_URL
    if not database_url:
        raise ValueError("DATABASE_URL is not set in settings")
    print(f"database_url: {database_url}")
except ImportError as e:
    raise ImportError(f"Failed to import settings: {str(e)}")
except AttributeError as e:
    raise ValueError("DATABASE_URL or required DB variables are not set in settings")

config.set_main_option("sqlalchemy.url", database_url)

def run_migrations_offline() -> None:
    """Exécuter les migrations en mode hors-ligne."""
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        raise ValueError("No database URL provided for offline migrations")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,          # Détecte les changements de type
        compare_server_default=True # Détecte les defaults serveur
    )
    with context.begin_transaction():
        context.run_migrations()

def do_run_migrations(connection) -> None:
    """Configurer le contexte pour les migrations en ligne."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True
    )
    with context.begin_transaction():
        context.run_migrations()

async def run_migrations_online() -> None:
    """Exécuter les migrations en mode en-ligne (async)."""
    try:
        connectable = create_async_engine(
            database_url,
            poolclass=pool.NullPool,
            future=True
        )
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    except Exception as e:
        raise RuntimeError(f"Failed to run online migrations: {str(e)}")
    finally:
        if 'connectable' in locals():
            await connectable.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())