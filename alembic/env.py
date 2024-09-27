# alembic/env.py
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
from app.core.config import settings

# Append the app directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.db.base import Base  # Import your Base
from app.core.config import settings  # Import settings

# this is the Alembic Config object, which provides access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
fileConfig(config.config_file_name)

# Set the SQLAlchemy database URL
config.set_main_option('sqlalchemy.url', settings.DATABASE_URL)
print(f"Database URL: {settings.DATABASE_URL}")

target_metadata = Base.metadata

def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,  # Enable if you want Alembic to detect changes in column types
        )

        with context.begin_transaction():
            context.run_migrations()

run_migrations_online()

