import os
from logging.config import fileConfig

from alembic import context
from one_os_addon.models import Base
from sqlalchemy import engine_from_config, pool, text

config = context.config
if os.getenv("DATABASE_URL") and not config.attributes.get("explicit_database_url"):
    config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _install_legacy_boolean_addition(connection):
    """Provide PostgreSQL compatibility for immutable revision 0002."""
    schema = f"one_os_alembic_boolean_compat_{connection.scalar(text('SELECT pg_backend_pid()'))}"
    quoted_schema = connection.dialect.identifier_preparer.quote(schema)
    original_search_path = connection.scalar(text("SHOW search_path"))
    connection.exec_driver_sql(f"CREATE SCHEMA {quoted_schema}")  # noqa: S608
    connection.exec_driver_sql(
        f"CREATE FUNCTION {quoted_schema}.boolean_add(boolean, boolean) "  # noqa: S608
        "RETURNS integer LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE "
        "RETURN $1::integer + $2::integer"
    )
    connection.exec_driver_sql(
        f"CREATE OPERATOR {quoted_schema}.+ ("  # noqa: S608
        "LEFTARG = boolean, RIGHTARG = boolean, "
        f"FUNCTION = {quoted_schema}.boolean_add)"  # noqa: S608
    )
    connection.exec_driver_sql(
        f"CREATE FUNCTION {quoted_schema}.integer_boolean_add(integer, boolean) "  # noqa: S608
        "RETURNS integer LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE "
        "RETURN $1 + $2::integer"
    )
    connection.exec_driver_sql(
        f"CREATE OPERATOR {quoted_schema}.+ ("  # noqa: S608
        "LEFTARG = integer, RIGHTARG = boolean, "
        f"FUNCTION = {quoted_schema}.integer_boolean_add)"  # noqa: S608
    )
    connection.execute(
        text("SELECT set_config('search_path', :path, true)"),
        {"path": f"{original_search_path}, {quoted_schema}"},
    )
    return quoted_schema, original_search_path


def _remove_legacy_boolean_addition(connection, compatibility):
    quoted_schema, original_search_path = compatibility
    connection.execute(
        text("SELECT set_config('search_path', :path, true)"),
        {"path": original_search_path},
    )
    connection.exec_driver_sql(f"DROP SCHEMA {quoted_schema} CASCADE")  # noqa: S608


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata, render_as_batch=True
            )
            with context.begin_transaction():
                current_revision = context.get_context().get_current_revision()
                compatibility = None
                if connection.dialect.name == "postgresql" and current_revision in (None, "0001"):
                    compatibility = _install_legacy_boolean_addition(connection)
                context.run_migrations()
                # On failure PostgreSQL rolls the uncommitted compatibility schema back with
                # the migration; only the successful path needs an explicit pre-commit drop.
                if compatibility is not None:
                    _remove_legacy_boolean_addition(connection, compatibility)
    finally:
        connectable.dispose()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
