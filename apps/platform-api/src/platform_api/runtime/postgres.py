"""PostgreSQL-backed repository implementations for platform-api."""

from __future__ import annotations

import json
from typing import Any

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from platform_contracts import Artifact, Case, Run


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------

_pool: ThreadedConnectionPool | None = None


def init_pool(dsn: str, minconn: int = 1, maxconn: int = 10) -> None:
    """Initialise the module-level connection pool. Call once at startup."""
    global _pool
    _pool = ThreadedConnectionPool(minconn, maxconn, dsn)


def get_pool() -> ThreadedConnectionPool:
    if _pool is None:
        raise RuntimeError("PostgreSQL connection pool has not been initialised")
    return _pool


def close_pool() -> None:
    if _pool is not None:
        _pool.closeall()


class _PoolCursor:
    """Context manager that checks out a connection and returns it on exit."""

    def __init__(self) -> None:
        self._conn = None

    def __enter__(self):
        self._conn = get_pool().getconn()
        self._conn.autocommit = False
        return self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        get_pool().putconn(self._conn)


# ---------------------------------------------------------------------------
# Case repository
# ---------------------------------------------------------------------------

class PostgresCaseRepository:
    """Persists Case records as JSONB rows keyed by case_id."""

    def get_case(self, case_id: str) -> Case | None:
        with _PoolCursor() as cur:
            cur.execute("SELECT data FROM cases WHERE case_id = %s", (case_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return Case.model_validate(row["data"])

    def save_case(self, case: Case) -> Case:
        data = case.model_dump(mode="json")
        with _PoolCursor() as cur:
            cur.execute(
                """
                INSERT INTO cases (case_id, client_id, data, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (case_id) DO UPDATE
                  SET data = EXCLUDED.data,
                      client_id = EXCLUDED.client_id,
                      updated_at = EXCLUDED.updated_at
                """,
                (
                    case.case_id,
                    case.client_id,
                    json.dumps(data),
                    case.created_at,
                    case.updated_at,
                ),
            )
        return Case.model_validate(data)

    def list_cases_by_client(self, client_id: str) -> list[Case]:
        with _PoolCursor() as cur:
            cur.execute(
                "SELECT data FROM cases WHERE client_id = %s ORDER BY created_at DESC",
                (client_id,),
            )
            rows = cur.fetchall()
        return [Case.model_validate(row["data"]) for row in rows]


# ---------------------------------------------------------------------------
# Artifact repository
# ---------------------------------------------------------------------------

class PostgresArtifactRepository:
    """Persists Artifact records and their payloads as JSONB."""

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        with _PoolCursor() as cur:
            cur.execute("SELECT data FROM artifacts WHERE artifact_id = %s", (artifact_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return Artifact.model_validate(row["data"])

    def save_artifact(
        self,
        artifact: Artifact,
        *,
        payload: object | None = None,
        content_source: str | None = None,
    ) -> Artifact:
        data = artifact.model_dump(mode="json")
        payload_json = json.dumps(payload) if payload is not None else None
        with _PoolCursor() as cur:
            cur.execute(
                """
                INSERT INTO artifacts (artifact_id, data, payload, content_source, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (artifact_id) DO UPDATE
                  SET data = EXCLUDED.data,
                      payload = COALESCE(EXCLUDED.payload, artifacts.payload),
                      content_source = COALESCE(EXCLUDED.content_source, artifacts.content_source)
                """,
                (
                    artifact.artifact_id,
                    json.dumps(data),
                    payload_json,
                    content_source,
                    artifact.created_at,
                ),
            )
        return Artifact.model_validate(data)

    def get_payload(self, artifact_id: str) -> object | None:
        with _PoolCursor() as cur:
            cur.execute("SELECT payload FROM artifacts WHERE artifact_id = %s", (artifact_id,))
            row = cur.fetchone()
        if row is None or row["payload"] is None:
            return None
        return row["payload"]

    def get_content_source(self, artifact_id: str) -> str | None:
        with _PoolCursor() as cur:
            cur.execute("SELECT content_source FROM artifacts WHERE artifact_id = %s", (artifact_id,))
            row = cur.fetchone()
        return row["content_source"] if row else None

    def get_artifacts(self, artifact_ids: list[str]) -> list[Artifact]:
        if not artifact_ids:
            return []
        with _PoolCursor() as cur:
            cur.execute(
                "SELECT data FROM artifacts WHERE artifact_id = ANY(%s)",
                (artifact_ids,),
            )
            rows = cur.fetchall()
        id_order = {aid: i for i, aid in enumerate(artifact_ids)}
        artifacts = [Artifact.model_validate(row["data"]) for row in rows]
        artifacts.sort(key=lambda a: id_order.get(a.artifact_id, 9999))
        return artifacts


# ---------------------------------------------------------------------------
# Run repository
# ---------------------------------------------------------------------------

class PostgresRunRepository:
    """Persists Run records as JSONB rows keyed by run_id."""

    def get_run(self, run_id: str) -> Run | None:
        with _PoolCursor() as cur:
            cur.execute("SELECT data FROM runs WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return Run.model_validate(row["data"])

    def save_run(self, run: Run) -> Run:
        data = run.model_dump(mode="json")
        case_id = run.case_ref.id if run.case_ref else None
        with _PoolCursor() as cur:
            cur.execute(
                """
                INSERT INTO runs (run_id, case_id, data, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (run_id) DO UPDATE
                  SET data = EXCLUDED.data,
                      updated_at = EXCLUDED.updated_at
                """,
                (
                    run.run_id,
                    case_id,
                    json.dumps(data),
                    run.created_at,
                    run.updated_at,
                ),
            )
        return Run.model_validate(data)


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    data          JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS cases_client_id_idx ON cases (client_id);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id    TEXT PRIMARY KEY,
    data           JSONB NOT NULL,
    payload        JSONB,
    content_source TEXT,
    created_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    case_id     TEXT,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_case_id_idx ON runs (case_id);
"""


def apply_schema() -> None:
    """Idempotently create tables if they do not exist."""
    with _PoolCursor() as cur:
        cur.execute(SCHEMA_SQL)
