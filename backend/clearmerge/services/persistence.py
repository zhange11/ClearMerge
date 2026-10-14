from __future__ import annotations

import json
from typing import Any, Protocol


class ReviewRecordStore(Protocol):
    def load(self) -> list[Any]: ...
    def save(self, record: Any) -> None: ...
    def close(self) -> None: ...


class PostgresReviewStore:
    """Durable API index for reviews; LangGraph checkpoints live in the same database."""

    def __init__(self, connection_url: str) -> None:
        try:
            import psycopg
        except ImportError as error:
            raise RuntimeError("Postgres persistence requires psycopg") from error
        self._connection = psycopg.connect(connection_url, autocommit=True)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_records (
                review_id TEXT PRIMARY KEY,
                delivery_id TEXT NOT NULL UNIQUE,
                thread_id TEXT NOT NULL,
                state JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS review_records_updated_at_idx ON review_records (updated_at DESC)"
        )

    def load(self) -> list[Any]:
        rows = self._connection.execute(
            "SELECT review_id, delivery_id, thread_id, state FROM review_records ORDER BY updated_at DESC"
        ).fetchall()
        return [
            _review_record_type()(
                review_id=row[0],
                delivery_id=row[1],
                thread_id=row[2],
                state=dict(row[3]) if isinstance(row[3], dict) else json.loads(row[3]),
            )
            for row in rows
        ]

    def save(self, record: Any) -> None:
        self._connection.execute(
            """
            INSERT INTO review_records (review_id, delivery_id, thread_id, state, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, %s)
            ON CONFLICT (review_id) DO UPDATE SET
                delivery_id = EXCLUDED.delivery_id,
                thread_id = EXCLUDED.thread_id,
                state = EXCLUDED.state,
                updated_at = EXCLUDED.updated_at
            """,
            (
                record.review_id,
                record.delivery_id,
                record.thread_id,
                json.dumps(record.state),
                record.state.get("updated_at"),
            ),
        )

    def close(self) -> None:
        self._connection.close()


def _review_record_type() -> type:
    from .reviews import ReviewRecord

    return ReviewRecord
