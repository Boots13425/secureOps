from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .config import settings


@contextmanager
def connection():
    with psycopg.connect(settings.dsn, row_factory=dict_row) as conn:
        yield conn


def initialize_schema() -> None:
    schema = (Path(__file__).resolve().parents[1] / "schema.sql").read_text(encoding="utf-8")
    with connection() as conn:
        conn.execute(schema)
