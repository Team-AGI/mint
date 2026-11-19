"""Run against PostgreSQL with MINT_TEST_DATABASE_URL and gateway on PYTHONPATH."""
import os
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app import activity, db


@unittest.skipUnless(os.getenv("MINT_TEST_DATABASE_URL"), "set MINT_TEST_DATABASE_URL for PostgreSQL")
class ActivityAnalysisTest(unittest.IsolatedAsyncioTestCase):
    async def test_comparison_uses_only_scoped_timeline_queries(self):
        # One connection keeps the fixture in pg_temp for both reporting modes.
        async with AsyncConnectionPool(os.environ["MINT_TEST_DATABASE_URL"], min_size=1, max_size=1,
                                       kwargs={"row_factory": dict_row}, open=False) as pool:
            self.enterContext(patch.object(db, "admin_pool", return_value=pool))
            self.enterContext(patch.object(db, "pool", side_effect=AssertionError("unexpected decision pool checkout")))
            async with pool.connection() as connection:
                await connection.execute("""
                    CREATE TEMP TABLE principals (token text, display_name text);
                    CREATE TEMP TABLE decisions (created_at timestamptz, user_token text, decision text,
                        server_id text, policy_id text, client jsonb, result_preview jsonb,
                        upstream_executed boolean, upstream_attempted boolean);
                    INSERT INTO decisions (created_at, user_token, decision) VALUES
                        ('2026-01-01 15:20Z', 'a', 'Allow'), ('2026-01-01 15:40Z', 'a', 'Block'),
                        ('2026-01-07 09:00Z', 'a', 'Alert'), ('2026-07-01 06:00Z', 'a', 'Allow'),
                        ('2026-01-01 15:30Z', 'b', 'Block');
                """)

            for month, bucket, count in [(1, "hour", 2), (2, "day", 3), (8, "month", 4)]:
                with self.subTest(bucket=bucket):
                    filters = dict(user_token="a", event_kind="tools/call", until=datetime(2026, month, 2, tzinfo=UTC))
                    full = await activity.analysis(**filters)
                    before = pool.get_stats()["requests_num"]
                    timeline = await activity.analysis(**filters, series_only=True)
                    self.assertEqual(pool.get_stats()["requests_num"] - before, 2)
                    self.assertEqual(timeline, {key: full[key] for key in ("total", "bucket", "series")})
                    self.assertEqual((timeline["bucket"], timeline["total"]), (bucket, count))
                    if bucket == "hour":
                        self.assertEqual({row["at"] for row in timeline["series"]}, {datetime(2026, 1, 2)})

            before = pool.get_stats()["requests_num"]
            empty = await activity.analysis(user_token="a", principal="b", series_only=True)
            self.assertEqual(pool.get_stats()["requests_num"] - before, 1)
            self.assertEqual(empty, {"total": 0, "bucket": "hour", "series": []})
