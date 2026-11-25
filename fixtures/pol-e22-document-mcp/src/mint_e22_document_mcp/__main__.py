"""Serve a single bounded, local test document over MCP stdio."""

import os
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from typing import Annotated, TypedDict

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

DOCUMENT_ID = "e22-test-document"
MAX_LINES = 32
server = MCPServer("mint-e22-document-mcp")


class DocumentState(TypedDict):
    document_id: str
    change_count: int
    lines: list[str]


def state_file() -> Path:
    override = os.environ.get("E22_STATE_DIR")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if override:
        directory = Path(override)
    elif local_app_data:
        directory = Path(local_app_data) / "MINT-E22-Document-Test"
    else:
        raise ToolError("E22_STATE_DIR must name a dedicated test-state directory.")

    if not directory.is_absolute() or directory.resolve() != directory:
        raise ToolError("The test-state directory must be an absolute, non-redirected path.")
    directory.mkdir(parents=True, exist_ok=True)
    database = directory / "e22-test-document.sqlite3"
    if database.resolve() != database or (
        database.exists() and (not database.is_file() or database.stat().st_nlink != 1)
    ):
        raise ToolError("The test-state database must be a regular, unlinked file.")
    return database


@contextmanager
def open_document():
    connection = sqlite3.connect(state_file(), timeout=5)
    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS document_lines (
                    sequence INTEGER PRIMARY KEY,
                    line TEXT NOT NULL
                )
            """)
            yield connection
    finally:
        connection.close()


def read_document(connection: sqlite3.Connection) -> DocumentState:
    rows = connection.execute("SELECT line FROM document_lines ORDER BY sequence").fetchall()
    return {"document_id": DOCUMENT_ID, "change_count": len(rows), "lines": [row[0] for row in rows]}


@server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def get_test_document() -> DocumentState:
    """Read the fixed test document and its committed change count."""
    with open_document() as connection:
        return read_document(connection)


@server.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
))
def append_test_line(text: Annotated[str, Field(min_length=1, max_length=120)]) -> DocumentState:
    """Append one line to the fixed test document and return its committed change count."""
    if not text.strip() or any(not character.isprintable() for character in text):
        raise ToolError("Enter one nonempty line of printable text.")
    with open_document() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT count(*) FROM document_lines").fetchone()[0] >= MAX_LINES:
            raise ToolError("The test document has reached its 32-line limit.")
        connection.execute("INSERT INTO document_lines(line) VALUES (?)", (text,))
        return read_document(connection)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
