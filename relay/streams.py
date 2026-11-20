"""Byte pipes between two connections."""

from __future__ import annotations

import asyncio

CHUNK = 64 * 1024


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
    """Copies from reader to writer until the reader ends. True when the
    writer's side was then half-closed, False when it could not be."""
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, EOFError):
        return False
    try:
        if writer.can_write_eof():
            writer.write_eof()
            return True
    except (OSError, RuntimeError):
        pass
    return False


async def splice(a_reader: asyncio.StreamReader, a_writer: asyncio.StreamWriter,
                 b_reader: asyncio.StreamReader, b_writer: asyncio.StreamWriter) -> None:
    """Joins two connections both ways until both end, then closes them. When
    one direction ends and the other side cannot be half-closed (TLS), both close."""
    one = asyncio.ensure_future(pipe(a_reader, b_writer))
    two = asyncio.ensure_future(pipe(b_reader, a_writer))
    try:
        done, waiting = await asyncio.wait({one, two}, return_when=asyncio.FIRST_COMPLETED)
        if waiting and all(task.result() for task in done):
            await asyncio.wait(waiting)
    finally:
        for task in (one, two):
            task.cancel()
        for writer in (a_writer, b_writer):
            close(writer)


def close(writer: asyncio.StreamWriter) -> None:
    """Closes a connection, whatever state it is in."""
    try:
        writer.close()
    except (OSError, RuntimeError):
        pass


def address(writer: asyncio.StreamWriter) -> str:
    """The far end's IP address, for the log."""
    try:
        peer = writer.get_extra_info("peername")
    except (OSError, RuntimeError):
        peer = None
    return str(peer[0]) if peer else "?"
