"""Async stdio JSON-RPC transport.

This module is the *only* writer of raw response bytes. Detection rules receive
what it recorded; they never manufacture it.

Two properties matter for evidence integrity:

  * Every send records the exact text written, and every read records the exact
    text received, before any parsing. Both go into DynamicEvidence unmodified.
  * A read timeout returns a ``Timeout`` sentinel. It never returns a
    synthesised response dict. The previous implementation fabricated
    ``{"error": "Method not found but processed"}``-style payloads and reported
    them as observations; there is deliberately no way to do that here.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


class Timeout:
    """Sentinel: no answer arrived within the deadline. Not a response."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover
        return "<Timeout>"


TIMEOUT = Timeout()


@dataclass
class Exchange:
    """One request and whatever came back, verbatim."""

    request_obj: Dict[str, Any]
    request_json: str
    response_raw: str = ""
    response_parsed: Optional[Dict[str, Any]] = None
    timed_out: bool = False
    transport_error: Optional[str] = None

    @property
    def answered(self) -> bool:
        return bool(self.response_raw) and self.response_parsed is not None

    def result(self) -> Optional[Any]:
        if self.response_parsed and "result" in self.response_parsed:
            return self.response_parsed["result"]
        return None

    def error(self) -> Optional[Dict[str, Any]]:
        if self.response_parsed and isinstance(
            self.response_parsed.get("error"), dict
        ):
            return self.response_parsed["error"]
        return None

    def error_code(self) -> Optional[int]:
        err = self.error()
        if err is None:
            return None
        code = err.get("code")
        return code if isinstance(code, int) else None

    def response_text(self) -> str:
        """Everything the server said, as a flat string, for canary searching."""
        return self.response_raw


class StdioClient:
    """Line-delimited JSON-RPC 2.0 over a child process's stdin/stdout.

    A single background reader owns stdout and dispatches each line to the
    future waiting on that request id. That is what makes pipelining safe: with
    several requests in flight, no coroutine can consume an answer belonging to
    another one. Responses whose id nobody is waiting for (including the
    ``id: null`` a server returns for a parse error) go to a loose queue that a
    waiter with no expected id can consume.
    """

    def __init__(self, proc: asyncio.subprocess.Process):
        self.proc = proc
        self._next_id = 1
        self.notifications: List[str] = []
        self.stderr_lines: List[str] = []
        self._stderr_task: Optional[asyncio.Task] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._pending: Dict[Any, asyncio.Future] = {}
        self._loose: "asyncio.Queue[tuple]" = asyncio.Queue()
        self._stdout_closed = False

    # -- lifecycle ---------------------------------------------------------

    def start_stderr_pump(self) -> None:
        async def pump() -> None:
            assert self.proc.stderr is not None
            while True:
                try:
                    line = await self.proc.stderr.readline()
                except Exception:
                    return
                if not line:
                    return
                self.stderr_lines.append(
                    line.decode("utf-8", errors="replace").rstrip("\r\n"))
                del self.stderr_lines[:-500]

        self._stderr_task = asyncio.ensure_future(pump())
        self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self) -> None:
        assert self.proc.stdout is not None
        while True:
            try:
                line = await self.proc.stdout.readline()
            except Exception:
                break
            if not line:
                self._stdout_closed = True
                break
            text = line.decode("utf-8", errors="replace")
            if not text.strip():
                continue

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                # Non-JSON on stdout is itself an observation.
                await self._loose.put((text, None))
                continue

            if isinstance(parsed, dict) and "id" not in parsed and "method" in parsed:
                self.notifications.append(text.strip())
                continue

            rid = parsed.get("id") if isinstance(parsed, dict) else None
            fut = self._pending.pop(rid, None)
            if fut is not None and not fut.done():
                fut.set_result((text, parsed if isinstance(parsed, dict) else None))
            else:
                await self._loose.put(
                    (text, parsed if isinstance(parsed, dict) else None))

        # Wake anything still waiting.
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    def stderr_tail(self, n: int = 20) -> str:
        return "\n".join(self.stderr_lines[-n:])

    @property
    def alive(self) -> bool:
        return self.proc.returncode is None

    # -- io ----------------------------------------------------------------

    def next_id(self) -> int:
        i = self._next_id
        self._next_id += 1
        return i

    async def request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        timeout: float = 5.0,
        request_id: Optional[Any] = None,
    ) -> Exchange:
        rid = self.next_id() if request_id is None else request_id
        obj: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            obj["params"] = params
        return await self.send_object(obj, timeout=timeout, expect_id=rid)

    async def notify(self, method: str,
                     params: Optional[Dict[str, Any]] = None) -> None:
        obj: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            obj["params"] = params
        await self._write(json.dumps(obj))

    async def _write(self, text: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((text + "\n").encode("utf-8"))
        await self.proc.stdin.drain()

    async def send_object(
        self,
        obj: Dict[str, Any],
        *,
        timeout: float = 5.0,
        expect_id: Any = None,
    ) -> Exchange:
        return await self.send_raw(json.dumps(obj), obj, timeout=timeout,
                                   expect_id=expect_id)

    async def send_raw(
        self,
        request_json: str,
        request_obj: Optional[Dict[str, Any]] = None,
        *,
        timeout: float = 5.0,
        expect_id: Any = None,
    ) -> Exchange:
        """Send and await the correlated answer.

        Safe to call concurrently: each call registers its own future before
        writing, so answers cannot be stolen by a sibling request.
        """
        ex = Exchange(request_obj=request_obj or {}, request_json=request_json)
        if not self.alive:
            ex.transport_error = f"process already exited rc={self.proc.returncode}"
            return ex

        loop = asyncio.get_event_loop()
        fut: Optional[asyncio.Future] = None
        if expect_id is not None:
            fut = loop.create_future()
            self._pending[expect_id] = fut

        try:
            await self._write(request_json)
        except Exception as exc:  # noqa: BLE001
            if expect_id is not None:
                self._pending.pop(expect_id, None)
            ex.transport_error = f"write failed: {exc}"
            return ex

        try:
            if fut is not None:
                text, parsed = await asyncio.wait_for(fut, timeout)
            else:
                text, parsed = await asyncio.wait_for(self._loose.get(), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            if expect_id is not None:
                self._pending.pop(expect_id, None)
            if self._stdout_closed and not self.alive:
                ex.transport_error = "stdout closed"
            else:
                ex.timed_out = True
            return ex

        ex.response_raw = text
        ex.response_parsed = parsed
        return ex

    async def close(self) -> None:
        for task in (self._stderr_task, self._reader_task):
            if task:
                task.cancel()
        try:
            if self.proc.stdin and not self.proc.stdin.is_closing():
                self.proc.stdin.close()
        except Exception:
            pass


async def spawn(
    argv: Sequence[str],
    cwd: str,
    env: Optional[Dict[str, str]] = None,
) -> asyncio.subprocess.Process:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    kwargs: Dict[str, Any] = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    return await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=full_env,
        **kwargs,
    )
