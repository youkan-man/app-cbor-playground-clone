"""Self-hosted CBOR workbench. No external requests or frontend CDNs."""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import time
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

from cbor_codec import CBORError, Decoder, VERSION, analyze, decode_input

LOG = logging.getLogger("cbor")
ROOT = Path(__file__).resolve().parent
MAX_BYTES = int(os.environ.get("CBOR_MAX_BYTES", "262144"))
MAX_BODY = MAX_BYTES * 12 + 4096


def json_pack(value: Any) -> bytes:
    return zlib.compress(json.dumps(value, ensure_ascii=False, allow_nan=False).encode(), 6)


def json_unpack(value: bytes) -> Any:
    return json.loads(zlib.decompress(value))


class Store:
    def __init__(self, directory: str | Path):
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        self.path = path / "history.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS history (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, created TEXT NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL,
                format TEXT NOT NULL, mode TEXT NOT NULL, requested_offset INTEGER NOT NULL,
                data BLOB NOT NULL, result BLOB NOT NULL, summary TEXT NOT NULL)""")

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def list(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT id,title,created,pinned,format,mode,summary FROM history ORDER BY pinned DESC,created DESC").fetchall()
        return [{**{k: r[k] for k in ("id", "title", "created", "pinned", "format", "mode")}, **json.loads(r["summary"])} for r in rows]

    @staticmethod
    def summary(result: dict) -> str:
        s = result["selected"]
        return json.dumps({"size": result["size"], "offset": s["offset"], "hits": s["hits"], "consumed": s["consumed"], "items": s["items"]})

    def save(self, payload: dict) -> dict:
        fmt, mode = payload.get("format", "hex"), payload.get("mode", "scan")
        text = payload.get("text", "")
        offset = parse_offset(payload.get("offset", 0))
        title = str(payload.get("title", "")).strip()[:180]
        if not isinstance(text, str):
            raise CBORError("入力は文字列で指定してください")
        raw = decode_input(text, fmt)
        if len(raw) > MAX_BYTES:
            raise CBORError(f"入力上限は {MAX_BYTES:,} バイトです。CBOR_MAX_BYTES で変更できます")
        started = time.perf_counter()
        sequence = payload.get("sequence", False)
        if not isinstance(sequence, bool):
            raise CBORError("sequence は真偽値で指定してください")
        result = analyze(raw, mode, offset, sequence)
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        identifier = uuid.uuid4().hex
        title = title or f"解析 · {now[11:19]} · {len(raw)} B"
        with self.connect() as db:
            db.execute("INSERT INTO history(id,title,created,source,format,mode,requested_offset,data,result,summary) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (identifier, title, now, text, fmt, mode, offset, raw, json_pack(result), self.summary(result)))
        return self.get(identifier)

    def get(self, identifier: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM history WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise LookupError("履歴が見つかりません")
        result = {k: row[k] for k in ("id", "title", "created", "pinned", "source", "format", "mode", "requested_offset")}
        result["hex"] = row["data"].hex()
        result["result"] = json_unpack(row["result"])
        return result

    def patch(self, identifier: str, payload: dict) -> dict:
        with self.connect() as db:
            if "title" in payload:
                title = str(payload["title"]).strip()[:180]
                if not title:
                    raise CBORError("履歴名を入力してください")
                db.execute("UPDATE history SET title=? WHERE id=?", (title, identifier))
            if "pinned" in payload:
                if not isinstance(payload["pinned"], bool):
                    raise CBORError("pinned は真偽値で指定してください")
                db.execute("UPDATE history SET pinned=? WHERE id=?", (int(payload["pinned"]), identifier))
        return self.get(identifier)

    def select(self, identifier: str, offset: int) -> dict:
        record = self.get(identifier)
        selected = Decoder(bytes.fromhex(record["hex"])).detail(offset, record["result"].get("sequence", False))
        result = record["result"]
        result["selected"] = selected
        with self.connect() as db:
            db.execute("UPDATE history SET result=?,summary=? WHERE id=?", (json_pack(result), self.summary(result), identifier))
        record["result"] = result
        return record

    def delete(self, identifier: str) -> None:
        with self.connect() as db:
            count = db.execute("DELETE FROM history WHERE id=?", (identifier,)).rowcount
        if not count:
            raise LookupError("履歴が見つかりません")


def parse_offset(value: Any) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError()
        offset = int(value, 16 if value.lower().startswith("0x") else 10) if isinstance(value, str) else int(value)
        if offset < 0 or isinstance(value, float) and value != offset:
            raise ValueError()
        return offset
    except (ValueError, TypeError, OverflowError):
        raise CBORError("開始オフセットは非負整数 (10進 / 0x16進) で指定してください") from None


def compare_records(a: dict, b: dict) -> dict:
    left = {r["path"]: r for r in a["result"]["selected"]["rows"]}
    right = {r["path"]: r for r in b["result"]["selected"]["rows"]}
    rows, counts = [], {"added": 0, "removed": 0, "changed": 0, "encoding": 0, "same": 0}
    for path in dict.fromkeys([*left, *right]):
        x, y = left.get(path), right.get(path)
        if x is None:
            status = "added"
        elif y is None:
            status = "removed"
        elif (x["type"], x["value"]) != (y["type"], y["value"]):
            status = "changed"
        else:
            # Only compare a container's header, not its whole subtree. A single
            # leaf modification should not mark every ancestor as changed.
            endx = x["header"] if x["children"] else x["end"]
            endy = y["header"] if y["children"] else y["end"]
            hx, hy = a["hex"][x["start"] * 2:endx * 2], b["hex"][y["start"] * 2:endy * 2]
            status = "encoding" if (hx, x["indefinite"]) != (hy, y["indefinite"]) else "same"
        counts[status] += 1
        rows.append({"path": path, "status": status, "left": x, "right": y})
    ah, bh = a["hex"], b["hex"]
    differences = sum(ah[i:i + 2] != bh[i:i + 2] for i in range(0, max(len(ah), len(bh)), 2))
    return {"left": a, "right": b, "rows": rows, "counts": counts, "byte_differences": differences}


class RequestProtection:
    """Bounded request body and same-origin mutation without cookies or accounts."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if scope["method"] in ("POST", "PATCH", "DELETE"):
            origin = headers.get("origin")
            host = headers.get("host", "")
            if origin and origin not in ("http://" + host, "https://" + host):
                return await JSONResponse({"error": "別オリジンからの更新は許可していません"}, status_code=403)(scope, receive, send)
        length = headers.get("content-length", "0")
        try:
            too_large = int(length) > MAX_BODY
        except ValueError:
            too_large = True
        if too_large:
            return await JSONResponse({"error": "リクエストが大きすぎます"}, status_code=413)(scope, receive, send)
        used = 0
        async def bounded_receive():
            nonlocal used
            message = await receive()
            used += len(message.get("body", b""))
            if used > MAX_BODY:
                raise CBORError("リクエストが大きすぎます")
            return message
        async def safe_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"same-origin"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
                    (b"cache-control", b"no-store"),
                ])
            await send(message)
        await self.app(scope, bounded_receive, safe_send)


def create_app(data_dir: str | Path | None = None):
    store = Store(data_dir or os.environ.get("CBOR_DATA_DIR", str(ROOT / "data")))

    async def payload(request: Request) -> dict:
        try:
            value = await request.json()
        except (ValueError, UnicodeError):
            raise CBORError("JSON リクエストが不正です") from None
        if not isinstance(value, dict):
            raise CBORError("JSON オブジェクトが必要です")
        return value

    async def home(request):
        return FileResponse(ROOT / "static" / "index.html")

    async def health(request):
        return JSONResponse({"status": "ok", "version": VERSION, "max_bytes": MAX_BYTES})

    async def history(request):
        return JSONResponse(await run_in_threadpool(store.list))

    async def run_analysis(request):
        value = await payload(request)
        return JSONResponse(await run_in_threadpool(store.save, value), status_code=201)

    async def entry(request):
        identifier = request.path_params["id"]
        if request.method == "PATCH":
            value = await payload(request)
            result = await run_in_threadpool(store.patch, identifier, value)
        elif request.method == "DELETE":
            await run_in_threadpool(store.delete, identifier)
            return Response(status_code=204)
        else:
            result = await run_in_threadpool(store.get, identifier)
        return JSONResponse(result)

    async def candidate(request):
        value = await payload(request)
        result = await run_in_threadpool(store.select, request.path_params["id"], parse_offset(value.get("offset", 0)))
        return JSONResponse(result)

    async def comparison(request):
        value = await payload(request)
        if not isinstance(value.get("left"), str) or not isinstance(value.get("right"), str):
            raise CBORError("比較する2件の履歴を指定してください")
        a = await run_in_threadpool(store.get, value["left"])
        b = await run_in_threadpool(store.get, value["right"])
        return JSONResponse(await run_in_threadpool(compare_records, a, b))

    async def node_info(request):
        record = await run_in_threadpool(store.get, request.path_params["id"])
        offset = parse_offset(request.query_params.get("offset", "0"))
        def inspect():
            decoder = Decoder(bytes.fromhex(record["hex"]))
            node = decoder.nodes.get(offset)
            if node is None:
                raise CBORError("この位置に有効な CBOR 要素はありません", offset)
            return {"diagnostic": decoder.diagnostic(node, True), "json": decoder.json_value(node),
                    "hex": decoder.data[node.start:node.end].hex(),
                    "payload": decoder.payload(node).hex() if node.kind in ("bytes", "text") else None}
        return JSONResponse(await run_in_threadpool(inspect))

    async def export(request):
        record = await run_in_threadpool(store.get, request.path_params["id"])
        fmt = request.query_params.get("format", "json")
        identifier = record["id"][:8]
        if fmt == "cbor":
            body, mime, suffix = bytes.fromhex(record["hex"]), "application/cbor", ".cbor"
        elif fmt == "diagnostic":
            body, mime, suffix = record["result"]["selected"]["diagnostic"], "text/plain; charset=utf-8", ".diag"
        else:
            body, mime, suffix = json.dumps(record, ensure_ascii=False, indent=2), "application/json", ".json"
        return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="cbor-{identifier}{suffix}"'})

    async def known_error(request, exc):
        code = 404 if isinstance(exc, LookupError) else 400
        return JSONResponse({"error": str(exc), "offset": getattr(exc, "offset", None)}, status_code=code)

    routes = [Route("/", home), Route("/api/health", health), Route("/api/history", history),
              Route("/api/analyze", run_analysis, methods=["POST"]),
              Route("/api/compare", comparison, methods=["POST"]),
              Route("/api/history/{id}/candidate", candidate, methods=["POST"]),
              Route("/api/history/{id}/node", node_info), Route("/api/history/{id}/export", export),
              Route("/api/history/{id}", entry, methods=["GET", "PATCH", "DELETE"]),
              Mount("/static", app=StaticFiles(directory=ROOT / "static"))]
    app = Starlette(routes=routes, exception_handlers={CBORError: known_error, LookupError: known_error})
    app.add_middleware(RequestProtection)
    app.state.store = store
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), log_level="info")
