"""CBOR binary inspection and diagnostic notation, with lossless byte offsets.

RFC 8949 wire types; RFC 8742 sequences. Scanning never skips a byte. Numeric
values sent to JavaScript are strings so uint64 / negative integers stay exact.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import struct
from dataclasses import dataclass, field
from typing import Any

VERSION = "1.0.0"
MAX_DEPTH = 128


class CBORError(ValueError):
    def __init__(self, message: str, offset: int = 0):
        super().__init__(message)
        self.offset = offset


@dataclass(slots=True)
class Node:
    start: int
    end: int
    header: int
    kind: str
    value: Any = None
    children: list[Node] = field(default_factory=list)
    indefinite: bool = False
    hits: int = 1
    depth: int = 1


class Decoder:
    """Bottom-up parsing makes each byte offset independent of recursion state."""
    def __init__(self, data: bytes):
        self.data = data
        self.nodes: dict[int, Node] = {}
        self.errors: dict[int, CBORError] = {}
        for pos in range(len(data) - 1, -1, -1):
            try:
                self.nodes[pos] = self._item(pos)
            except CBORError as exc:
                self.errors[pos] = CBORError(str(exc), exc.offset)

    def _child(self, pos: int) -> Node:
        if pos in self.nodes:
            return self.nodes[pos]
        if pos in self.errors:
            raise self.errors[pos]
        raise CBORError("データが途中で終了しています", pos)

    def _item(self, start: int) -> Node:
        data, size = self.data, len(self.data)
        first = data[start]
        major, ai = first >> 5, first & 31
        pos, arg = start + 1, ai
        indefinite = ai == 31
        if 28 <= ai <= 30:
            raise CBORError("予約済みの追加情報 (28–30)", start)
        if ai in (24, 25, 26, 27):
            width = 1 << (ai - 24)
            if pos + width > size:
                raise CBORError("ヘッダーが途中で終了しています", pos)
            arg = int.from_bytes(data[pos:pos + width], "big")
            pos += width
        if indefinite and major not in (2, 3, 4, 5):
            raise CBORError("この位置では break / 不定長指定は使用できません", start)
        node = Node(start, pos, pos, "", indefinite=indefinite)
        if major in (0, 1):
            node.kind, node.value = ("uint", arg) if major == 0 else ("nint", -1 - arg)
        elif major in (2, 3):
            node.kind = "bytes" if major == 2 else "text"
            if indefinite:
                while True:
                    if pos >= size:
                        raise CBORError("不定長文字列の break がありません", pos)
                    if data[pos] == 255:
                        pos += 1
                        break
                    child = self._child(pos)
                    if child.kind != node.kind or child.indefinite:
                        raise CBORError("不定長文字列には同じ型の定長チャンクが必要です", pos)
                    node.children.append(child)
                    pos = child.end
            else:
                if arg > size - pos:
                    raise CBORError("文字列の宣言長に対してデータが不足しています", pos)
                end = pos + arg
                if major == 3:
                    try:
                        data[pos:end].decode("utf-8", errors="strict")
                    except UnicodeDecodeError as exc:
                        raise CBORError("不正な UTF-8 文字列です", pos + exc.start) from None
                pos = end
        elif major in (4, 5):
            node.kind = "array" if major == 4 else "map"
            count = arg * (2 if major == 5 else 1)
            if not indefinite and count > size - pos:
                raise CBORError("配列 / マップの宣言要素数に対してデータが不足しています", pos)
            while indefinite or len(node.children) < count:
                if indefinite and pos < size and data[pos] == 255:
                    if major == 5 and len(node.children) % 2:
                        raise CBORError("マップのキーに対応する値がありません", pos)
                    pos += 1
                    break
                child = self._child(pos)
                node.children.append(child)
                pos = child.end
        elif major == 6:
            node.kind, node.value = "tag", arg
            child = self._child(pos)
            node.children.append(child)
            pos = child.end
        else:
            if ai < 20 or ai == 24:
                if ai == 24 and arg < 32:
                    raise CBORError("2バイト simple 値は 32 以上が必要です", start)
                node.kind, node.value = "simple", arg
            elif ai in (20, 21):
                node.kind, node.value = "bool", ai == 21
            elif ai == 22:
                node.kind = "null"
            elif ai == 23:
                node.kind = "undefined"
            elif ai in (25, 26, 27):
                node.kind = "float"
                node.value = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[ai], data[start + 1:pos])[0]
        node.end = pos
        if node.children:
            node.hits += sum(n.hits for n in node.children)
            node.depth += max(n.depth for n in node.children)
            if node.depth > MAX_DEPTH:
                raise CBORError(f"ネスト上限 {MAX_DEPTH} を超えています", start)
        return node

    def payload(self, node: Node) -> bytes:
        if node.indefinite:
            return b"".join(self.payload(c) for c in node.children)
        return self.data[node.header:node.end]

    def scalar(self, node: Node) -> str:
        kind, value = node.kind, node.value
        if kind == "text":
            return json.dumps(self.payload(node).decode("utf-8"), ensure_ascii=False)
        if kind == "bytes":
            return "h'" + self.payload(node).hex() + "'"
        if kind == "float":
            if math.isnan(value):
                return "NaN"
            if math.isinf(value):
                return "Infinity" if value > 0 else "-Infinity"
            return repr(value)
        if kind == "bool":
            return "true" if value else "false"
        if kind in ("null", "undefined"):
            return kind
        if kind == "simple":
            return f"simple({value})"
        return str(value)

    def diagnostic(self, node: Node, pretty: bool = False, level: int = 0) -> str:
        if node.kind == "tag":
            return f"{node.value}({self.diagnostic(node.children[0], pretty, level)})"
        if node.kind in ("bytes", "text") and node.indefinite:
            # RFC 8949 chunk notation; preserve chunk boundaries.
            if not node.children:
                return "(_ " + ("h''" if node.kind == "bytes" else '""') + ")"
            return "(_ " + ", ".join(self.diagnostic(c) for c in node.children) + ")"
        if node.kind not in ("array", "map"):
            return self.scalar(node)
        a, b = ("[", "]") if node.kind == "array" else ("{", "}")
        prefix = a + ("_ " if node.indefinite else "")
        if not node.children:
            return prefix + b
        if node.kind == "array":
            parts = [self.diagnostic(c, pretty, level + 1) for c in node.children]
        else:
            parts = [self.diagnostic(k, False) + ": " + self.diagnostic(v, pretty, level + 1)
                     for k, v in zip(node.children[::2], node.children[1::2])]
        if pretty and (node.kind == "map" or any(c.children for c in node.children) or len(parts) > 8):
            indent = "  " * (level + 1)
            return prefix + "\n" + indent + (",\n" + indent).join(parts) + "\n" + "  " * level + b
        return prefix + ", ".join(parts) + b

    def json_value(self, node: Node) -> Any:
        kind = node.kind
        if kind in ("uint", "nint"):
            return node.value if abs(node.value) <= 9007199254740991 else {"$integer": str(node.value)}
        if kind == "float":
            return node.value if math.isfinite(node.value) else {"$float": self.scalar(node)}
        if kind == "text":
            return self.payload(node).decode("utf-8")
        if kind == "bytes":
            return {"$bytes": self.payload(node).hex()}
        if kind == "tag":
            return {"$tag": str(node.value), "value": self.json_value(node.children[0])}
        if kind == "array":
            return [self.json_value(c) for c in node.children]
        if kind == "map":
            pairs = list(zip(node.children[::2], node.children[1::2]))
            keys = [self.json_value(k) for k, _ in pairs]
            if all(isinstance(k, str) for k in keys) and len(set(keys)) == len(keys):
                return {k: self.json_value(v) for k, (_, v) in zip(keys, pairs)}
            return {"$map": [[self.json_value(k), self.json_value(v)] for k, v in pairs]}
        if kind == "undefined":
            return {"$undefined": True}
        if kind == "simple":
            return {"$simple": node.value}
        return node.value

    def rows(self, roots: list[Node]) -> tuple[list[dict], list[str]]:
        rows, warnings = [], []
        def visit(node: Node, path: str, label: str, parent: int | None, depth: int, display: str) -> None:
            index = len(rows)
            if node.kind in ("array", "map"):
                value = str(len(node.children) // (2 if node.kind == "map" else 1)) + (" pairs" if node.kind == "map" else " items")
            elif node.kind == "tag":
                value = f"tag({node.value})"
            else:
                value = self.scalar(node)
            rows.append({"id": index, "parent": parent, "path": path, "display_path": display, "label": label,
                         "depth": depth, "start": node.start, "end": node.end,
                         "header": node.header, "type": node.kind, "value": value,
                         "indefinite": node.indefinite, "children": len(node.children)})
            if node.kind == "map":
                seen: dict[str, int] = {}
                for n, (k, v) in enumerate(zip(node.children[::2], node.children[1::2])):
                    key = self.diagnostic(k)
                    occurrence = seen.get(key, 0)
                    if occurrence:
                        warnings.append(f"{path}: キー {key[:80]} が重複しています (offset {k.start})")
                    seen[key] = occurrence + 1
                    # JSON encoded path segment prevents collisions from arbitrary map keys.
                    segment = json.dumps(key, ensure_ascii=False)
                    child_path = f"{path}/map/{segment}#{occurrence}"
                    plain_key = self.payload(k).decode("utf-8") if k.kind == "text" else ""
                    suffix = "." + plain_key if re.fullmatch(r"[A-Za-z_]\w*", plain_key) else "[" + key + "]"
                    shown = display + suffix + (f"#{occurrence}" if occurrence else "")
                    visit(k, child_path + "/key", f"key · {key[:80]}", index, depth + 1, shown + " (key)")
                    visit(v, child_path + "/value", key[:80], index, depth + 1, shown)
            else:
                for n, c in enumerate(node.children):
                    suffix = "value" if node.kind == "tag" else str(n)
                    label2 = "value" if node.kind == "tag" else f"[{n}]"
                    visit(c, path + "/" + suffix, label2, index, depth + 1, display + (".value" if node.kind == "tag" else f"[{n}]"))
        for n, root in enumerate(roots):
            visit(root, f"$/{n}", f"item {n}", None, 0, "$" if len(roots) == 1 else f"$[{n}]")
        return rows, warnings

    def detail(self, start: int, sequence: bool = False) -> dict:
        if not 0 <= start < len(self.data):
            raise CBORError("開始オフセットがデータ範囲外です", start)
        roots, pos = [], start
        while pos in self.nodes:
            node = self.nodes[pos]
            roots.append(node)
            pos = node.end
            if not sequence:
                break
        rows, warnings = self.rows(roots)
        err = self.errors.get(pos) if sequence or not roots else None
        return {"offset": start, "end": pos, "consumed": pos - start,
                "hits": sum(n.hits for n in roots), "items": len(roots),
                "complete": pos == len(self.data), "rows": rows,
                "diagnostic": ",\n".join(self.diagnostic(n, True) for n in roots),
                "json": [self.json_value(n) for n in roots], "warnings": warnings,
                "error": {"message": str(err), "offset": err.offset} if err else None}

    def candidates(self, mode: str = "scan", offset: int = 0, sequence: bool = False) -> list[dict]:
        if mode not in ("scan", "exact"):
            raise CBORError("解析モードが不正です")
        # Dynamic programming: the maximal valid sequence at pos is the first
        # item followed by the already-computed maximal sequence at its end.
        chains: dict[int, tuple[int, int, int]] = {}
        for pos in range(len(self.data) - 1, -1, -1):
            node = self.nodes.get(pos)
            if node is not None:
                tail_hits, tail_items, end = chains.get(node.end, (0, 0, node.end)) if sequence else (0, 0, node.end)
                chains[pos] = (node.hits + tail_hits, tail_items + 1, end)
        candidates = [{"offset": p, "hits": h, "items": i, "consumed": end - p,
                       "end": end, "complete": end == len(self.data)}
                      for p, (h, i, end) in chains.items() if mode == "scan" or p == offset]
        candidates.sort(key=lambda c: (-c["hits"], -c["consumed"], -c["items"], c["offset"]))
        return candidates


def analyze(data: bytes, mode: str = "scan", offset: int = 0, sequence: bool = False) -> dict:
    if not data:
        raise CBORError("入力データが空です")
    if mode == "exact" and not 0 <= offset < len(data):
        raise CBORError("開始オフセットがデータ範囲外です", offset)
    decoder = Decoder(data)
    candidates = decoder.candidates(mode, offset, sequence)
    start = candidates[0]["offset"] if candidates else (offset if mode == "exact" else 0)
    return {"version": VERSION, "size": len(data), "mode": mode, "sequence": sequence,
            "tested": len(data) if mode == "scan" else 1,
            "candidates": candidates, "best": candidates[0] if candidates else None,
            "selected": decoder.detail(start, sequence)}


def head(major: int, value: int) -> bytes:
    if value < 0 or value > 0xffffffffffffffff:
        raise CBORError("CBOR ヘッダーの整数範囲外です")
    if value < 24:
        return bytes([major << 5 | value])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([major << 5 | ai]) + value.to_bytes(width, "big")
    raise CBORError("整数範囲外です")


def encode_number(value: int | float, width: int | None = None) -> bytes:
    if isinstance(value, int):
        v = value if value >= 0 else -1 - value
        if v <= 0xffffffffffffffff:
            if width is not None:
                if width not in (0, 1, 2, 3):
                    raise CBORError("整数の幅指定は _0 ～ _3 です")
                size = 1 << width
                if v >= 1 << (8 * size):
                    raise CBORError("指定した整数幅に収まりません")
                return bytes([(0 if value >= 0 else 1) << 5 | (24 + width)]) + v.to_bytes(size, "big")
            return head(0 if value >= 0 else 1, v)
        raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return head(6, 2 if value >= 0 else 3) + head(2, len(raw)) + raw
    if width is not None and width not in (1, 2, 3):
        raise CBORError("浮動小数点の幅指定は _1 / _2 / _3 です")
    if math.isnan(value) and width is None:
        return bytes.fromhex("f97e00")
    formats = [(1, 249, ">e"), (2, 250, ">f"), (3, 251, ">d")]
    for w, prefix, fmt in formats:
        if width is not None and w != width:
            continue
        try:
            packed = struct.pack(fmt, value)
            restored = struct.unpack(fmt, packed)[0]
            if width is not None or math.isnan(value) or (restored == value and math.copysign(1, restored) == math.copysign(1, value)):
                return bytes([prefix]) + packed
        except (OverflowError, struct.error):
            if width is not None:
                raise CBORError("指定した浮動小数点幅に収まりません") from None
    raise CBORError("浮動小数点数をエンコードできません")


class DiagnosticParser:
    """Safe recursive descent, never eval. Supports the RFC 8949 basic notation."""
    def __init__(self, text: str):
        self.text, self.pos = text, 0

    def space(self) -> None:
        while self.pos < len(self.text):
            if self.text[self.pos].isspace():
                self.pos += 1
            elif self.text[self.pos] == "/":
                end = self.text.find("/", self.pos + 1)
                if end < 0:
                    raise CBORError("診断表記のコメントが閉じていません", self.pos)
                self.pos = end + 1
            else:
                break

    def take(self, token: str) -> bool:
        self.space()
        if self.text.startswith(token, self.pos):
            self.pos += len(token)
            return True
        return False

    def expect(self, token: str) -> None:
        if not self.take(token):
            raise CBORError(f"診断表記: {token!r} が必要です (文字位置 {self.pos})", self.pos)

    def width(self) -> int | None:
        if self.take("_"):
            if self.pos >= len(self.text) or self.text[self.pos] not in "0123":
                raise CBORError("不正な幅指定です", self.pos)
            value = int(self.text[self.pos])
            self.pos += 1
            return value
        return None

    def value(self, depth: int = 0) -> bytes:
        self.space()
        if depth > MAX_DEPTH:
            raise CBORError("診断表記のネストが深すぎます", self.pos)
        if self.pos >= len(self.text):
            raise CBORError("診断表記が途中で終了しています", self.pos)
        ch = self.text[self.pos]
        if ch in "[{":
            self.pos += 1
            major, close = (4, "]") if ch == "[" else (5, "}")
            indefinite = self.take("_")
            parts = []
            if not self.take(close):
                while True:
                    parts.append(self.value(depth + 1))
                    if major == 5:
                        self.expect(":")
                        parts.append(self.value(depth + 1))
                    if self.take(close):
                        break
                    self.expect(",")
                    if self.take(close):
                        break
            count = len(parts) // (2 if major == 5 else 1)
            return (bytes([major << 5 | 31]) if indefinite else head(major, count)) + b"".join(parts) + (b"\xff" if indefinite else b"")
        if self.take("(_"):
            parts = [self.value(depth + 1)]
            while self.take(","):
                parts.append(self.value(depth + 1))
            self.expect(")")
            major = parts[0][0] >> 5
            if major not in (2, 3) or any(p[0] >> 5 != major or p[0] & 31 == 31 for p in parts):
                raise CBORError("不定長文字列のチャンク型が不正です", self.pos)
            return bytes([major << 5 | 31]) + b"".join(parts) + b"\xff"
        if ch == '"':
            try:
                value, used = json.JSONDecoder().raw_decode(self.text[self.pos:])
                encoded = value.encode("utf-8")
            except (ValueError, UnicodeError):
                raise CBORError("不正なテキスト文字列です", self.pos) from None
            self.pos += used
            return head(3, len(encoded)) + encoded
        for prefix in ("h'", "b64'"):
            if self.take(prefix):
                end = self.text.find("'", self.pos)
                if end < 0:
                    raise CBORError("バイト文字列が閉じていません", self.pos)
                raw = self.text[self.pos:end]
                self.pos = end + 1
                data = decode_input(raw, "hex" if prefix == "h'" else "base64")
                return head(2, len(data)) + data
        for name, raw in (("false", b"\xf4"), ("true", b"\xf5"), ("null", b"\xf6"), ("undefined", b"\xf7")):
            if self.take(name):
                return raw
        if self.take("simple("):
            match = re.match(r"\d+", self.text[self.pos:])
            if not match:
                raise CBORError("simple の値が必要です", self.pos)
            value = int(match[0])
            self.pos += len(match[0])
            self.expect(")")
            if not 0 <= value <= 255 or 24 <= value <= 31:
                raise CBORError("simple 値は 0–23 または 32–255 です", self.pos)
            return head(7, value)
        for name, value in (("-Infinity", -math.inf), ("Infinity", math.inf), ("NaN", math.nan)):
            if self.take(name):
                return encode_number(value, self.width())
        match = re.match(r"-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)", self.text[self.pos:])
        if not match:
            raise CBORError(f"診断表記を解釈できません (文字位置 {self.pos})", self.pos)
        token = match[0]
        self.pos += len(token)
        value = int(token, 0) if "x" in token.lower() or "b" in token.lower() else (float(token) if any(c in token for c in ".eE") else int(token))
        if isinstance(value, int) and self.take("("):
            if value < 0:
                raise CBORError("タグ番号は非負整数です", self.pos)
            child = self.value(depth + 1)
            self.expect(")")
            return head(6, value) + child
        return encode_number(value, self.width())

    def parse(self) -> bytes:
        self.space()
        if self.pos == len(self.text):
            raise CBORError("診断表記が空です")
        result = [self.value()]
        while self.take(","):
            result.append(self.value())
        self.space()
        if self.pos != len(self.text):
            raise CBORError(f"診断表記の末尾に余分な文字があります (文字位置 {self.pos})", self.pos)
        return b"".join(result)


def encode_json(value: Any, depth: int = 0) -> bytes:
    if depth > MAX_DEPTH:
        raise CBORError("JSON のネストが深すぎます")
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, (int, float)):
        return encode_number(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode_json(v, depth + 1) for v in value)
    if isinstance(value, dict):
        # JSON mode is literal JSON. Extended JSON output is not silently interpreted.
        return head(5, len(value)) + b"".join(encode_json(k, depth + 1) + encode_json(v, depth + 1) for k, v in value.items())
    raise CBORError("サポートされていない JSON 値です")


def decode_input(text: str, fmt: str) -> bytes:
    if not isinstance(text, str):
        raise CBORError("入力は文字列で指定してください")
    if fmt == "hex":
        text = text.strip()
        if text.startswith("h'") and text.endswith("'"):
            text = text[2:-1]
        text = re.sub(r"0[xX]", "", text)
        text = re.sub(r"[\s,:_-]", "", text)
        if re.search(r"[^0-9a-fA-F]", text) or len(text) % 2:
            raise CBORError("HEX は偶数桁の16進数で指定してください。オフセット / ASCII 列は含めないでください")
        return bytes.fromhex(text)
    if fmt == "base64":
        compact = re.sub(r"\s", "", text)
        try:
            return base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            raise CBORError("不正な Base64 です") from None
    if fmt == "diagnostic":
        return DiagnosticParser(text).parse()
    if fmt == "json":
        try:
            value = json.loads(text, parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
            return encode_json(value)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise CBORError(f"不正な JSON です: {exc}") from None
    raise CBORError("入力形式が不正です")
