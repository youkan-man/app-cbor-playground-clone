"""Recognize pasted CBOR representations without silently repairing bytes.

The wire decoder remains strict. This module accepts transport representations,
extracts byte columns, and records discontinuities before the decoder sees them.
Offsets in ``segments`` address the extracted data; source offsets address the
original input string. Independent fragments must never be decoded as a single
CBOR item merely because their bytes are adjacent in the extracted buffer.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any
from urllib.parse import unquote_to_bytes

from cbor_codec import CBORError, decode_input

FORMATS = {"auto", "hex", "base64", "json", "diagnostic", "text", "binary"}
LABELS = {"hex": "HEX", "base64": "Base64", "json": "JSON", "diagnostic": "Diagnostic", "text": "UTF-8 テキスト", "binary": "バイナリ"}
_WIDTH_TRANSLATION = {i: i - 0xFEE0 for i in range(0xFF01, 0xFF5F)} | {0x3000: 0x20, 0x200B: 0x20, 0xFEFF: 0x20}
_TOKENS = re.compile(r"[^\s,:;_\-]+")
_ADDRESS = re.compile(r"^[ \t]*(?:0[xX])?([\da-fA-F]{4,16})(?::[ \t]*|[ \t]{2,})(.*)$")
_LABEL = re.compile(r"\b(?:payload|data|hex|bytes?|cbor|buffer|rx|tx|recv|received|send|sent)(?:\s*\([^\n)]{0,40}\))?\s*(?::|=|->)\s*", re.I)
_METADATA = re.compile(r"\s+[a-zA-Z_][\w.-]*\s*=")
_FENCE = re.compile(r"^[ \t]*```([\w+-]*)[^\n]*\n([\s\S]*?)^[ \t]*```[ \t]*$", re.M)


def _result(data: bytes, fmt: str, label: str | None = None, *, start: int | None = None,
            end: int | None = None, warnings: list[str] | None = None) -> dict[str, Any]:
    return {"data": data, "format": fmt, "label": label or LABELS[fmt],
            "warnings": warnings or [],
            "segments": [{"start": 0, "end": len(data), "source_start": start, "source_end": end}] if data else []}


def _join(parts: list[dict[str, Any]], fmt: str, label: str, warnings: list[str]) -> dict[str, Any] | None:
    if not parts:
        return None
    raw = bytearray()
    segments: list[dict[str, Any]] = []
    notes = list(warnings)
    for part in parts:
        shift = len(raw)
        raw.extend(part["data"])
        segments.extend({**s, "start": s["start"] + shift, "end": s["end"] + shift} for s in part["segments"])
        notes.extend(part["warnings"])
    return {"data": bytes(raw), "format": fmt, "label": label, "warnings": list(dict.fromkeys(notes)), "segments": segments}


def _trim(text: str, base: int = 0) -> tuple[str, int]:
    prefix = len(text) - len(text.lstrip("\ufeff\u200b \t\r\n"))
    return text[prefix:].rstrip("\ufeff\u200b \t\r\n"), base + prefix


def _text(text: str) -> dict[str, Any]:
    warnings = ["入力形式を確定できないため、元のテキストを UTF-8 バイト列として解析しました"]
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        # JSON transports can carry lone UTF-16 surrogates. Preserve their code
        # units rather than replacing them with '?' or refusing the whole input.
        data = text.encode("utf-8", errors="surrogatepass")
        warnings.append("単独のサロゲートを含むため、そのコード単位をバイト列に保持しました")
    return _result(data, "text", start=0, end=len(text), warnings=warnings)


def _structured(text: str, fmt: str, base: int) -> dict[str, Any] | None:
    try:
        data = decode_input(text, fmt)
    except (CBORError, ValueError, UnicodeError, RecursionError, OverflowError):
        return None
    if not data:
        return None
    return _result(data, fmt, start=base, end=base + len(text))


def _base64(text: str, base: int, *, explicit: bool = False) -> dict[str, Any] | None:
    body, base = _trim(text, base)
    notes: list[str] = []
    marked = False
    uri = re.fullmatch(r"data:[^,\r\n]*;base64\s*,([\s\S]*)", body, re.I)
    if uri:
        base += uri.start(1)
        body = uri[1]
        marked = True
        notes.append("data URI の Base64 本文を抽出しました")
    elif re.match(r"^(?:base64|b64)\s*[:=]", body, re.I):
        match = re.match(r"^(?:base64|b64)\s*[:=]\s*", body, re.I)
        assert match is not None
        base += match.end()
        body = body[match.end():]
        marked = True
    if len(body) >= 2 and body[0] == body[-1] and body[0] in "\"'":
        body, base = body[1:-1], base + 1
    compact = re.sub(r"\s+", "", body)
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        return None
    bare = compact.rstrip("=")
    if len(bare) % 4 == 1:
        return None
    if not explicit and not marked:
        # Do not interpret ordinary short lowercase words as binary just because
        # their letters belong to the Base64 alphabet. Clear binary representations
        # and canonical encoded strings still work without a mode selection.
        evidence = ("=" in compact or bool(re.search(r"[+/_-]", compact)) or
                    bool(re.search(r"[A-Z]", compact)) or
                    (len(compact) >= 8 and bool(re.search(r"\d", compact))))
        if not evidence or len(bare) < 2:
            return None
    try:
        data = base64.b64decode(bare + "=" * (-len(bare) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    # Reject nonzero discarded pad bits. Otherwise almost any three letters can
    # masquerade as a Base64 value and win over the literal-text interpretation.
    canonical = base64.b64encode(data).decode().rstrip("=")
    if canonical != bare.translate(str.maketrans("-_", "+/")):
        return None
    if not data:
        return None
    if len(bare) % 4:
        notes.append("省略された Base64 パディングを補って読み込みました")
    return _result(data, "base64", start=base, end=base + len(body), warnings=notes)


def _byte_literal(text: str, base: int) -> dict[str, Any] | None:
    match = re.fullmatch(r"[bB]([\"'])([\s\S]*)\1", text)
    if not match:
        return None
    body = match[2]
    data = bytearray()
    simple = {"n": 10, "r": 13, "t": 9, "b": 8, "f": 12, "v": 11, "a": 7,
              "\\": 92, "'": 39, '"': 34}
    pos = 0
    while pos < len(body):
        ch = body[pos]
        if ch != "\\":
            if ord(ch) > 127:
                return None
            data.append(ord(ch))
            pos += 1
            continue
        pos += 1
        if pos >= len(body):
            return None
        ch = body[pos]
        if ch in simple:
            data.append(simple[ch])
            pos += 1
        elif ch == "x" and re.fullmatch(r"[\da-fA-F]{2}", body[pos + 1:pos + 3]):
            data.append(int(body[pos + 1:pos + 3], 16))
            pos += 3
        elif ch in "01234567":
            octal = re.match(r"[0-7]{1,3}", body[pos:])
            assert octal is not None
            number = int(octal[0], 8)
            if number > 255:
                return None
            data.append(number)
            pos += len(octal[0])
        else:
            return None
    if not data:
        return None
    return _result(bytes(data), "hex", "バイトリテラル", start=base, end=base + len(text))


def _array(text: str, base: int) -> dict[str, Any] | None:
    """Explicit byte-array wrappers; ordinary JSON arrays keep JSON semantics."""
    typed = re.fullmatch(r"(?:new\s+)?(?:Uint8Array|Int8Array|bytes|bytearray|Buffer\.from)\s*\(\s*\[([\s\S]*)\]\s*\)\s*;?", text)
    declaration = re.fullmatch(r"(?:(?:const|static|unsigned|signed)\s+){0,3}(?:(?:char|byte|uint8_t|int8_t|BYTE)\s+)?[a-zA-Z_]\w*\s*\[\s*\]\s*=\s*\{([\s\S]*)\}\s*;?", text)
    java = re.fullmatch(r"new\s+byte\s*\[\s*\]\s*\{([\s\S]*)\}\s*;?", text)
    bare = re.fullmatch(r"\[([\s\S]*)\]\s*;?", text)
    match = typed or declaration or java
    if not match and bare and re.search(r"(?:0[xX]|\\x|%[\da-fA-F]{2})", bare[1]):
        match = bare
    if not match:
        return None
    body = match[1]
    body_base = base + match.start(1)
    # For real language byte arrays, unprefixed integers are decimal, exactly as
    # written in the source. Mixed 0x/decimal arrays therefore remain faithful.
    tokens = [token.strip() for token in body.split(",") if token.strip()]
    if tokens and all(re.fullmatch(r"(?:0[xX][\da-fA-F]+|[+-]?\d+)", token) for token in tokens):
        values = [int(token, 16 if token.lower().startswith("0x") else 10) for token in tokens]
        if all(0 <= value <= 255 for value in values):
            return _result(bytes(values), "hex", "バイト配列", start=body_base, end=body_base + len(body))
        return None
    parsed = _hex_sequence(body, body_base, force=True)
    if parsed:
        parsed["label"] = "バイト配列"
    return parsed


def _hex_sequence(text: str, base: int, *, force: bool = False, complete: bool = False) -> dict[str, Any] | None:
    """Read hex tokens, keeping a gap between bytes separated by unknown data."""
    data = bytearray()
    segments: list[dict[str, Any]] = []
    run_start = 0
    source_start: int | None = None
    source_end: int | None = None
    invalid = 0
    odd = 0
    valid_tokens = 0

    def flush() -> None:
        nonlocal run_start, source_start, source_end
        if len(data) > run_start:
            segments.append({"start": run_start, "end": len(data), "source_start": source_start, "source_end": source_end})
        run_start = len(data)
        source_start = source_end = None

    def add(hex_value: str, begin: int, end: int) -> None:
        nonlocal source_start, source_end
        if not hex_value:
            return
        if source_start is None:
            source_start = begin
        source_end = end
        data.extend(bytes.fromhex(hex_value))

    def token_value(token: str, begin: int) -> None:
        nonlocal invalid, odd, valid_tokens
        if re.fullmatch(r"(?:\\x[\da-fA-F]{2})+", token):
            add("".join(re.findall(r"\\x([\da-fA-F]{2})", token)), begin, begin + len(token))
            valid_tokens += 1
            return
        if re.fullmatch(r"(?:%[\da-fA-F]{2})+", token):
            add(token.replace("%", ""), begin, begin + len(token))
            valid_tokens += 1
            return
        if re.fullmatch(r"(?:0[xX][\da-fA-F]{2})+", token):
            add(re.sub(r"0[xX]", "", token), begin, begin + len(token))
            valid_tokens += 1
            return
        if token.lower().startswith("0x"):
            token, begin = token[2:], begin + 2
        if re.fullmatch(r"[\da-fA-F]+", token):
            length = len(token) // 2 * 2
            add(token[:length], begin, begin + length)
            if length:
                valid_tokens += 1
            if len(token) % 2:
                odd += 1
                flush()
            return
        # A compact damaged run such as 8201??02 or 82GG01 can be recovered,
        # but a word such as 'garbage' must not contribute its internal 'ba'.
        prefix = re.match(r"[\da-fA-F]{2,}", token)
        if prefix and (re.search(r"\d", prefix[0]) or len(prefix[0]) >= 8):
            pieces = list(re.finditer(r"[\da-fA-F]+|[^\da-fA-F]+", token))
            for piece in pieces:
                if re.fullmatch(r"[\da-fA-F]+", piece[0]):
                    length = len(piece[0]) // 2 * 2
                    add(piece[0][:length], begin + piece.start(), begin + piece.start() + length)
                    if length:
                        valid_tokens += 1
                    if length != len(piece[0]):
                        odd += 1
                        flush()
                else:
                    invalid += 1
                    flush()
            return
        invalid += 1
        flush()

    for match in _TOKENS.finditer(text):
        token_value(match[0], base + match.start())
    flush()
    if not data or complete and (invalid or odd):
        return None
    if not force:
        if invalid and (valid_tokens < 2 or valid_tokens < invalid):
            return None
        if odd and not invalid and valid_tokens == 1 and not re.search(r"\d", text) and not re.search(r"(?:0[xX]|\\x|%)", text):
            return None
    notes: list[str] = []
    if invalid:
        notes.append(f"読み取れない箇所 {invalid} 件を境界として、前後を独立した領域に分けました")
    if odd:
        notes.append(f"奇数桁の HEX {odd} 箇所は末尾の半バイトを補完せず、読み取れたバイトだけを残しました")
    return {"data": bytes(data), "format": "hex", "label": "HEX", "warnings": notes, "segments": segments}


def _hex(text: str, base: int, *, explicit: bool = False, complete: bool = False) -> dict[str, Any] | None:
    body, base = _trim(text, base)
    literal = _byte_literal(body, base)
    if literal:
        return literal
    array = _array(body, base)
    if array:
        return array
    if explicit and body.startswith("h'") and body.endswith("'"):
        body, base = body[2:-1], base + 2
    if len(body) > 2 and body[0] == body[-1] and body[0] in "\"'" and (explicit or "\\x" in body or re.fullmatch(r"(?:%[\da-fA-F]{2})+", body[1:-1])):
        body, base = body[1:-1], base + 1
    # Encoded representations may be copied using fullwidth ASCII or a BOM.
    # Translation is never applied to JSON strings or to the UTF-8 fallback.
    normalized = body.translate(_WIDTH_TRANSLATION)
    parsed = _hex_sequence(normalized, base, force=explicit, complete=complete)
    if parsed and normalized != body:
        parsed["warnings"].insert(0, "全角の英数字・区切りを HEX 表記として読み取りました")
    return parsed


def _dump_column(body: str) -> str:
    if "|" in body:
        return body.split("|", 1)[0].rstrip()
    # xxd/canonical dumps separate the ASCII column by padding. Preserve the
    # two-space grouping inside Wireshark's byte column (after byte eight).
    first = re.match(r"\s*([\da-fA-F]+)(?:\s|$)", body)
    grouped = bool(first and len(first[1]) > 2)
    for gap in re.finditer(r"[ \t]{2,}", body):
        suffix = body[gap.end():].strip()
        if not suffix:
            return body[:gap.start()]
        tokens = suffix.split()
        byte_like = all(re.fullmatch(r"[\da-fA-F]{2}", token) for token in tokens)
        if grouped or not byte_like:
            return body[:gap.start()]
    return body


def _dumps(text: str, base: int) -> dict[str, Any] | None:
    parts: list[dict[str, Any]] = []
    previous_end: int | None = None
    previous_had_gap = False
    cursor = base
    found = False
    discontinuities = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        match = _ADDRESS.match(body)
        if not match:
            if found and body.strip() == "*":
                previous_end = None
                previous_had_gap = True
            cursor += len(line)
            continue
        address = int(match[1], 16)
        prefix = body[:match.start(2)]
        # Double spaces also occur in ordinary hex. Without a colon or an
        # ASCII column, require a conventional zero-padded, aligned address.
        # Otherwise 8201  02 would silently lose its first two payload bytes.
        addressed = (":" in prefix or "|" in match[2] or
                     (len(match[1]) in (4, 8, 16) and match[1].startswith("00") and address % 8 == 0))
        if not addressed:
            cursor += len(line)
            continue
        column = _dump_column(match[2])
        parsed = _hex_sequence(column, cursor + match.start(2), force=True)
        if not parsed:
            cursor += len(line)
            continue
        found = True
        # Avoid treating a whole timestamp/date as a dump address: a byte column
        # must begin with an actual hex token, not with arbitrary prose.
        if not re.match(r"\s*(?:[\da-fA-F]{2}|0[xX][\da-fA-F]{2}|\?\?|\*\*)", column):
            cursor += len(line)
            continue
        if previous_end is not None and address == previous_end and not previous_had_gap and parts:
            previous = parts[-1]
            shift = len(previous["data"])
            previous["data"] += parsed["data"]
            if len(previous["segments"]) and len(parsed["segments"]):
                last = previous["segments"][-1]
                first = parsed["segments"][0]
                last["end"] = shift + first["end"]
                last["source_end"] = first["source_end"]
                previous["segments"].extend({**s, "start": s["start"] + shift, "end": s["end"] + shift} for s in parsed["segments"][1:])
            previous["warnings"].extend(parsed["warnings"])
        else:
            if parts:
                discontinuities += 1
            parsed["segments"][0]["address"] = address
            parts.append(parsed)
        previous_had_gap = bool(parsed["warnings"])
        # With unknown bytes, the extracted byte count no longer proves the
        # next source address is adjacent. Do not infer a repaired address.
        previous_end = address + len(parsed["data"]) if not previous_had_gap else None
        cursor += len(line)
    if not parts:
        return None
    notes = ["ダンプのオフセット列・ASCII 列を除いてバイト列を抽出しました"]
    if discontinuities:
        notes.append("ダンプのオフセットが連続しない箇所は別領域として解析します")
    return _join(parts, "hex", "HEX ダンプ", notes)


def _logs(text: str, base: int) -> dict[str, Any] | None:
    parts: list[dict[str, Any]] = []
    cursor = base
    kinds: list[str] = []
    for line in text.splitlines(keepends=True):
        matches = list(_LABEL.finditer(line))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
            body = line[match.end():end]
            metadata = _METADATA.search(body)
            if metadata:
                body = body[:metadata.start()]
            body, body_base = _trim(body, cursor + match.end())
            if not body:
                continue
            parsed = _recognize(body, body_base, contextual=True)
            if parsed:
                parts.append(parsed)
                kinds.append(parsed["format"])
        cursor += len(line)
    if not parts:
        return None
    fmt = kinds[0] if all(kind == kinds[0] for kind in kinds) else "hex"
    return _join(parts, fmt, "ログ内の " + (LABELS[fmt] if len(set(kinds)) == 1 else "バイト列"),
                 ["ログのデータ欄を抽出しました。各レコードは独立した領域として解析します"])


def _recognize(text: str, base: int, *, contextual: bool = False) -> dict[str, Any] | None:
    body, base = _trim(text, base)
    if not body:
        return None
    if body.lower().startswith("data:") or re.match(r"^(?:base64|b64)\s*[:=]", body, re.I):
        value = _base64(body, base)
        if value:
            return value
        uri = re.fullmatch(r"data:[^,\r\n]*,([\s\S]*)", body, re.I)
        if uri and re.fullmatch(r"(?:%[\da-fA-F]{2})+", uri[1]):
            return _result(unquote_to_bytes(uri[1]), "hex", "data URI", start=base + uri.start(1), end=base + len(body))
    literal = _byte_literal(body, base) or _array(body, base)
    if literal:
        return literal
    # Containers and quoted values carry clear semantic intent. A JSON string
    # containing hex remains a CBOR text value, not an implicit byte buffer.
    structured = body[0] in "[{\"" or body in ("true", "false", "null")
    if structured:
        value = _structured(body, "json", base) or _structured(body, "diagnostic", base)
        if value:
            return value
        # Malformed containers must not leak their property names into a hex
        # extractor. Preserve them as text unless an explicit byte array matched.
        return None
    if re.match(r"^(?:h'|b64'|simple\s*\(|\(_|undefined\b|NaN\b|-?Infinity\b|\d+\s*\(|-?\d+[._])", body):
        value = _structured(body, "diagnostic", base)
        if value:
            return value
    if not contextual and _LABEL.search(body):
        return None
    value = _dumps(body, base)
    if value:
        return value
    value = _hex(body, base, complete=True)
    if value:
        return value
    # A single decimal digit is a complete JSON value, not a complete hex byte.
    # Comma-separated values also have an unambiguous Diagnostic interpretation.
    if re.fullmatch(r"-?\d", body) or re.search(r"[,.]", body) or re.fullmatch(r"-?\d+(?:[eE][+-]?\d+)", body):
        value = _structured(body, "json", base) or _structured(body, "diagnostic", base)
        if value:
            return value
    # Byte-sized tokens separated by whitespace are stronger evidence than
    # a coincidental Base64 decoding after all whitespace has been stripped.
    # In particular, do not turn 82 01 ZZ 02 into unrelated Base64 bytes.
    if re.search(r"[\s,:;]", body):
        value = _hex(body, base)
        if value:
            return value
    value = _base64(body, base)
    if value:
        return value
    # Recover valid hex fragments only with byte-like evidence. Unknown words
    # are never globally stripped down to their letters A-F.
    return _hex(body, base, explicit=contextual)


def parse_input(text: str, preferred: str = "auto") -> dict[str, Any]:
    """Accept a nonempty input and return its recognized bytes and provenance.

    A selected format is tried first, then the same automatic recognition used
    by the default mode. Failed syntax is never repaired by inventing bytes.
    When nothing establishes an encoded representation, retain literal UTF-8.
    """
    if not isinstance(text, str):
        raise CBORError("入力は文字列で指定してください")
    if not isinstance(preferred, str) or preferred not in FORMATS:
        raise CBORError("入力形式が不正です")
    if not text:
        raise CBORError("入力データが空です")
    if preferred == "text":
        result = _text(text)
        result["warnings"] = result["warnings"][1:]
        return result
    # Mask terminal control sequences with spaces so original character
    # positions remain accurate. The literal-text fallback still uses text.
    prepared = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", lambda m: " " * len(m[0]), text)
    body, base = _trim(prepared)
    result: dict[str, Any] | None = None
    if preferred in ("json", "diagnostic"):
        result = _structured(body, preferred, base)
    elif preferred == "base64":
        result = _base64(body, base, explicit=True)
    elif preferred in ("hex", "binary"):
        result = _dumps(body, base) if preferred == "hex" else None
        result = result or _hex(body, base, explicit=True, complete=True)
        if result and preferred == "binary":
            result["format"], result["label"] = "binary", LABELS["binary"]
    if result:
        return result

    # Entire code fences retain their language hint without requiring the user
    # to remove Markdown. Multiple blocks are intentionally separate fragments.
    fenced: list[dict[str, Any]] = []
    for match in _FENCE.finditer(prepared):
        language, content = match[1].lower(), match[2]
        hint = {"json": "json", "diag": "diagnostic", "diagnostic": "diagnostic", "cbor": "diagnostic", "hex": "hex", "hexdump": "hex", "base64": "base64", "b64": "base64"}.get(language)
        inner, inner_base = _trim(content, match.start(2))
        value = None
        if hint in ("json", "diagnostic"):
            value = _structured(inner, hint, inner_base)
        elif hint == "base64":
            value = _base64(inner, inner_base, explicit=True)
        elif hint == "hex":
            value = _dumps(inner, inner_base) or _hex(inner, inner_base, explicit=True)
        value = value or _recognize(inner, inner_base) or _logs(inner, inner_base)
        if value:
            fenced.append(value)
    if fenced:
        fmt = fenced[0]["format"]
        result = _join(fenced, fmt, "コードブロック内の " + LABELS[fmt], ["コードブロックの本文を抽出しました"])
    if result is None:
        result = _recognize(body, base)
    if result is None:
        result = _logs(body, base)
    if result is None and preferred == "hex":
        result = _hex(body, base, explicit=True)
    if result is None:
        result = _text(text)
    if preferred != "auto" and result["format"] != preferred:
        result["warnings"].insert(0, f"指定された {LABELS[preferred]} と一致しないため、{result['label']} として読み込みました")
    return result
