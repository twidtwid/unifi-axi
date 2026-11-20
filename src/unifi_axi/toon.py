"""TOON output (the subset used here) and the same data as JSON.

A Doc is an ordered list of blocks: `key: value` lines, `name[N]:` lists,
`name[N]{cols}:` tables, and nested groups. Commands build one Doc; cli.main
prints it once, as TOON (default) or JSON (--json). Errors are Doc lines too.
"""

from __future__ import annotations

import json
import re
from typing import Any

_NUMERIC = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$|^0\d+$")
_NEEDS_QUOTE = set(':,"\\[]{}#\n\r\t')


def toon_scalar(value: Any) -> str:
    """One TOON primitive. Strings are quoted when the TOON spec (section 7.2)
    requires it: empty, padded, a literal (true/false/null), numeric-looking,
    a leading '-', or containing a colon, quote, backslash, bracket, brace,
    delimiter or control character."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if (text == "" or text != text.strip() or text in ("true", "false", "null")
            or _NUMERIC.match(text) or text.startswith("-")
            or any(c in _NEEDS_QUOTE for c in text)):
        return '"' + (text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
                      .replace("\r", "\\r").replace("\t", "\\t")) + '"'
    return text


class Doc:
    """Ordered output blocks: key/value lines and tables."""

    def __init__(self, fields: list[str] | None = None):
        self.blocks: list[tuple] = []
        self.fields = fields or []
        self.fields_used: set[str] = set()
        self.fields_seen: set[str] = set()

    def kv(self, key: str, text: str) -> None:
        self.blocks.append(("kv", key, text))

    def table(self, name: str, cols: list[str], rows: list[dict]) -> None:
        extra = [f for f in self.fields if f not in cols and any(f in r for r in rows)]
        self.fields_used.update(f for f in self.fields if f in cols or f in extra)
        for r in rows:
            self.fields_seen.update(r)
        self.blocks.append(("table", name, cols + extra, rows))

    def items(self, name: str, values: list[str]) -> None:
        self.blocks.append(("list", name, values))

    def group(self, name: str, sub: Doc) -> None:
        """A nested doc (one AP of `verify --all`). TOON prints its lines inline;
        JSON gives every group of the same name as one list of objects."""
        self.blocks.append(("group", name, sub))

    def unknown_fields(self) -> list[str]:
        """--fields names that matched no column of any table in this doc."""
        sub = [b[2] for b in self.blocks if b[0] == "group"]
        used = self.fields_used.union(*(d.fields_used for d in sub))
        return [f for f in self.fields if f not in used]

    def available_fields(self) -> list[str]:
        sub = [b[2] for b in self.blocks if b[0] == "group"]
        return sorted(self.fields_seen.union(*(d.fields_seen for d in sub)))

    def toon(self) -> str:
        lines = []
        groups: dict[str, list[Doc]] = {}
        for block in self.blocks:
            if block[0] == "group":
                groups.setdefault(block[1], []).append(block[2])
        repeated_kv: dict[str, list[str]] = {}
        for block in self.blocks:
            if block[0] == "kv":
                repeated_kv.setdefault(block[1], []).append(block[2])
        repeated_kv = {k: v for k, v in repeated_kv.items() if len(v) > 1}
        done: set[str] = set()
        for block in self.blocks:
            if block[0] == "kv" and block[1] in repeated_kv:
                # a key printed twice (two warn: lines) becomes one list; TOON forbids duplicate keys
                if block[1] not in done:
                    done.add(block[1])
                    values = repeated_kv[block[1]]
                    lines.append(f"{block[1]}[{len(values)}]:")
                    lines.extend(f"  - {toon_scalar(v)}" for v in values)
                continue
            if block[0] == "group":
                # every group of one name is one TOON list of objects, at its first position
                name = block[1]
                if name in done:
                    continue
                done.add(name)
                lines.append(f"{name}[{len(groups[name])}]:")
                for sub in groups[name]:
                    sub_lines = sub.toon().rstrip("\n").split("\n")
                    lines.append("  - " + sub_lines[0])
                    lines.extend("    " + ln for ln in sub_lines[1:])
            elif block[0] == "kv":
                lines.append(f"{block[1]}: {toon_scalar(block[2])}")
            elif block[0] == "list":
                lines.append(f"{block[1]}[{len(block[2])}]:")
                lines.extend(f"  - {toon_scalar(v)}" for v in block[2])
            else:
                _, name, cols, rows = block
                lines.append(f"{name}[{len(rows)}]{{{','.join(cols)}}}:")
                for r in rows:
                    lines.append("  " + ",".join(toon_scalar(r.get(c)) for c in cols))
        return "\n".join(lines) + "\n"

    def obj(self) -> dict[str, Any]:
        """A repeated name never overwrites: groups always collect into a list,
        and any other name seen twice becomes a list of its values."""
        out: dict[str, Any] = {}
        repeated: set[str] = set()
        for block in self.blocks:
            name = block[1]
            if block[0] == "group":
                out.setdefault(name, []).append(block[2].obj())
                continue
            if block[0] in ("kv", "list"):
                value = block[2]
            else:
                _, _, cols, rows = block
                value = [{c: r.get(c) for c in cols} for r in rows]
            if name in out:
                if name not in repeated:
                    out[name], repeated = [out[name]], repeated | {name}
                out[name].append(value)
            else:
                out[name] = value
        return out

    def json(self) -> str:
        return json.dumps(self.obj(), indent=1) + "\n"
