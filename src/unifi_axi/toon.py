"""TOON output (the subset used here) and the same data as JSON.

A Doc is an ordered list of blocks: `key: value` lines, `name[N]:` lists,
`name[N]{cols}:` tables, and nested groups. Commands build one Doc; cli.main
prints it once, as TOON (default) or JSON (--json). Errors are Doc lines too.
"""

from __future__ import annotations

import json
from typing import Any


def toon_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    if text and not any(c in text for c in ',"\n\r\t') and text == text.strip():
        return text
    if text == "":
        return ""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


class Doc:
    """Ordered output blocks: key/value lines and tables."""

    def __init__(self, fields: list[str] | None = None):
        self.blocks: list[tuple] = []
        self.fields = fields or []

    def kv(self, key: str, text: str) -> None:
        self.blocks.append(("kv", key, text))

    def table(self, name: str, cols: list[str], rows: list[dict]) -> None:
        extra = [f for f in self.fields if f not in cols and any(f in r for r in rows)]
        self.blocks.append(("table", name, cols + extra, rows))

    def items(self, name: str, values: list[str]) -> None:
        self.blocks.append(("list", name, values))

    def group(self, name: str, sub: Doc) -> None:
        """A nested doc (one AP of `verify --all`). TOON prints its lines inline;
        JSON gives every group of the same name as one list of objects."""
        self.blocks.append(("group", name, sub))

    def toon(self) -> str:
        lines = []
        for block in self.blocks:
            if block[0] == "group":
                lines.append(block[2].toon().rstrip("\n"))
            elif block[0] == "kv":
                lines.append(f"{block[1]}: {block[2]}")
            elif block[0] == "list":
                lines.append(f"{block[1]}[{len(block[2])}]:")
                lines.extend(f"  {v}" for v in block[2])
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
