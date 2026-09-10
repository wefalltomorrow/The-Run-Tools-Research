#!/usr/bin/env python3
"""Catalog the contents of *new* Frostbite 2 bundles in the X360 Italian Pack.

This only reads bundle metadata (EBX names, RES names/types, chunk GUIDs and sizes).
It does not extract or publish game payloads. Delta/base bundles are intentionally
skipped because reconstructing them requires the matching Xbox 360 base game.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import zipfile

TARGET_TERMS = [
    "alf_8c_com", "lam_dia_sv", "lam_gal_spl", "lan_del_int",
    "mas_gtm_str", "mas_mc12", "pag_zon_r", "italian", "italy",
    "ital_", "_ita_", "challenge",
]


def db_to_plain(obj):
    if obj is None:
        return None
    if hasattr(obj, "elems"):
        return {k: db_to_plain(v) for k, v in obj.elems.items()}
    if hasattr(obj, "content"):
        c = obj.content
        if isinstance(c, list):
            return [db_to_plain(x) for x in c]
        if isinstance(c, (bytes, bytearray)):
            return c.hex()
        if hasattr(c, "format") and callable(c.format):
            try:
                return c.format()
            except Exception:
                pass
        if isinstance(c, (str, int, float, bool)) or c is None:
            return c
        return repr(c)
    return repr(obj)


def status(entry):
    if entry.get("base"):
        return "base"
    if entry.get("delta"):
        return "delta"
    return "new"


def is_interesting(text: str) -> bool:
    t = text.lower()
    return any(term in t for term in TARGET_TERMS)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("zip_path")
    ap.add_argument("--frostbite-scripts", required=True)
    ap.add_argument("--out-dir", default="analysis-output")
    args = ap.parse_args()

    zip_path = Path(args.zip_path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fb2 = Path(args.frostbite_scripts) / "frostbite2"
    sys.path.insert(0, str(fb2))
    import dbo  # type: ignore
    import noncas  # type: ignore

    result = {
        "archive": str(zip_path),
        "toc_files": {},
        "totals": {"new_bundles": 0, "parsed_new_bundles": 0, "errors": 0},
    }

    with zipfile.ZipFile(zip_path, "r") as zf, tempfile.TemporaryDirectory() as td:
        names = set(zf.namelist())
        td_path = Path(td)

        for toc_index, toc_name in enumerate(sorted(n for n in names if n.lower().endswith(".toc"))):
            toc_tmp = td_path / f"toc_{toc_index:03d}.bin"
            toc_tmp.write_bytes(zf.read(toc_name))
            try:
                toc = db_to_plain(dbo.readToc(str(toc_tmp)))
            except Exception as exc:
                result["toc_files"][toc_name] = {"toc_error": f"{type(exc).__name__}: {exc}"}
                result["totals"]["errors"] += 1
                continue

            bundles = toc.get("bundles") if isinstance(toc, dict) else None
            if not isinstance(bundles, list):
                continue
            new_entries = [e for e in bundles if isinstance(e, dict) and status(e) == "new"]
            if not new_entries:
                continue

            sb_name = toc_name[:-3] + "sb"
            toc_result = {
                "new_bundle_count": len(new_entries),
                "sb": sb_name,
                "bundles": [],
            }
            result["toc_files"][toc_name] = toc_result
            result["totals"]["new_bundles"] += len(new_entries)

            if sb_name not in names:
                toc_result["sb_error"] = "matching .sb not found in archive"
                result["totals"]["errors"] += len(new_entries)
                continue

            sb_tmp = td_path / f"sb_{toc_index:03d}.bin"
            with zf.open(sb_name, "r") as src, sb_tmp.open("wb") as dst:
                while True:
                    block = src.read(4 * 1024 * 1024)
                    if not block:
                        break
                    dst.write(block)

            with sb_tmp.open("rb") as sb:
                for entry in new_entries:
                    bundle_id = str(entry.get("id") or "")
                    item = {
                        "id": bundle_id,
                        "offset": entry.get("offset"),
                        "size": entry.get("size"),
                        "interesting": is_interesting(bundle_id),
                    }
                    try:
                        offset = entry.get("offset")
                        if not isinstance(offset, int):
                            raise ValueError("new bundle has no integer offset")
                        sb.seek(offset)
                        bundle = noncas.Bundle(sb)
                        item["ebx"] = [
                            {"name": e.name, "size": e.size, "originalSize": e.originalSize}
                            for e in bundle.ebxEntries
                        ]
                        item["res"] = [
                            {"name": e.name, "resType": f"0x{e.resType:08X}", "size": e.size, "originalSize": e.originalSize}
                            for e in bundle.resEntries
                        ]
                        item["chunks"] = [
                            {"id": e.id.format(), "size": e.size}
                            for e in bundle.chunkEntries
                        ]
                        item["interesting"] = item["interesting"] or any(
                            is_interesting(x["name"]) for x in item["ebx"] + item["res"]
                        )
                        result["totals"]["parsed_new_bundles"] += 1
                    except Exception as exc:
                        item["error"] = f"{type(exc).__name__}: {exc}"
                        result["totals"]["errors"] += 1
                    toc_result["bundles"].append(item)

    json_path = out_dir / "italian-pack-new-bundle-catalog.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "NFS The Run - Xbox 360 Italian Pack NEW bundle catalog",
        "=" * 68,
        "Only TOC entries that are neither base nor delta are catalogued.",
        f"New bundles: {result['totals']['new_bundles']}",
        f"Successfully parsed: {result['totals']['parsed_new_bundles']}",
        f"Errors: {result['totals']['errors']}",
        "",
        "Interesting Italian/content bundles and their asset names:",
    ]

    found = 0
    for toc_name, toc in result["toc_files"].items():
        if not isinstance(toc, dict):
            continue
        selected = [b for b in toc.get("bundles", []) if b.get("interesting")]
        if not selected:
            continue
        lines.append(f"\n[{toc_name}]")
        for b in selected:
            found += 1
            lines.append(f"  BUNDLE {b.get('id')}")
            if b.get("error"):
                lines.append(f"    ERROR {b['error']}")
                continue
            for e in b.get("ebx", []):
                lines.append(f"    EBX   {e['name']}")
            for e in b.get("res", []):
                lines.append(f"    RES   {e['name']} ({e['resType']})")
            for e in b.get("chunks", []):
                lines.append(f"    CHUNK {e['id']} size={e['size']}")

    if not found:
        lines.append("  none matched target terms")

    lines += ["", "All new bundle IDs by TOC:"]
    for toc_name, toc in result["toc_files"].items():
        if not isinstance(toc, dict) or not toc.get("bundles"):
            continue
        lines.append(f"\n[{toc_name}]")
        for b in toc["bundles"]:
            marker = "*" if b.get("interesting") else " "
            lines.append(f" {marker} {b.get('id')}")

    txt = "\n".join(lines) + "\n"
    (out_dir / "italian-pack-new-bundle-catalog.txt").write_text(txt, encoding="utf-8")
    print(txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
