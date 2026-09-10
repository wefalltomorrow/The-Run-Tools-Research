#!/usr/bin/env python3
"""Metadata-only analysis of the unpacked Xbox 360 Italian Pack archive.

This script deliberately emits no copyrighted game payloads. It inventories the ZIP,
checks Frostbite/X360 magic values, searches for a small set of research strings, and
parses .toc metadata with NicknineTheEagle/Frostbite-Scripts when available.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile

TARGET_TERMS = [
    "italian",
    "nfs12itapack0000",
    "lamborghini",
    "diablo",
    "gallardo",
    "pagani",
    "zonda",
    "maserati",
    "mc12",
    "granturismo",
    "lancia",
    "delta",
    "alfa",
    "competizione",
    "challenge",
    "unlock",
    "unlocker",
    "promo",
    "dlc",
    "entitlement",
    "license",
    "marketplace",
]

X360_LZX_MAGIC = b"\x0f\xf5\x12\xed"


def human_size(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    value = float(n)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{n} B"


def iter_search_patterns():
    for term in TARGET_TERMS:
        yield term, term.encode("ascii", "ignore"), "ascii"
        yield term, term.encode("utf-16le"), "utf16le"
        yield term, term.encode("utf-16be"), "utf16be"


def search_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, max_hits_per_member: int = 80):
    patterns = [(term, needle.lower(), enc) for term, needle, enc in iter_search_patterns() if needle]
    hits = []
    overlap = max((len(p[1]) for p in patterns), default=1) - 1
    absolute = 0
    tail = b""

    with zf.open(info, "r") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            data = tail + block
            lowered = data.lower()
            base = absolute - len(tail)
            for term, needle, enc in patterns:
                start = 0
                while len(hits) < max_hits_per_member:
                    pos = lowered.find(needle, start)
                    if pos < 0:
                        break
                    hits.append({"term": term, "encoding": enc, "offset": base + pos})
                    start = pos + max(1, len(needle))
                if len(hits) >= max_hits_per_member:
                    break
            if len(hits) >= max_hits_per_member:
                break
            absolute += len(block)
            tail = data[-overlap:] if overlap > 0 else b""

    return hits


def db_to_plain(obj):
    """Best-effort conversion of Frostbite dbo.DbObject values into JSON-safe data."""
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
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return repr(obj)


def summarize_toc(plain):
    if not isinstance(plain, dict):
        return {"root_type": type(plain).__name__}

    summary = {
        "keys": sorted(plain.keys()),
        "cas": plain.get("cas"),
        "alwaysEmitSuperbundle": plain.get("alwaysEmitSuperbundle"),
    }
    bundles = plain.get("bundles") or []
    chunks = plain.get("chunks") or []
    summary["bundle_count"] = len(bundles) if isinstance(bundles, list) else None
    summary["chunk_count"] = len(chunks) if isinstance(chunks, list) else None

    if isinstance(bundles, list):
        compact = []
        delta_count = 0
        base_count = 0
        for entry in bundles:
            if not isinstance(entry, dict):
                continue
            if entry.get("delta"):
                delta_count += 1
            if entry.get("base"):
                base_count += 1
            compact.append({k: entry.get(k) for k in ("id", "offset", "size", "delta", "base") if k in entry})
        summary["delta_bundle_count"] = delta_count
        summary["base_bundle_count"] = base_count
        summary["sample_bundles"] = compact[:12]

    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("zip_path")
    ap.add_argument("--frostbite-scripts", default="")
    ap.add_argument("--out-dir", default="analysis-output")
    args = ap.parse_args()

    zip_path = Path(args.zip_path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not zip_path.is_file():
        raise SystemExit(f"ZIP not found: {zip_path}")

    dbo = None
    if args.frostbite_scripts:
        fb2 = Path(args.frostbite_scripts) / "frostbite2"
        if fb2.is_dir():
            sys.path.insert(0, str(fb2))
            try:
                import dbo as dbo_module  # type: ignore
                dbo = dbo_module
            except Exception as exc:
                print(f"Warning: could not import Frostbite dbo parser: {exc}")

    report = {
        "archive": str(zip_path),
        "archive_size": zip_path.stat().st_size,
        "archive_sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "extension_counts": {},
        "largest_files": [],
        "x360_lzx_members": [],
        "string_hits": {},
        "toc_summaries": {},
        "toc_errors": {},
    }

    lines = []
    lines.append("NFS The Run - Xbox 360 Italian Pack metadata analysis")
    lines.append("=" * 64)
    lines.append(f"Archive: {zip_path.name}")
    lines.append(f"Archive size: {human_size(report['archive_size'])} ({report['archive_size']} bytes)")
    lines.append(f"Archive SHA-256: {report['archive_sha256']}")
    lines.append("")

    with zipfile.ZipFile(zip_path, "r") as zf:
        files = [i for i in zf.infolist() if not i.is_dir()]
        report["file_count"] = len(files)
        report["uncompressed_total"] = sum(i.file_size for i in files)
        report["compressed_total"] = sum(i.compress_size for i in files)

        ext_counts = collections.Counter((Path(i.filename).suffix.lower() or "<none>") for i in files)
        report["extension_counts"] = dict(ext_counts.most_common())
        largest = sorted(files, key=lambda i: i.file_size, reverse=True)[:25]
        report["largest_files"] = [
            {"path": i.filename, "size": i.file_size, "compressed_size": i.compress_size}
            for i in largest
        ]

        lines.append(f"Files: {len(files)}")
        lines.append(f"Uncompressed payload: {human_size(report['uncompressed_total'])}")
        lines.append(f"ZIP-compressed payload: {human_size(report['compressed_total'])}")
        lines.append("")
        lines.append("Extension counts:")
        for ext, count in ext_counts.most_common():
            lines.append(f"  {ext:10s} {count}")
        lines.append("")
        lines.append("Largest files:")
        for i in largest:
            lines.append(f"  {human_size(i.file_size):>12s}  {i.filename}")

        # Header/magic scan and targeted string search.
        for info in files:
            try:
                with zf.open(info, "r") as fh:
                    header = fh.read(32)
            except Exception:
                continue
            if header.startswith(X360_LZX_MAGIC):
                report["x360_lzx_members"].append(info.filename)

            # Search all reasonably sized files plus the main superbundles. The search
            # is streamed, so large files do not need to be held in memory.
            try:
                hits = search_member(zf, info)
            except Exception as exc:
                hits = [{"error": str(exc)}]
            if hits:
                report["string_hits"][info.filename] = hits

        lines.append("")
        lines.append("X360 LZX-compressed members (magic 0F F5 12 ED):")
        if report["x360_lzx_members"]:
            for name in report["x360_lzx_members"]:
                lines.append(f"  {name}")
        else:
            lines.append("  none detected")

        # Parse .toc metadata with Frostbite-Scripts. TOCs are small, so extracting
        # them temporarily is cheap and keeps the report metadata-only.
        toc_infos = [i for i in files if i.filename.lower().endswith(".toc")]
        if dbo:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                for info in toc_infos:
                    local = td_path / Path(info.filename).name
                    try:
                        with zf.open(info, "r") as src, local.open("wb") as dst:
                            dst.write(src.read())
                        parsed = dbo.readToc(str(local))
                        plain = db_to_plain(parsed)
                        report["toc_summaries"][info.filename] = summarize_toc(plain)
                    except Exception as exc:
                        report["toc_errors"][info.filename] = f"{type(exc).__name__}: {exc}"
        else:
            report["toc_errors"]["<parser>"] = "Frostbite dbo parser unavailable"

    lines.append("")
    lines.append("TOC metadata summaries:")
    for path in sorted(report["toc_summaries"]):
        s = report["toc_summaries"][path]
        lines.append(
            f"  {path}: bundles={s.get('bundle_count')} chunks={s.get('chunk_count')} "
            f"delta={s.get('delta_bundle_count')} base={s.get('base_bundle_count')} cas={s.get('cas')}"
        )
        samples = s.get("sample_bundles") or []
        for sample in samples[:4]:
            lines.append(f"      {sample}")

    if report["toc_errors"]:
        lines.append("")
        lines.append("TOC parse errors:")
        for path, err in sorted(report["toc_errors"].items()):
            lines.append(f"  {path}: {err}")

    lines.append("")
    lines.append("Targeted string hits:")
    if report["string_hits"]:
        for path in sorted(report["string_hits"]):
            hits = report["string_hits"][path]
            if hits and "error" in hits[0]:
                lines.append(f"  {path}: ERROR {hits[0]['error']}")
                continue
            compact = ", ".join(
                f"{h['term']}[{h['encoding']}]@0x{h['offset']:X}" for h in hits[:24]
            )
            suffix = " ..." if len(hits) > 24 else ""
            lines.append(f"  {path}: {compact}{suffix}")
    else:
        lines.append("  no targeted strings found in raw stored members")

    (out_dir / "italian-pack-analysis.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "italian-pack-analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n".join(lines[:80]))
    print(f"\nWrote {out_dir / 'italian-pack-analysis.txt'}")
    print(f"Wrote {out_dir / 'italian-pack-analysis.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
