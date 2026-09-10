#!/usr/bin/env python3
"""Metadata-only analysis of the unpacked Xbox 360 Italian Pack archive.

No game payload is emitted. The report inventories the archive, parses Frostbite 2
TOCs, classifies bundle entries as base/delta/new, and highlights Italian Pack
vehicle/content identifiers useful for a PC port.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

RAW_TERMS = [
    "italian", "italy", "nfs12itapack0000", "lamborghini", "diablo",
    "gallardo", "pagani", "zonda", "maserati", "mc12", "granturismo",
    "lancia", "delta", "alfa", "competizione", "challenge", "unlock",
    "unlocker", "promo", "dlc", "entitlement", "license", "marketplace",
]

# Known/obvious Frostbite vehicle abbreviations seen in the Italian Pack TOCs.
BUNDLE_TERMS = [
    "alf_8c_com", "lam_dia_sv", "lam_gal_spl", "lan_del_int",
    "mas_gtm_str", "mas_mc12", "pag_zon_r",
    "italian", "italy", "ital_", "_ita_", "itapack", "challenge",
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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(4 * 1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def iter_search_patterns():
    for term in RAW_TERMS:
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


def compact_bundle(entry):
    return {k: entry.get(k) for k in ("id", "offset", "size", "delta", "base") if k in entry}


def bundle_status(entry) -> str:
    if entry.get("base"):
        return "base"
    if entry.get("delta"):
        return "delta"
    return "new"


def summarize_toc(plain):
    if not isinstance(plain, dict):
        return {"root_type": type(plain).__name__}

    bundles = plain.get("bundles") or []
    chunks = plain.get("chunks") or []
    summary = {
        "keys": sorted(plain.keys()),
        "cas": plain.get("cas"),
        "alwaysEmitSuperbundle": plain.get("alwaysEmitSuperbundle"),
        "bundle_count": len(bundles) if isinstance(bundles, list) else None,
        "chunk_count": len(chunks) if isinstance(chunks, list) else None,
    }

    if not isinstance(bundles, list):
        return summary

    counts = collections.Counter()
    new_entries = []
    target_entries = []
    for entry in bundles:
        if not isinstance(entry, dict):
            continue
        status = bundle_status(entry)
        counts[status] += 1
        item = compact_bundle(entry)
        item["status"] = status
        bundle_id = str(entry.get("id") or "").lower()
        if status == "new" and len(new_entries) < 250:
            new_entries.append(item)
        if bundle_id and any(term in bundle_id for term in BUNDLE_TERMS):
            target_entries.append(item)

    summary["base_bundle_count"] = counts["base"]
    summary["delta_bundle_count"] = counts["delta"]
    summary["new_bundle_count"] = counts["new"]
    summary["new_bundles"] = new_entries
    summary["target_bundles"] = target_entries
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
        "archive_sha256": sha256_file(zip_path),
        "extension_counts": {}, "largest_files": [], "x360_lzx_members": [],
        "string_hits": {}, "toc_summaries": {}, "toc_errors": {},
    }
    lines = [
        "NFS The Run - Xbox 360 Italian Pack metadata analysis",
        "=" * 64,
        f"Archive: {zip_path.name}",
        f"Archive size: {human_size(report['archive_size'])} ({report['archive_size']} bytes)",
        f"Archive SHA-256: {report['archive_sha256']}", "",
    ]

    with zipfile.ZipFile(zip_path, "r") as zf:
        files = [i for i in zf.infolist() if not i.is_dir()]
        report["file_count"] = len(files)
        report["uncompressed_total"] = sum(i.file_size for i in files)
        report["compressed_total"] = sum(i.compress_size for i in files)
        ext_counts = collections.Counter((Path(i.filename).suffix.lower() or "<none>") for i in files)
        report["extension_counts"] = dict(ext_counts.most_common())
        largest = sorted(files, key=lambda i: i.file_size, reverse=True)[:25]
        report["largest_files"] = [
            {"path": i.filename, "size": i.file_size, "compressed_size": i.compress_size} for i in largest
        ]

        lines += [
            f"Files: {len(files)}",
            f"Uncompressed payload: {human_size(report['uncompressed_total'])}",
            f"ZIP-compressed payload: {human_size(report['compressed_total'])}", "",
            "Extension counts:",
        ]
        for ext, count in ext_counts.most_common():
            lines.append(f"  {ext:10s} {count}")
        lines += ["", "Largest files:"]
        for i in largest:
            lines.append(f"  {human_size(i.file_size):>12s}  {i.filename}")

        for info in files:
            try:
                with zf.open(info, "r") as fh:
                    header = fh.read(32)
                if header.startswith(X360_LZX_MAGIC):
                    report["x360_lzx_members"].append(info.filename)
                hits = search_member(zf, info)
                if hits:
                    report["string_hits"][info.filename] = hits
            except Exception as exc:
                report["string_hits"][info.filename] = [{"error": str(exc)}]

        lines += ["", "X360 LZX-compressed members (magic 0F F5 12 ED):"]
        if report["x360_lzx_members"]:
            lines.extend(f"  {name}" for name in report["x360_lzx_members"])
        else:
            lines.append("  none detected (the supplied SB files appear already container-decompressed)")

        toc_infos = [i for i in files if i.filename.lower().endswith(".toc")]
        if dbo:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                for idx, info in enumerate(toc_infos):
                    local = td_path / f"{idx:03d}_{Path(info.filename).name}"
                    try:
                        with zf.open(info, "r") as src, local.open("wb") as dst:
                            dst.write(src.read())
                        report["toc_summaries"][info.filename] = summarize_toc(db_to_plain(dbo.readToc(str(local))))
                    except Exception as exc:
                        report["toc_errors"][info.filename] = f"{type(exc).__name__}: {exc}"
        else:
            report["toc_errors"]["<parser>"] = "Frostbite dbo parser unavailable"

    lines += ["", "TOC metadata summaries:"]
    global_counts = collections.Counter()
    for path in sorted(report["toc_summaries"]):
        s = report["toc_summaries"][path]
        base = s.get("base_bundle_count") or 0
        delta = s.get("delta_bundle_count") or 0
        new = s.get("new_bundle_count") or 0
        global_counts.update({"base": base, "delta": delta, "new": new})
        lines.append(
            f"  {path}: bundles={s.get('bundle_count')} chunks={s.get('chunk_count')} "
            f"new={new} delta={delta} base={base} cas={s.get('cas')}"
        )

    lines += [
        "",
        "Bundle classification totals across parsed TOCs:",
        f"  new={global_counts['new']} delta={global_counts['delta']} base={global_counts['base']}",
        "",
        "Italian/target bundle IDs:",
    ]
    any_target = False
    for path in sorted(report["toc_summaries"]):
        targets = report["toc_summaries"][path].get("target_bundles") or []
        if not targets:
            continue
        any_target = True
        lines.append(f"  [{path}]")
        for item in targets:
            lines.append(f"    {item.get('status'):5s}  {item.get('id')}")
    if not any_target:
        lines.append("  none")

    lines += ["", "New bundle IDs (neither base nor delta; capped at 250 per TOC):"]
    for path in sorted(report["toc_summaries"]):
        items = report["toc_summaries"][path].get("new_bundles") or []
        if not items:
            continue
        lines.append(f"  [{path}] count={report['toc_summaries'][path].get('new_bundle_count')}")
        for item in items:
            lines.append(f"    {item.get('id')}")

    if report["toc_errors"]:
        lines += ["", "TOC parse errors:"]
        for path, err in sorted(report["toc_errors"].items()):
            lines.append(f"  {path}: {err}")

    lines += ["", "Targeted raw-string hits:"]
    if report["string_hits"]:
        for path in sorted(report["string_hits"]):
            hits = report["string_hits"][path]
            if hits and "error" in hits[0]:
                lines.append(f"  {path}: ERROR {hits[0]['error']}")
                continue
            compact = ", ".join(f"{h['term']}[{h['encoding']}]@0x{h['offset']:X}" for h in hits[:24])
            lines.append(f"  {path}: {compact}{' ...' if len(hits) > 24 else ''}")
    else:
        lines.append("  no targeted strings found in raw stored members")

    txt = "\n".join(lines) + "\n"
    (out_dir / "italian-pack-analysis.txt").write_text(txt, encoding="utf-8")
    (out_dir / "italian-pack-analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
