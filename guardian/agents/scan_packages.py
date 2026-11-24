"""Bounded package evidence from the deterministic scan of the selected commits."""
from __future__ import annotations


def package_changes(base: list[dict], head: list[dict]) -> list[dict]:
    """Compare installed versions by ecosystem and package name."""
    def versions(rows):
        result = {}
        for row in rows:
            if not row.get("first_party"):
                key = row.get("ecosystem") or "unknown", row["name"]
                result.setdefault(key, set()).add(row.get("version") or row.get("declared") or "?")
        return result

    before, after = versions(base), versions(head)
    changes = []
    for ecosystem, name in sorted(before.keys() | after.keys()):
        key = ecosystem, name
        old, new = before.get(key, set()), after.get(key, set())
        if old != new:
            changes.append({"ecosystem": ecosystem, "name": name, "change": "updated" if old and new else "added" if new else "removed",
                            "before": sorted(old), "after": sorted(new)})
    return changes


def _fields(row: dict, keys: tuple[str, ...]) -> dict:
    return {key: row[key][:180] if isinstance(row[key], str) else row[key] for key in keys if row.get(key) is not None}


def inventory(report: dict, ecosystem: str, query: str, offset: int) -> dict:
    query = query.casefold()
    rows = [row for row in report.get("inventory", []) if (not ecosystem or ecosystem == row.get("ecosystem"))
            and (not query or any(query in str(row.get(key, "")).casefold() for key in ("name", "purl", "key")))]
    rows.sort(key=lambda row: (not row.get("direct"), row.get("name", ""), row.get("version") or "", row.get("key", "")))
    return {"total": len(rows), "offset": offset, "next_offset": offset + 4 if offset + 4 < len(rows) else None,
            "packages": [_fields(row, ("ecosystem", "name", "version", "purl", "key", "source_file",
                                       "lockfile_line", "direct", "runtime", "found_by")) for row in rows[offset:offset + 4]]}


def advisories(report: dict, ecosystem: str, name: str, version: str, offset: int) -> dict:
    inventory_rows = [p for p in report.get("inventory", []) if p.get("ecosystem") == ecosystem and p.get("name") == name
                      and (not version or p.get("version") == version)]
    component_keys = {p["key"] for p in inventory_rows}
    rows = [v for v in report.get("vulnerabilities", []) if v.get("name") == name and (not version or v.get("version") == version)
            and (v.get("ecosystem") == ecosystem or (not v.get("ecosystem") and v.get("component_key") in component_keys))]
    rows.sort(key=lambda row: (row.get("label") != "introduced", row.get("id", ""), row.get("key", "")))
    return {"ecosystem": ecosystem, "name": name[:180], "version": version[:100], "installed_instances": len(inventory_rows),
            "total": len(rows), "offset": offset, "next_offset": offset + 4 if offset + 4 < len(rows) else None,
            "scanner_errors": sorted(report["headline"].get("vulnerabilities", {}).get("errors") or {}),
            "advisories": [{**_fields(row, ("id", "label", "severity", "version", "component_key", "malicious")),
                            "fixed_versions": [str(fix)[:80] for fix in (row.get("fixed") or [])[:4]],
                            "sources": [str(source)[:40] for source in (row.get("sources") or [])[:4]],
                            "reachability": (row.get("reachability") or {}).get("status")} for row in rows[offset:offset + 4]]}


def changes(report: dict, ecosystem: str, offset: int) -> dict:
    if report["headline"].get("base_commit_full") == report["headline"].get("head_commit_full"):
        return {"comparison": "single_snapshot", "changes": []}
    if "package_changes_qualified" not in report:
        return {"comparison": "legacy_report", "changes": [], "note": "Rescan to get changes identified by ecosystem."}
    rows = [row for row in report["package_changes_qualified"] if not ecosystem or row["ecosystem"] == ecosystem]
    return {"comparison": "base_to_head", "total": len(rows), "offset": offset, "next_offset": offset + 5 if offset + 5 < len(rows) else None,
            "changes": [{**_fields(row, ("ecosystem", "name", "change")),
                         "before": [v[:80] for v in row["before"][:5]], "after": [v[:80] for v in row["after"][:5]],
                         "version_counts": [len(row["before"]), len(row["after"])]} for row in rows[offset:offset + 5]]}
