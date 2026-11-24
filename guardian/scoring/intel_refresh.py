"""Nightly advisory-data refresh (launchd, 02:00 IST): Grype DB, OSV offline export for npm, CISA KEV.

Runs before the GitHub nightly re-check (02:30 IST), so that re-check uses fresh data even if GitHub delays its schedule.
A new OSV archive replaces the old one only after it downloaded completely and passed a zip integrity test.
Usage: python -m guardian.scoring.intel_refresh
"""
from __future__ import annotations

import shutil
import subprocess
import time
import zipfile
from pathlib import Path

import requests

from guardian.scoring.intel import OSV_ZIP, kev

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"


def refresh_osv(dest: Path = OSV_ZIP, url: str = OSV_URL, http=requests) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(".zip.part")
    with http.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(part, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    try:
        with zipfile.ZipFile(part) as z:
            if z.testzip() is not None:
                raise zipfile.BadZipFile("corrupt member")
    except zipfile.BadZipFile as e:
        part.unlink(missing_ok=True)
        return f"kept previous OSV archive ({e})"
    shutil.move(part, dest)
    return f"OSV npm archive updated ({dest.stat().st_size // 1_000_000} MB)"


def main() -> int:
    stamp = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # noqa: E731
    print(f"[{stamp()}] intel refresh start", flush=True)
    g = subprocess.run(["grype", "db", "update"], capture_output=True, text=True)
    print("grype:", (g.stdout or g.stderr).strip().splitlines()[-1:] or ["(no output)"], flush=True)
    try:
        print(refresh_osv(), flush=True)
    except Exception as e:  # network trouble: keep yesterday's data and say so
        print(f"OSV refresh failed, previous archive kept: {type(e).__name__}: {e}", flush=True)
    d, err = kev(max_age=0)
    print(f"KEV entries: {len(d)} {err or ''}", flush=True)
    print(f"[{stamp()}] intel refresh done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
