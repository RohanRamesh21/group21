"""One-time sandbox setup (`guardian sandbox setup`): pull the digest-pinned images, then fetch the Grype DB.

This is the only step that downloads tools. Scans themselves never pull (`--pull=never`). The Grype database
is downloaded by Guardian on the host from the official listing, its sha256 is checked against the listing, and
it is imported by Grype inside a container with no network.
"""
from __future__ import annotations

import hashlib
import json
import subprocess

from guardian import sandbox

GRYPE_LISTING = "https://grype.anchore.io/databases/v6/latest.json"
GRYPE_DIR = sandbox.ROOT / ".cache" / "grype"


def pull_images(log=print) -> dict[str, str]:
    """Pull every image in guardian.yaml by digest. Returns key -> 'ok' or the error."""
    out = {}
    for key, ref in sandbox.config()["images"].items():
        if "@sha256:" not in ref:
            out[key] = "refused: not pinned by digest"
            continue
        r = subprocess.run(["podman", "pull", "-q", ref], capture_output=True, text=True, timeout=900)
        out[key] = "ok" if r.returncode == 0 else f"pull failed: {r.stderr.strip()[-200:]}"
        log(f"{key:12} {out[key]}  ({ref})")
    return out


def update_grype_db(log=print) -> dict:
    """Download the current Grype DB (checksum-verified) and import it offline into .cache/grype."""
    import requests

    listing = requests.get(GRYPE_LISTING, timeout=30)
    listing.raise_for_status()
    meta = listing.json()
    algo, digest = meta["checksum"].split(":", 1)
    if algo != "sha256":
        raise RuntimeError(f"unexpected checksum type {algo}")
    GRYPE_DIR.mkdir(parents=True, exist_ok=True)
    archive = GRYPE_DIR / f"grype-db-{digest[:16]}.tar.zst"  # listing names contain ':', kept out of local paths
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        log(f"downloading {meta['path']} (built {meta['built']})")
        h, tmp = hashlib.sha256(), archive.with_suffix(".part")
        with requests.get(GRYPE_LISTING.rsplit("/", 1)[0] + "/" + meta["path"], stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    h.update(chunk)
                    f.write(chunk)
        if h.hexdigest() != digest:
            tmp.unlink()
            raise RuntimeError("Grype DB checksum mismatch: download discarded")
        tmp.rename(archive)
    for old in [*GRYPE_DIR.glob("grype-db-*.tar.zst"), *GRYPE_DIR.glob("vulnerability-db_*.tar.zst")]:
        if old != archive:
            old.unlink()
    # the archive is mounted under its own extension: grype picks the decompressor from the file name
    res = sandbox.run("grype", ["db", "import", "{db.tar.zst}"], inputs={"db.tar.zst": archive}, output=GRYPE_DIR / "db",
                      env={"GRYPE_DB_CACHE_DIR": "{out}", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}, timeout=600)
    if not res.ok:
        raise RuntimeError(res.error or res.stderr[-300:])
    info = {"schema": meta["schemaVersion"], "built": meta["built"], "archive": archive.name, "sha256": digest}
    (GRYPE_DIR / "guardian-db.json").write_text(json.dumps(info, indent=1))
    log(f"grype DB ready: schema {info['schema']}, built {info['built']}")
    return info


def setup(log=print) -> dict:
    images = pull_images(log)
    try:
        db = update_grype_db(log)
    except Exception as e:  # report, keep going: Grype is a second opinion next to OSV
        db = {"error": f"{type(e).__name__}: {e}"[:300]}
        log(f"grype DB not updated: {db['error']}")
    return {"images": images, "grype_db": db, "status": sandbox.status()}
