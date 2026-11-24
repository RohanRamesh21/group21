"""npm registry intelligence: provenance verification (stretch goal 3) and advanced package risk (stretch goal 4).

Deterministic, no LLM. Runs in Guardian's own process and talks only to hosts in guardian.yaml `registries.fetch_hosts`
(registry.npmjs.org for packuments, signing keys, attestations and tarballs). Package code is downloaded and READ
(in memory, never extracted to disk, never run). Responses are cached for a day under .cache/npm-meta.

Which packages: in a PR comparison, every npm package version that is new in the head lockfile; in a full scan,
the direct dependencies (at most MAX_FULL_SCAN). Findings (all cite the package and the registry fact):

  Provenance (D24)
    signature_invalid           registry signature does not verify for name@version:integrity          critical, hard
    lockfile_integrity_mismatch lockfile integrity differs from the registry's for the same version     critical, hard
    registry_version_missing    lockfile says registry.npmjs.org, but the registry has no such version critical, hard
    provenance_mismatch         SLSA provenance subject digest differs from the lockfile integrity     critical, hard
    provenance_dropped          the previous release had a provenance attestation, this one has none  high
  Package behaviour and history (D20-D23)
    publisher_change            published by a different npm account than the previous release        medium
    maintainer_change           maintainer list changed since the previous release                    low
    unusual_release             published < 72 h ago, or after > 1 year of silence, or in a burst      medium
    young_package               the package itself is < 30 days old                                    medium
    suspicious_install_behavior install script reads secrets, downloads, spawns processes or is obfuscated  high
    dependency_confusion        internal-scope name resolved from the public registry (policy internal_scopes)  critical, hard
"""
from __future__ import annotations

import base64
import concurrent.futures as cf
import hashlib
import io
import json
import re
import tarfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "npm-meta"
NPM = "https://registry.npmjs.org"
TTL = 24 * 3600
MAX_FULL_SCAN = 80
MAX_TARBALL = 20 * 1024 * 1024
LIFECYCLE = ("preinstall", "install", "postinstall")
# install-script patterns: (regex, why). Matched on the script command and the JS files it runs.
BEHAVIOUR = [
    # secret-looking variables or the whole environment; plain configuration variables (ESBUILD_BINARY_PATH) do not count
    (re.compile(r"process\.env\.\w*(?:TOKEN|SECRET|PASSWORD|PASSWD|_KEY|CREDENTIAL|AUTH)\w*|(?:JSON\.stringify|Object\.(?:keys|entries))\(\s*process\.env"
                r"|\.npmrc|\.ssh/|id_rsa|\.aws/credentials|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET", re.I), "reads secrets or credentials"),
    (re.compile(r"\b(curl|wget)\b|https?\.(get|request)\(|\bfetch\(|net\.connect|dns\.(lookup|resolve)|XMLHttpRequest"
                r"|require\(\s*['\"](?:https?|net|dns|tls|dgram|axios|node-fetch|got|request)['\"]\s*\)", re.I), "makes network requests"),
    (re.compile(r"child_process|\bexecSync\b|\bspawnSync?\b|\bexec\(", re.I), "starts other programs"),
    (re.compile(r"\beval\(|new Function\(|Buffer\.from\([^)]{40,},\s*['\"]base64|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}", re.I), "runs obfuscated or generated code"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}|\.onion\b|discord(?:app)?\.com/api/webhooks|pastebin\.com|ngrok", re.I), "contacts a raw IP or a data-drop service"),
]


class Fetcher:
    """HTTP GET restricted to the policy's fetch hosts, with a small on-disk cache."""

    def __init__(self, allowed_hosts: set[str]):
        import requests
        self.allowed = allowed_hosts
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "guardian-supply-chain-scanner"
        self.errors: list[str] = []

    def get_json(self, url: str, ttl: int = TTL) -> dict | None:
        host = urlparse(url).netloc
        if host not in self.allowed:
            raise PermissionError(f"{host} is not in registries.fetch_hosts")
        key = CACHE / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")
        if key.exists() and time.time() - key.stat().st_mtime < ttl:
            return json.loads(key.read_text())
        r = self.http.get(url, timeout=30)
        if r.status_code == 404:
            data = {"__missing__": True}
        else:
            r.raise_for_status()
            data = r.json()
        CACHE.mkdir(parents=True, exist_ok=True)
        key.write_text(json.dumps(data))
        return data

    def get_bytes(self, url: str, limit: int = MAX_TARBALL) -> bytes:
        host = urlparse(url).netloc
        if host not in self.allowed:
            raise PermissionError(f"{host} is not in registries.fetch_hosts")
        r = self.http.get(url, timeout=60, stream=True)
        r.raise_for_status()
        buf = io.BytesIO()
        for chunk in r.iter_content(1 << 16):
            buf.write(chunk)
            if buf.tell() > limit:
                raise ValueError(f"tarball larger than {limit // 1_000_000} MB")
        return buf.getvalue()


def _ts(s: str | None) -> float | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None
    except ValueError:
        return None


def _integrity_hex(integrity: str | None) -> str | None:
    if not integrity or not integrity.startswith("sha512-"):
        return None
    return base64.b64decode(integrity[7:]).hex()


def npm_keys(f: Fetcher) -> dict:
    doc = f.get_json(f"{NPM}/-/npm/v1/keys") or {}
    return {k["keyid"]: k for k in doc.get("keys", [])}


def verify_signature(name: str, version: str, integrity: str, sigs: list[dict], keys: dict) -> str:
    """npm registry signature over '<name>@<version>:<integrity>' (ECDSA P-256 / SHA-256). valid|invalid|unsigned|unknown_key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if not sigs:
        return "unsigned"
    msg = f"{name}@{version}:{integrity}".encode()
    for s in sigs:
        k = keys.get(s.get("keyid"))
        if not k:
            continue
        pub = serialization.load_der_public_key(base64.b64decode(k["key"]))
        try:
            pub.verify(base64.b64decode(s["sig"]), msg, ec.ECDSA(hashes.SHA256()))
            return "valid"
        except InvalidSignature:
            return "invalid"
    return "unknown_key"


def attestation(f: Fetcher, url: str, integrity_hex: str | None) -> dict:
    """SLSA provenance from the registry's attestation bundle: source repo, workflow, builder, digest match.
    The Sigstore certificate chain is NOT verified here (see docs/KNOWN_LIMITATIONS.md)."""
    doc = f.get_json(url) or {}
    out = {"present": False}
    for a in doc.get("attestations", []):
        if "slsa.dev/provenance" not in a.get("predicateType", ""):
            continue
        env = (a.get("bundle") or {}).get("dsseEnvelope") or {}
        try:
            stmt = json.loads(base64.b64decode(env.get("payload", "")))
        except ValueError:
            continue
        pred = stmt.get("predicate") or {}
        wf = ((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}
        digests = [s.get("digest", {}).get("sha512") for s in stmt.get("subject", [])]
        out = {"present": True, "source": wf.get("repository"), "workflow": wf.get("path"), "ref": wf.get("ref"),
               "builder": ((pred.get("runDetails") or {}).get("builder") or {}).get("id"),
               "digest_match": (integrity_hex in digests) if integrity_hex else None}
        break
    return out


def inspect_install_script(f: Fetcher, tarball_url: str, scripts: dict) -> list[dict]:
    """Read the lifecycle scripts and the JS files they run from the tarball (in memory) and match risky behaviour."""
    texts = {f"package.json scripts.{k}": v for k, v in scripts.items() if k in LIFECYCLE}
    wanted = {m.group(1).removeprefix("./") for v in texts.values() for m in re.finditer(r"node\s+([\w./-]+\.(?:c?js|mjs))", v)}
    if wanted:
        with tarfile.open(fileobj=io.BytesIO(f.get_bytes(tarball_url)), mode="r:gz") as tar:
            for m in tar.getmembers():
                rel = m.name.split("/", 1)[-1]
                if m.isfile() and rel in wanted and m.size < 2_000_000:
                    texts[rel] = tar.extractfile(m).read().decode(errors="replace")
    hits = []
    for where, text in texts.items():
        for rx, why in BEHAVIOUR:
            mm = rx.search(text)
            if mm:
                line = text.count("\n", 0, mm.start()) + 1
                snippet = text.splitlines()[line - 1].strip()[:160] if text else ""
                hits.append({"why": why, "file": where, "line": line, "snippet": snippet})
    return hits


def _prev_version(doc: dict, version: str) -> str | None:
    times = {v: _ts(t) for v, t in (doc.get("time") or {}).items() if v not in ("created", "modified")}
    mine = times.get(version)
    if mine is None:
        return None
    earlier = [(t, v) for v, t in times.items() if t is not None and t < mine and v in (doc.get("versions") or {})]
    return max(earlier)[1] if earlier else None


def check_package(f: Fetcher, keys: dict, name: str, version: str, integrity: str | None, resolved: str | None,
                  install_script: bool, policy: dict, now: float) -> tuple[list[dict], dict]:
    """All registry checks for one npm package version. Returns (findings, provenance row)."""
    finds: list[dict] = []
    row = {"name": name, "version": version, "signature": "not_checked", "provenance": None, "publisher": None,
           "published": None, "source": None}
    host = urlparse(resolved or "").netloc

    def add(t, sev, summary, hard=False, detector="D24"):
        finds.append({"detector": detector, "type": t, "severity": sev, "hard_signal": hard, "component": f"{name}@{version}",
                      "file": None, "line": None, "summary": summary})

    scopes = [s.rstrip("/") for s in (policy.get("internal_scopes") or [])]
    if scopes and any(name.startswith(s + "/") for s in scopes) and host == "registry.npmjs.org":
        add("dependency_confusion", "critical", f"{name} is in an internal scope ({', '.join(scopes)}) but was resolved from the "
            "public registry: a public package with this name replaced the internal one", hard=True, detector="D23")
    if host != "registry.npmjs.org":
        row["signature"] = "not_applicable"
        row["note"] = f"resolved from {host or 'a non-registry source'}: npm registry signatures do not apply"
        return finds, row

    doc = f.get_json(f"{NPM}/{quote(name, safe='@')}")
    if not doc or doc.get("__missing__") or version not in (doc.get("versions") or {}):
        row["signature"] = "missing"
        add("registry_version_missing", "critical", f"the lockfile says {name}@{version} comes from registry.npmjs.org, but the registry "
            "has no such version: the lockfile entry cannot be verified (forged, or removed by npm, e.g. as malware)", hard=True)
        return finds, row
    meta = doc["versions"][version]
    dist = meta.get("dist") or {}
    row["publisher"] = (meta.get("_npmUser") or {}).get("name")
    row["published"] = (doc.get("time") or {}).get(version)

    # ---- provenance
    if integrity and dist.get("integrity") and integrity != dist["integrity"]:
        add("lockfile_integrity_mismatch", "critical", f"the lockfile integrity for {name}@{version} differs from the registry's: the "
            "lockfile points at a different tarball than the one npm published", hard=True)
    sig = verify_signature(name, version, dist.get("integrity") or integrity or "", dist.get("signatures") or [], keys)
    row["signature"] = sig
    if sig == "invalid":
        add("signature_invalid", "critical", f"the npm registry signature for {name}@{version} does not verify", hard=True)
    ihex = _integrity_hex(dist.get("integrity") or integrity)
    if (dist.get("attestations") or {}).get("url"):
        prov = attestation(f, dist["attestations"]["url"], ihex)
        row["provenance"] = prov
        row["source"] = prov.get("source")
        if prov.get("present") and prov.get("digest_match") is False:
            add("provenance_mismatch", "critical", f"the SLSA provenance for {name}@{version} is for a different tarball than the "
                "one in the lockfile", hard=True)
    prev = _prev_version(doc, version)
    pmeta = (doc.get("versions") or {}).get(prev) or {} if prev else {}
    if prev and (pmeta.get("dist") or {}).get("attestations") and not dist.get("attestations"):
        add("provenance_dropped", "high", f"{name}@{prev} was published with build provenance (built by CI from its source repo); "
            f"{version} has none: it may have been published by hand, e.g. with a stolen token")

    # ---- history
    pub, ppub = row["publisher"], (pmeta.get("_npmUser") or {}).get("name")
    if prev and pub and ppub and pub != ppub:
        add("publisher_change", "medium", f"{name}@{version} was published by npm user '{pub}'; the previous release {prev} by "
            f"'{ppub}'", detector="D20")
    m_now = sorted(x.get("name", "") for x in meta.get("maintainers") or [])
    m_prev = sorted(x.get("name", "") for x in pmeta.get("maintainers") or [])
    if prev and m_prev and m_now != m_prev:
        added = sorted(set(m_now) - set(m_prev))
        add("maintainer_change", "low", f"maintainers changed since {prev}" + (f": added {', '.join(added)}" if added else ""), detector="D20")
    t_ver, t_prev, t_created = _ts(row["published"]), _ts((doc.get("time") or {}).get(prev)) if prev else None, _ts((doc.get("time") or {}).get("created"))
    day = 86400
    if t_ver and now - t_ver < 3 * day:
        add("unusual_release", "medium", f"{name}@{version} was published {round((now - t_ver) / 3600)} h ago: most malicious releases "
            "are found and removed within days, so very new versions deserve a wait or a review", detector="D21")
    elif t_ver and t_prev and t_ver - t_prev > 365 * day:
        add("unusual_release", "medium", f"{name}@{version} came out after {round((t_ver - t_prev) / day)} days without a release "
            f"(previous: {prev}): dormant packages are a common takeover target", detector="D21")
    if t_ver:
        burst = [v for v, t in (doc.get("time") or {}).items()  # stable versions only: canary/nightly builds are routine
                 if v not in ("created", "modified") and "-" not in v and (tt := _ts(t)) and abs(tt - t_ver) < day]
        if len(burst) >= 5:
            add("unusual_release", "medium", f"{len(burst)} versions of {name} were published within a day of {version}", detector="D21")
    if t_created and now - t_created < 30 * day:
        add("young_package", "medium", f"the package {name} was created {round((now - t_created) / day)} days ago", detector="D21")

    # ---- install script behaviour
    scripts = {k: v for k, v in (meta.get("scripts") or {}).items() if k in LIFECYCLE}
    allow = set((policy.get("install_scripts") or {}).get("allowlist") or [])
    if scripts and dist.get("tarball") and name not in allow:  # allow-listed: approved by a human (guardian.yaml)
        hits = inspect_install_script(f, dist["tarball"], scripts)
        row["install_script"] = {"scripts": scripts, "behaviour": hits}
        if hits:
            add("suspicious_install_behavior", "high", f"{name}@{version} runs code at install time that "
                + "; ".join(sorted({h['why'] for h in hits})) + f" (e.g. {hits[0]['file']}:{hits[0]['line']}: {hits[0]['snippet'][:90]})",
                detector="D22")
    return finds, row


def analyse(base: dict, head: dict, compare: bool, policy: dict, log=lambda m: None) -> tuple[list[dict], dict]:
    """Registry checks for the npm packages this change adds (PR mode) or the direct dependencies (full scan).
    Returns (findings, summary). Findings carry `changed` = True when the package version is new in this change."""
    allowed = set((policy.get("registries") or {}).get("fetch_hosts") or [])
    rows = [p for p in head["inventory"] if p.get("found_by") == "guardian npm lockfile parser" and p.get("version")]
    if compare:
        before = {(p["name"], p["version"]) for p in base["inventory"]}
        todo = {(p["name"], p["version"]): p for p in rows if (p["name"], p["version"]) not in before}
    else:
        todo = {(p["name"], p["version"]): p for p in rows if p.get("direct")}
        todo = dict(list(todo.items())[:MAX_FULL_SCAN])
    summary = {"checked": 0, "scope": "new in this change" if compare else f"direct dependencies (max {MAX_FULL_SCAN})",
               "signed": 0, "attested": 0, "packages": [], "errors": []}
    if not todo:
        return [], summary
    log(f"Checking {len(todo)} npm package(s) on the registry: signatures, provenance, publishers, release history, install scripts")
    f = Fetcher(allowed)
    try:
        keys = npm_keys(f)
    except Exception as e:  # noqa: BLE001 registry unreachable: report, never guess
        summary["errors"].append(f"npm signing keys unavailable: {type(e).__name__}: {str(e)[:120]}")
        return [], summary
    now = time.time()
    findings: list[dict] = []

    def one(p):
        try:
            return check_package(f, keys, p["name"], p["version"], p.get("integrity"), p.get("resolved"), p.get("has_install_script"),
                                 policy, now)
        except Exception as e:  # noqa: BLE001
            return [], {"name": p["name"], "version": p["version"], "signature": "not_checked",
                        "error": f"{type(e).__name__}: {str(e)[:120]}"}
    with cf.ThreadPoolExecutor(8) as ex:
        for (finds, row), p in zip(ex.map(one, todo.values()), todo.values()):
            summary["packages"].append(row)
            for x in finds:
                findings.append({**x, "file": p.get("source_file"), "line": p.get("lockfile_line"), "changed": compare})
    pk = summary["packages"]
    summary.update(checked=len(pk), signed=sum(1 for r in pk if r.get("signature") == "valid"),
                   attested=sum(1 for r in pk if (r.get("provenance") or {}).get("present")),
                   errors=[f"{r['name']}@{r['version']}: {r['error']}" for r in pk if r.get("error")])
    return findings, summary
