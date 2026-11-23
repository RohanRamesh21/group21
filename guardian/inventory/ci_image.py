"""Parse GitHub Actions workflows and Dockerfiles into components (stage S2)."""
from __future__ import annotations

import re

import yaml

from guardian.models import ImageRef, WorkflowAction

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY_OWNERS = {"actions", "github"}


def _line_and_comment(text: str, uses: str, occurrence: int = 0) -> tuple[int | None, str | None]:
    """Line of the `occurrence`-th (0-based) `uses:` line with this exact value, and its version comment.
    Repeated actions (e.g. actions/checkout in every job) each get their own line."""
    seen = 0
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)", line)
        if m and m.group(1) == uses:
            if seen == occurrence:
                c = re.search(r"#\s*(\S+)", line.split(uses, 1)[1])
                return i, (c.group(1) if c else None)
            seen += 1
    return None, None


def parse_workflow(path: str, text: str) -> list[WorkflowAction]:
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    out: list[WorkflowAction] = []
    occurrences: dict[str, int] = {}
    jobs = doc.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        uses_list = []
        if isinstance(job.get("uses"), str):  # reusable workflow
            uses_list.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                uses_list.append(step["uses"])
        for uses in uses_list:
            if uses.startswith("./") or uses.startswith("docker://"):
                continue  # local action, or an image (handled as an image reference elsewhere)
            if "@" not in uses:
                continue
            target, ref = uses.rsplit("@", 1)
            owner_repo = "/".join(target.split("/")[:2])
            line, comment = _line_and_comment(text, uses, occurrences.get(uses, 0))
            occurrences[uses] = occurrences.get(uses, 0) + 1
            out.append(WorkflowAction(
                workflow=path, job=str(job_name), uses=uses, owner_repo=owner_repo, ref=ref,
                pinned_sha=bool(SHA_RE.match(ref)),
                first_party=owner_repo.split("/")[0].lower() in FIRST_PARTY_OWNERS,
                version_comment=comment, line=line,
            ))
    return out


def _split_image(ref: str) -> tuple[str, str, str | None, str | None]:
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", ref if "/" in ref else f"library/{ref}"
    return registry, repo, tag, digest


def parse_dockerfile(path: str, text: str) -> list[ImageRef]:
    args: dict[str, str] = {}
    stages: set[str] = set()
    out: list[ImageRef] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.upper().startswith("ARG "):
            m = re.match(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?", line, re.I)
            if m and m.group(2):
                args[m.group(1)] = m.group(2).strip().strip('"')
        if not line.upper().startswith("FROM "):
            continue
        tokens = [t for t in line.split()[1:] if not t.startswith("--")]
        if not tokens:
            continue
        ref = tokens[0]
        stage = tokens[2] if len(tokens) >= 3 and tokens[1].upper() == "AS" else None
        ref = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: args.get(m.group(1), m.group(0)), ref)
        if stage:
            stages.add(stage)
        if ref in stages or ref.lower() == "scratch" or "$" in ref:
            if "$" in ref:  # unresolved build argument: still record it, it can't be pinned statically
                out.append(ImageRef(dockerfile=path, stage=stage, ref=ref, registry="unknown",
                                    repository=ref, tag=None, digest=None, line=i))
            continue
        registry, repo, tag, digest = _split_image(ref)
        out.append(ImageRef(dockerfile=path, stage=stage, ref=ref, registry=registry,
                            repository=repo, tag=tag, digest=digest, line=i))
    return out
