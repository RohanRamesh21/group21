from guardian.inventory.ci_image import parse_dockerfile, parse_workflow

WF = """
name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: tj-actions/changed-files@v46
      - uses: ./local-action
  reuse:
    uses: org/shared/.github/workflows/build.yml@main
"""

DF = """
ARG BASE_IMAGE=louislam/uptime-kuma:base2-slim
FROM louislam/uptime-kuma:builder-go AS build_healthcheck
FROM node:22@sha256:abc123 AS build
FROM $BASE_IMAGE AS release
FROM release AS rootless
"""


def test_workflow_pinning_and_first_party():
    acts = parse_workflow(".github/workflows/ci.yml", WF)
    by = {a.owner_repo: a for a in acts}
    assert by["actions/checkout"].pinned_sha and by["actions/checkout"].first_party
    assert by["actions/checkout"].version_comment == "v7.0.1"
    assert not by["tj-actions/changed-files"].pinned_sha and not by["tj-actions/changed-files"].first_party
    assert by["org/shared"].ref == "main"
    assert all(not a.uses.startswith("./") for a in acts)


def test_dockerfile_args_stages_and_digests():
    imgs = parse_dockerfile("docker/dockerfile", DF)
    refs = {i.ref: i for i in imgs}
    assert refs["louislam/uptime-kuma:builder-go"].tag == "builder-go"
    assert refs["louislam/uptime-kuma:builder-go"].digest is None
    assert refs["node:22@sha256:abc123"].digest == "sha256:abc123"
    assert refs["node:22@sha256:abc123"].repository == "library/node"
    assert "louislam/uptime-kuma:base2-slim" in refs  # ARG default substituted
    assert "release" not in refs  # internal stage, not an external image
