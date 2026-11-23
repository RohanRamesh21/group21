"""Unified supply-chain graph (stage S3): application, packages, image, workflows.

Node ids:
  app                       the application root
  pkg:<lockfile key>        one installed package
  img:<ref>                 a container base image
  wf:<path>                 a workflow file
  act:<owner/repo@ref>      a CI action reference
"""
from __future__ import annotations

import networkx as nx

from guardian.models import Edge, ImageRef, Package, WorkflowAction

APP = "app"


def pkg_node(key: str) -> str:
    return f"pkg:{key}"


def build_graph(
    packages: dict[str, Package],
    edges: list[Edge],
    actions: list[WorkflowAction] | None = None,
    images: list[ImageRef] | None = None,
    app_name: str = "app",
    commit: str = "",
) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(APP, type="Application", name=app_name, commit=commit)

    for p in packages.values():
        g.add_node(pkg_node(p.key), type="Package", **p.model_dump())
    for e in edges:
        src = APP if e.parent == "" else pkg_node(e.parent)
        g.add_edge(src, pkg_node(e.child), type="DEPENDS_ON", kind=e.kind, spec=e.spec, name=e.name)

    for a in actions or []:
        wf = f"wf:{a.workflow}"
        if wf not in g:
            g.add_node(wf, type="Workflow", file=a.workflow)
            g.add_edge(APP, wf, type="HAS_WORKFLOW")
        act = f"act:{a.owner_repo}@{a.ref}"
        if act not in g:
            g.add_node(act, type="Action", **a.model_dump(exclude={"workflow", "job", "line"}))
        g.add_edge(wf, act, type="USES", job=a.job, line=a.line)

    for im in images or []:
        node = f"img:{im.ref}"
        if node not in g:
            g.add_node(node, type="BaseImage", **im.model_dump(exclude={"line", "stage"}))
        g.add_edge(APP, node, type="BUILT_FROM", stage=im.stage, dockerfile=im.dockerfile, line=im.line)

    return g


def export_graphml(g: nx.DiGraph, path: str) -> None:
    """GraphML only allows scalar attributes; drop None values and stringify the rest."""
    h = nx.DiGraph()
    for n, d in g.nodes(data=True):
        h.add_node(n, **{k: (v if isinstance(v, (bool, int, float, str)) else str(v)) for k, v in d.items() if v is not None})
    for u, v, d in g.edges(data=True):
        h.add_edge(u, v, **{k: (x if isinstance(x, (bool, int, float, str)) else str(x)) for k, x in d.items() if x is not None})
    nx.write_graphml(h, path)
