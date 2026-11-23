"""Read-only graph tools (FINAL_PLAN.md §7.2). Exact structural answers for the pipeline and agents."""
from __future__ import annotations

from itertools import islice

import networkx as nx

from guardian.graph.builder import APP, pkg_node


class GraphTools:
    def __init__(self, g: nx.DiGraph):
        self.g = g
        self._by_purl: dict[str, list[str]] = {}
        for n, d in g.nodes(data=True):
            if d.get("type") == "Package":
                self._by_purl.setdefault(d["purl"], []).append(n)

    # --- lookups -------------------------------------------------------------
    def nodes_for(self, purl_or_key: str) -> list[str]:
        if purl_or_key.startswith("pkg:npm/") or purl_or_key.startswith("pkg:"):
            if purl_or_key in self._by_purl:
                return self._by_purl[purl_or_key]
            node = purl_or_key if purl_or_key in self.g else pkg_node(purl_or_key)
            return [node] if node in self.g else []
        node = pkg_node(purl_or_key)
        return [node] if node in self.g else []

    def label(self, node: str) -> str:
        d = self.g.nodes[node]
        if d.get("type") == "Package":
            return f"{d['name']}@{d['version']}"
        if node == APP:
            return d.get("name", "app")
        return node

    # --- graph questions -----------------------------------------------------
    def paths_to_root(self, purl_or_key: str, limit: int = 5) -> list[list[str]]:
        """Up to `limit` shortest dependency paths from the application to the package (labels)."""
        out: list[list[str]] = []
        for node in self.nodes_for(purl_or_key):
            try:
                for path in islice(nx.shortest_simple_paths(self.g, APP, node), limit):
                    out.append([self.label(n) for n in path])
            except nx.NetworkXNoPath:
                continue
        return out[:limit]

    def direct_parents_to_upgrade(self, purl_or_key: str) -> list[str]:
        """The direct dependencies through which the package is pulled in (first hop after the app)."""
        targets = set(self.nodes_for(purl_or_key))
        firsts = []
        for direct in self.g.successors(APP):
            if self.g.nodes[direct].get("type") != "Package":
                continue
            if direct in targets or targets & nx.descendants(self.g, direct):
                firsts.append(self.label(direct))
        return sorted(firsts)

    def who_depends_on(self, purl_or_key: str) -> list[str]:
        out = []
        for node in self.nodes_for(purl_or_key):
            out += [self.label(p) for p in self.g.predecessors(node)]
        return sorted(set(out))

    def blast_radius(self, purl_or_key: str) -> int:
        """How many packages (and the app) transitively depend on this package."""
        total: set[str] = set()
        for node in self.nodes_for(purl_or_key):
            total |= nx.ancestors(self.g, node)
        return len(total)

    def is_runtime(self, purl_or_key: str) -> bool:
        return any(self.g.nodes[n].get("runtime") for n in self.nodes_for(purl_or_key))

    def graph_facts(self, purl_or_key: str) -> dict:
        nodes = self.nodes_for(purl_or_key)
        if not nodes:
            return {"found": False}
        d = self.g.nodes[nodes[0]]
        return {
            "found": True,
            "name": d.get("name"),
            "versions": sorted({self.g.nodes[n]["version"] for n in nodes}),
            "copies": len(nodes),
            "direct": any(self.g.nodes[n].get("direct") for n in nodes),
            "runtime": self.is_runtime(purl_or_key),
            "dev_only": not self.is_runtime(purl_or_key),
            "has_install_script": any(self.g.nodes[n].get("has_install_script") for n in nodes),
            "resolved": d.get("resolved"),
            "integrity": d.get("integrity"),
            "paths": self.paths_to_root(purl_or_key, limit=3),
            "dependents": len(self.who_depends_on(purl_or_key)),
            "blast_radius": self.blast_radius(purl_or_key),
        }

    def summary(self) -> dict:
        pk = [d for _, d in self.g.nodes(data=True) if d.get("type") == "Package"]
        return {
            "packages": len(pk),
            "unique_name_versions": len({(d["name"], d["version"]) for d in pk}),
            "direct": sum(1 for d in pk if d.get("direct")),
            "runtime": sum(1 for d in pk if d.get("runtime")),
            "dev_only": sum(1 for d in pk if not d.get("runtime")),
            "install_scripts": sum(1 for d in pk if d.get("has_install_script")),
            "non_npmjs_resolved": sum(1 for d in pk if d.get("resolved") and "registry.npmjs.org" not in d["resolved"]),
            "workflows": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "Workflow"),
            "actions": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "Action"),
            "base_images": sum(1 for _, d in self.g.nodes(data=True) if d.get("type") == "BaseImage"),
            "edges": self.g.number_of_edges(),
        }
