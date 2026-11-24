"""Contextual scoring: rank stability, confidence, reachability, fix-candidate scoring, before/after delta.

Everything here is deterministic. Nothing in this package may lower a hard-signal floor or change a
level/decision/verdict, except the one documented CVE-only reachability rule in guardian/scoring/score.py.
See docs/contextual-scoring/README.md.
"""
