# Guardian sample policies (stretch goal: policy-as-code). Evaluated by Conftest/OPA inside the podman sandbox on the
# policy input that Guardian builds from each report (guardian/policy.py). `deny` blocks the merge; `warn` asks for a
# human review. Every message starts with a rule ID so the report and the UI can show which rule fired.
# Data (allow/deny lists) comes from guardian.yaml as `data.guardian`.
package main

import rego.v1

new_findings contains f if {
	some f in input.findings
	f.label == "introduced"
}

# ---------------------------------------------------------------- deny (block the merge)
deny contains msg if {
	some f in input.findings
	f.malicious
	msg := sprintf("[GP-001] known malicious package in the application: %s (%s)", [f.component, f.id])
}

deny contains msg if {
	some f in new_findings
	f.hard_signal
	msg := sprintf("[GP-002] supply-chain attack signal introduced: %s on %s", [f.type, f.component])
}

deny contains msg if {
	some f in new_findings
	f.kind == "vulnerability"
	f.severity == "critical"
	f.runtime
	msg := sprintf("[GP-003] critical vulnerability introduced in shipped code: %s %s", [f.component, f.id])
}

deny contains msg if {
	some f in new_findings
	f.type == "untrusted_image"
	f.severity == "high"
	msg := sprintf("[GP-004] base image from an untrusted registry introduced: %s", [f.component])
}

deny contains msg if {
	some c in input.components
	c.license in data.guardian.license_denylist
	c.new
	msg := sprintf("[GP-005] component with a denied licence introduced: %s@%s (%s)", [c.name, c.version, c.license])
}

# ---------------------------------------------------------------- warn (needs a human decision)
warn contains msg if {
	some f in new_findings
	f.kind == "vulnerability"
	f.severity == "high"
	msg := sprintf("[GP-101] high-severity vulnerability introduced: %s %s", [f.component, f.id])
}

warn contains msg if {
	some f in new_findings
	f.type in {"untrusted_image", "image_not_pinned", "action_not_pinned"}
	f.severity in {"high", "medium"}
	msg := sprintf("[GP-102] unpinned or untrusted build component introduced: %s (%s)", [f.component, f.type])
}

warn contains msg if {
	some f in new_findings
	f.type in {"extra_repository", "extra_index_url", "insecure_transport", "checksum_bypass", "sandbox_egress_blocked"}
	msg := sprintf("[GP-103] dependency source weakened: %s on %s", [f.type, f.component])
}

warn contains msg if {
	some f in new_findings
	f.type in {"suspicious_install_behavior", "provenance_dropped", "publisher_change", "unusual_release", "young_package"}
	msg := sprintf("[GP-104] package behaviour or history needs review: %s on %s", [f.type, f.component])
}

warn contains msg if {
	some t in input.not_checked
	msg := sprintf("[GP-105] a check did not run, so coverage is incomplete: %s", [t])
}
