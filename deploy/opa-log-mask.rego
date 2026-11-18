package system.log

# The health and policy views read whole catalog documents on each verification.
# Keep the lookup event and decision ID without copying the document into stdout.
mask contains "/result" if {
	input.path in {"authorization", "restrictions", "egress", "policy_set", "policy_ledger", "residency"}
}
