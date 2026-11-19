package mint_test.log

import data.system.log.mask

test_catalog_lookups if {
	every path in {"authorization", "restrictions", "egress", "policy_set", "policy_ledger", "residency"} {
		mask == {"/result"} with input as {"path": path, "result": {"version": "test"}}
	}
}

test_tool_decisions if {
	every decision in {"Allow", "Alert", "Restrict", "Approval", "Block"} {
		mask == set() with input as {"path": "mcp/authz/decision", "input": {}, "result": {"decision": decision}}
	}
}
