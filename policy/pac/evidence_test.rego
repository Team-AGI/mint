package mcp.pol.evidence_test

import data.mcp.pol.evidence
import rego.v1

facts := {"trusted": true, "now_ns": 100}

cases := {
	"POL-R-06": {
		"valid": {"destination_id": "service-b", "outbound_audience": "service-b", "inbound_credential_id": "fp-a", "outbound_credential_id": "fp-b"},
		"change": {"outbound_credential_id": "fp-a"},
	},
	"POL-R-07": {
		"valid": {"expected_peer": "server-a", "observed_peer": "server-a", "peer_verified": true},
		"change": {"observed_peer": "server-b"},
	},
	"POL-R-09": {
		"valid": {"redirect_uri": "https://client.example/callback", "approved_redirect_uris": ["https://client.example/callback"]},
		"change": {"redirect_uri": "https://other.example/callback"},
	},
	"POL-R-10": {
		"valid": {"expected_user": "user-a", "result_user": "user-a", "expected_session": "session-a", "result_session": "session-a", "expected_request_id": "request-a", "result_request_id": "request-a", "result_already_used": false},
		"change": {"result_already_used": true},
	},
	"POL-R-16": {
		"valid": {"transport": "https", "encrypted": true},
		"change": {"encrypted": false},
	},
	"POL-R-17": {
		"valid": {"expected_hostname": "mcp.example", "verified_hostname": "mcp.example", "certificate_chain_valid": true},
		"change": {"verified_hostname": "other.example"},
	},
	"POL-R-19": {
		"valid": {"client_type": "browser", "origin": "https://app.example", "approved_origins": ["https://app.example"]},
		"change": {"origin": "https://other.example"},
	},
	"POL-E-06": {
		"valid": {"approved_gateway_id": "mint", "observed_gateway_id": "mint", "gateway_path_verified": true},
		"change": {"gateway_path_verified": false},
	},
	"POL-E-12": {
		"valid": {"user_id": "user-a", "work_id": "work-a", "context_items": [{"user_id": "user-a", "work_id": "work-a"}]},
		"change": {"context_items": [{"user_id": "user-b", "work_id": "work-a"}]},
	},
	"POL-E-22": {
		"valid": {"request_id": "request-a", "reserved_request_id": "request-a", "reservation_status": "acquired"},
		"change": {"reservation_status": "already_used"},
	},
	"POL-E-24": {
		"valid": {"queue_elapsed_ms": 100, "run_elapsed_ms": 500, "max_queue_ms": 100, "max_run_ms": 500},
		"change": {"run_elapsed_ms": 501},
	},
	"POL-E-26": {
		"valid": {"append_only": true, "unauthorized_mutation_blocked": true, "integrity_verified": true},
		"change": {"integrity_verified": false},
	},
	"POL-E-27": {
		"valid": {"call_id": "call-a", "recorded_call_id": "call-a", "outcome": "denied", "recorded_outcome": "denied", "recorded_reason": "scope", "persisted_to": "protected_buffer"},
		"change": {"persisted_to": "unprotected_buffer"},
	},
	"POL-E-28": {
		"valid": {"scan_complete": true, "forbidden_fields": []},
		"change": {"forbidden_fields": ["token"]},
	},
	"POL-E-29": {
		"valid": {"standard_error": true, "scan_complete": true, "forbidden_fields": []},
		"change": {"standard_error": false},
	},
	"POL-O-16": {
		"valid": {"expected_call_ids": {"allowed": "call-1", "denied": "call-2", "failed": "call-3"}, "records": [{"outcome": "allowed", "call_id": "call-1"}, {"outcome": "denied", "call_id": "call-2"}, {"outcome": "failed", "call_id": "call-3"}]},
		"change": {"records": [{"outcome": "allowed", "call_id": "call-1"}, {"outcome": "denied", "call_id": "call-2"}, {"outcome": "failed", "call_id": "unrelated"}]},
	},
	"POL-O-17": {
		"valid": {"expected_event_ids": {"new_tool": "event-a", "abnormal_call_increase": "event-b"}, "alerts": [{"scenario": "new_tool", "event_id": "event-a"}, {"scenario": "abnormal_call_increase", "event_id": "event-b"}]},
		"change": {"alerts": [{"scenario": "new_tool", "event_id": "event-a"}]},
	},
	"POL-O-18": {
		"valid": {"responder_id": "on-call", "delivered_to": "on-call", "delivery_confirmed": true, "delivered_sections": ["risk", "stop", "investigate", "recover"]},
		"change": {"delivered_sections": ["risk", "stop", "investigate"]},
	},
	"POL-D-02": {
		"valid": {"server_id": "server-a", "configured_server_ids": ["server-b"], "autoconnect_server_ids": []},
		"change": {"autoconnect_server_ids": ["server-a"]},
	},
	"POL-D-03": {
		"valid": {"inventory_complete": true, "target_credential_ids": ["credential-a", "credential-b"], "confirmed_revoked_ids": ["credential-a", "credential-b"]},
		"change": {"confirmed_revoked_ids": ["credential-a"]},
	},
	"POL-D-04": {
		"valid": {"process_running": false, "autostart_enabled": false},
		"change": {"autostart_enabled": true},
	},
	"POL-D-05": {
		"valid": {"inventory_complete": true, "target_account_grant_ids": ["grant-a"], "revoked_account_grant_ids": ["grant-a"], "target_share_grant_ids": ["share-a"], "revoked_share_grant_ids": ["share-a"]},
		"change": {"revoked_share_grant_ids": []},
	},
	"POL-D-06": {
		"valid": {"inventory_complete": true, "target_firewall_rule_ids": ["rule-a"], "removed_firewall_rule_ids": ["rule-a"], "target_proxy_route_ids": ["route-a"], "removed_proxy_route_ids": ["route-a"]},
		"change": {"removed_proxy_route_ids": []},
	},
	"POL-D-08": {
		"valid": {"required_until_ns": 1000, "retain_until_ns": 1000, "protected_storage": true, "pre_termination_records_covered": true, "post_termination_records_covered": true},
		"change": {"retain_until_ns": 999},
	},
}

verdict(id, observation) := result if {
	result := evidence.decision with input as {"policy_id": id, "facts": facts, "observation": observation}
}

test_cases_cover_supported_policies if {
	object.keys(cases) == object.keys(evidence.reasons)
}

test_valid_observations[id] if {
	some id, fixture in cases
	verdict(id, fixture.valid).effect == "ALLOW"
}

test_violations[id] if {
	some id, fixture in cases
	result := verdict(id, object.union(fixture.valid, fixture.change))
	result.effect == "DENY"
	result.policy_ids == [id]
}

test_missing_observations[id] if {
	some id in object.keys(cases)
	result := verdict(id, {})
	result.effect == "DENY"
	result.policy_ids == [id]
}

test_unknown_policy_denied if {
	verdict("POL-D-07", {}).policy_ids == ["INPUT_CONTRACT"]
}

test_unknown_observation_type_denied if {
	verdict("POL-D-04", []).policy_ids == ["INPUT_CONTRACT"]
}

test_untrusted_evidence_denied if {
	result := evidence.decision with input as {
		"policy_id": "POL-D-04",
		"facts": {"trusted": false, "now_ns": 100},
		"observation": cases["POL-D-04"].valid,
	}
	result.policy_ids == ["INPUT_CONTRACT"]
}

test_non_browser_without_origin_allowed if {
	verdict("POL-R-19", {"client_type": "non_browser", "client_verified": true}).effect == "ALLOW"
}

test_unverified_non_browser_denied if {
	verdict("POL-R-19", {"client_type": "non_browser", "client_verified": false}).effect == "DENY"
}

test_malformed_audit_records_denied if {
	observation := object.union(cases["POL-O-16"].valid, {"records": [true, null]})
	verdict("POL-O-16", observation).effect == "DENY"
}

test_malformed_revocation_inventory_denied if {
	observation := {"inventory_complete": true, "target_credential_ids": [null], "confirmed_revoked_ids": [null]}
	verdict("POL-D-03", observation).effect == "DENY"
}
