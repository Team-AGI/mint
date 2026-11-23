# METADATA
# title: 집행 구성요소가 수집한 증거의 정책 판정
# description: 기존 판정 패키지에 규칙이 없는 정책을 한 건씩 평가한다.
package mcp.pol.evidence

import data.mcp.pol.lib
import rego.v1

obs := input.observation

reasons := {
	"POL-R-06": "하위 서비스에 사용할 자격의 대상 또는 지문 불일치",
	"POL-R-07": "연결 응답의 상대 신원 불일치 또는 미검증",
	"POL-R-09": "인증 결과 수신처가 승인 목록에 없음",
	"POL-R-10": "인증 결과의 사용자, 세션 또는 요청 불일치나 재사용",
	"POL-R-16": "원격 연결의 암호화 전송을 확인할 수 없음",
	"POL-R-17": "서버 인증서의 신뢰 또는 이름 일치 검증 실패",
	"POL-R-19": "브라우저 Origin이 미승인 상태이거나 연결 방식 확인 불가",
	"POL-E-06": "승인된 Gateway를 통한 호출임을 확인할 수 없음",
	"POL-E-12": "사용자 또는 업무가 다른 자료가 컨텍스트에 포함됨",
	"POL-E-22": "중복 실행 방지 예약이 이미 사용됐거나 요청과 일치하지 않음",
	"POL-E-24": "요청 대기 또는 실행 시간 한도 확인 실패나 초과",
	"POL-E-26": "감사 기록의 추가 전용 저장 또는 무결성 확인 실패",
	"POL-E-27": "거부, 실패 또는 예외의 감사 사유나 보호된 저장 기록 없음",
	"POL-E-28": "저장할 로그에서 금지 항목이 발견되거나 검사가 미완료",
	"POL-E-29": "표준 오류가 아니거나 반환할 오류에 금지 항목이 있음",
	"POL-O-16": "설정 변경 후 허용, 거부 또는 실패 시험의 감사 기록 누락",
	"POL-O-17": "경보 시험에서 새 Tool 또는 비정상 호출 증가 경보 누락",
	"POL-O-18": "조치 책임자에게 위험과 대응 절차가 전달되지 않음",
	"POL-D-02": "폐기 서버의 Agent 접속 정보 또는 자동 연결 경로 잔존",
	"POL-D-03": "폐기 대상 토큰 또는 API 키의 무효화 미확인",
	"POL-D-04": "서버 프로세스 종료 또는 자동 시작 해제 미확인",
	"POL-D-05": "폐기 대상 문서 계정 또는 공유 권한 회수 미확인",
	"POL-D-06": "폐기 대상 방화벽 규칙 또는 프록시 경로 제거 미확인",
	"POL-D-08": "폐기 감사 기록이 보존기간 동안 보호되는지 확인할 수 없음",
}

decision := lib.decide(findings)

contract_ok if {
	lib.base_contract_ok
	input.policy_id in object.keys(reasons)
	is_object(obs)
}

findings contains lib.finding("INPUT_CONTRACT", "DENY", "정책 ID, 신뢰 표식, 현재 시각 또는 증거 객체가 유효하지 않음") if {
	not contract_ok
}

findings contains lib.finding(input.policy_id, "DENY", reasons[input.policy_id]) if {
	contract_ok
	not input.policy_id in passes
}

# METADATA
# custom:
#   pol_id: POL-R-06
#   risk_id: RSK-R-04
#   checkpoint: 서버가 하위 서비스에 요청하기 전
passes contains "POL-R-06" if {
	lib.text(obs.destination_id)
	obs.outbound_audience == obs.destination_id
	lib.text(obs.inbound_credential_id)
	lib.text(obs.outbound_credential_id)
	obs.inbound_credential_id != obs.outbound_credential_id
}

# METADATA
# custom:
#   pol_id: POL-R-07
#   risk_id: RSK-R-05
#   checkpoint: MCP 연결 응답 수신 시
passes contains "POL-R-07" if {
	lib.text(obs.expected_peer)
	obs.observed_peer == obs.expected_peer
	obs.peer_verified == true
}

# METADATA
# custom:
#   pol_id: POL-R-09
#   risk_id: RSK-R-05
#   checkpoint: 연결 요청 시 결과 수신처 지정 및 결과 수신
passes contains "POL-R-09" if {
	lib.text(obs.redirect_uri)
	is_array(obs.approved_redirect_uris)
	obs.redirect_uri in obs.approved_redirect_uris
}

# METADATA
# custom:
#   pol_id: POL-R-10
#   risk_id: RSK-R-05
#   checkpoint: 연결 요청에 대한 결과 수신 시
passes contains "POL-R-10" if {
	lib.text(obs.expected_user)
	obs.result_user == obs.expected_user
	lib.text(obs.expected_session)
	obs.result_session == obs.expected_session
	lib.text(obs.expected_request_id)
	obs.result_request_id == obs.expected_request_id
	obs.result_already_used == false
}

# METADATA
# custom:
#   pol_id: POL-R-16
#   risk_id: RSK-R-09
#   checkpoint: 원격 요청 및 응답 전송 시
passes contains "POL-R-16" if {
	obs.transport == "https"
	obs.encrypted == true
}

# METADATA
# custom:
#   pol_id: POL-R-17
#   risk_id: RSK-R-09
#   checkpoint: 원격 서버 TLS 연결 시
passes contains "POL-R-17" if {
	lib.text(obs.expected_hostname)
	obs.verified_hostname == obs.expected_hostname
	obs.certificate_chain_valid == true
}

# METADATA
# custom:
#   pol_id: POL-R-19
#   risk_id: RSK-R-10
#   checkpoint: 브라우저 기반 원격 MCP 요청 수신 시
passes contains "POL-R-19" if {
	origin_allowed
}

# METADATA
# custom:
#   pol_id: POL-E-06
#   risk_id: RSK-E-05
#   checkpoint: Agent가 MCP 서버에 연결할 때
passes contains "POL-E-06" if {
	lib.text(obs.approved_gateway_id)
	obs.observed_gateway_id == obs.approved_gateway_id
	obs.gateway_path_verified == true
}

# METADATA
# custom:
#   pol_id: POL-E-12
#   risk_id: RSK-E-10
#   checkpoint: Agent 요청 시작 및 컨텍스트 구성 시
passes contains "POL-E-12" if {
	lib.text(obs.user_id)
	lib.text(obs.work_id)
	is_array(obs.context_items)
	every item in obs.context_items {
		item.user_id == obs.user_id
		item.work_id == obs.work_id
	}
}

# METADATA
# custom:
#   pol_id: POL-E-22
#   risk_id: RSK-E-17
#   checkpoint: 문서 수정 및 삭제 요청 재시도 시
passes contains "POL-E-22" if {
	lib.text(obs.request_id)
	obs.reserved_request_id == obs.request_id
	obs.reservation_status == "acquired"
}

# METADATA
# custom:
#   pol_id: POL-E-24
#   risk_id: RSK-E-18
#   checkpoint: Tool 요청 대기 및 실행 중
passes contains "POL-E-24" if {
	lib.count_value(obs.queue_elapsed_ms)
	lib.count_value(obs.run_elapsed_ms)
	lib.count_value(obs.max_queue_ms)
	lib.count_value(obs.max_run_ms)
	obs.max_queue_ms > 0
	obs.max_run_ms > 0
	obs.queue_elapsed_ms <= obs.max_queue_ms
	obs.run_elapsed_ms <= obs.max_run_ms
}

# METADATA
# custom:
#   pol_id: POL-E-26
#   risk_id: RSK-E-19
#   checkpoint: 감사 기록 저장 및 읽기 및 삭제 시
passes contains "POL-E-26" if {
	obs.append_only == true
	obs.unauthorized_mutation_blocked == true
	obs.integrity_verified == true
}

# METADATA
# custom:
#   pol_id: POL-E-27
#   risk_id: RSK-E-19
#   checkpoint: Tool 호출 거부 및 실패 및 예외 발생 시
passes contains "POL-E-27" if {
	lib.text(obs.call_id)
	obs.recorded_call_id == obs.call_id
	obs.outcome in {"denied", "failed", "exception"}
	obs.recorded_outcome == obs.outcome
	lib.text(obs.recorded_reason)
	obs.persisted_to in {"central", "protected_buffer"}
}

# METADATA
# custom:
#   pol_id: POL-E-28
#   risk_id: RSK-E-20
#   checkpoint: Tool 입력 및 응답 로그 기록 전
passes contains "POL-E-28" if {
	no_forbidden_fields
}

# METADATA
# custom:
#   pol_id: POL-E-29
#   risk_id: RSK-E-20
#   checkpoint: 오류 응답 생성 전
passes contains "POL-E-29" if {
	obs.standard_error == true
	no_forbidden_fields
}

# METADATA
# custom:
#   pol_id: POL-O-16
#   risk_id: RSK-E-19
#   checkpoint: 로그 수집 설정 변경 후 시험
passes contains "POL-O-16" if {
	is_object(obs.expected_call_ids)
	is_array(obs.records)
	every outcome in {"allowed", "denied", "failed"} {
		audit_test_recorded(outcome)
	}
}

# METADATA
# custom:
#   pol_id: POL-O-17
#   risk_id: RSK-O-13
#   checkpoint: 경보 규칙 적용 및 정기 시험 시
passes contains "POL-O-17" if {
	is_object(obs.expected_event_ids)
	is_array(obs.alerts)
	every scenario in {"new_tool", "abnormal_call_increase"} {
		alert_test_recorded(scenario)
	}
}

# METADATA
# custom:
#   pol_id: POL-O-18
#   risk_id: RSK-O-14
#   checkpoint: 위험 경보 발생 시
passes contains "POL-O-18" if {
	lib.text(obs.responder_id)
	obs.delivered_to == obs.responder_id
	obs.delivery_confirmed == true
	lib.subset(["risk", "stop", "investigate", "recover"], obs.delivered_sections)
}

# METADATA
# custom:
#   pol_id: POL-D-02
#   risk_id: RSK-D-02
#   checkpoint: 서버 연결 종료 및 설정 배포 시
passes contains "POL-D-02" if {
	lib.text(obs.server_id)
	identifier_list(obs.configured_server_ids)
	identifier_list(obs.autoconnect_server_ids)
	not obs.server_id in obs.configured_server_ids
	not obs.server_id in obs.autoconnect_server_ids
}

# METADATA
# custom:
#   pol_id: POL-D-03
#   risk_id: RSK-D-03
#   checkpoint: 서버 연동 종료 시
passes contains "POL-D-03" if {
	obs.inventory_complete == true
	identifiers_covered(obs.target_credential_ids, obs.confirmed_revoked_ids)
}

# METADATA
# custom:
#   pol_id: POL-D-04
#   risk_id: RSK-D-04
#   checkpoint: 로컬 서버 폐기 시
passes contains "POL-D-04" if {
	obs.process_running == false
	obs.autostart_enabled == false
}

# METADATA
# custom:
#   pol_id: POL-D-05
#   risk_id: RSK-D-05
#   checkpoint: 문서 저장소 연동 서버 폐기 시
passes contains "POL-D-05" if {
	obs.inventory_complete == true
	identifiers_covered(obs.target_account_grant_ids, obs.revoked_account_grant_ids)
	identifiers_covered(obs.target_share_grant_ids, obs.revoked_share_grant_ids)
}

# METADATA
# custom:
#   pol_id: POL-D-06
#   risk_id: RSK-D-06
#   checkpoint: 서버 연결 폐기 시
passes contains "POL-D-06" if {
	obs.inventory_complete == true
	identifiers_covered(obs.target_firewall_rule_ids, obs.removed_firewall_rule_ids)
	identifiers_covered(obs.target_proxy_route_ids, obs.removed_proxy_route_ids)
}

# METADATA
# custom:
#   pol_id: POL-D-08
#   risk_id: RSK-D-08
#   checkpoint: 서버 및 Tool 폐기 후 감사 기록 접근 시
passes contains "POL-D-08" if {
	lib.count_value(obs.required_until_ns)
	lib.count_value(obs.retain_until_ns)
	obs.required_until_ns > 0
	obs.retain_until_ns >= obs.required_until_ns
	obs.protected_storage == true
	obs.pre_termination_records_covered == true
	obs.post_termination_records_covered == true
}

origin_allowed if {
	obs.client_type == "browser"
	lib.text(obs.origin)
	is_array(obs.approved_origins)
	obs.origin in obs.approved_origins
}

origin_allowed if {
	obs.client_type == "non_browser"
	obs.client_verified == true
	not "origin" in object.keys(obs)
}

no_forbidden_fields if {
	obs.scan_complete == true
	obs.forbidden_fields == []
}

audit_test_recorded(outcome) if {
	id := obs.expected_call_ids[outcome]
	lib.text(id)
	some record in obs.records
	record.outcome == outcome
	record.call_id == id
}

alert_test_recorded(scenario) if {
	id := obs.expected_event_ids[scenario]
	lib.text(id)
	some alert in obs.alerts
	alert.scenario == scenario
	alert.event_id == id
}

identifiers_covered(targets, observed) if {
	identifier_list(targets)
	identifier_list(observed)
	lib.subset(targets, observed)
}

identifier_list(items) if {
	is_array(items)
	every item in items {
		lib.text(item)
	}
}
