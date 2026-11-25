# POL-I-08 격리 시험용 MCP

합성 텍스트 두 개(`public/sample.txt`, `internal-only/sample.txt`)와 도구 하나(`sample_access`)만 있는 stdio MCP입니다. 도구는 WebAssembly(WASI) 게스트 안에서 파일을 열고, 게스트에는 `public` 폴더 하나만 읽기 전용으로 붙습니다. 호스트 환경 변수와 네트워크는 게스트에 주지 않습니다.

| 호출 | 기대 결과 |
|---|---|
| `{"sample": "public", "operation": "read"}` | `file_access: true` |
| `{"sample": "public", "operation": "write"}` | `file_access: false` (쓰기 거부) |
| `{"sample": "internal-only", "operation": "read"}` | `file_access: false` (붙지 않은 폴더) |

`public` 폴더에 `sample.txt` 말고 다른 항목이 있거나, 경로에 링크·재분석 지점이 있으면 서버가 시작하지 않습니다.

## 등록과 시험

1. 콘솔의 저장소 도입 신청에 이 디렉터리를 소스로 넣고 stdio로 신청합니다. 실행 명령은 `python -m mint_i08_fixture`이고 의존성은 `wasmtime==51.0.0`입니다.
2. 승인 뒤 직원 PC의 하네스에서 위 세 호출을 하고, 호출 기록의 결과와 `public/sample.txt`의 SHA-256이 그대로인지 확인합니다.

격리 범위는 WASI 게스트 안의 파일 접근입니다. 게스트를 띄우는 호스트 Python 프로세스 자체는 격리하지 않습니다. 실행 시작 전에 게이트웨이가 격리 프로필을 OPA로 판정하는 단계는 아직 제품에 없습니다.
