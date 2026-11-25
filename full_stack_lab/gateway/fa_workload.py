"""fast-anything 측정용 작업량: 도구 결과 검사(출력 지시문·내용 지문)를 실제 크기의 텍스트로 돌린다."""
import glob
import json
import sys

from app import flow_fingerprint, poisoning


def corpus() -> list[str]:
    texts = []
    for path in sorted(glob.glob(sys.prefix + "/lib/python3.*/*.py"))[:120]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read()[:48_000])
    korean = "결재 문서 번호 2026-1125-0042, 담당자 kim.minsu@corp.example, 계좌 110-234-567890. " * 300
    texts += [korean, json.dumps({"rows": [{"id": i, "memo": f"고객 {i} 응대 기록"} for i in range(2000)]}, ensure_ascii=False)]
    return texts


def main() -> None:
    salt = b"\x01" * 16
    texts = corpus()
    total = 0
    for text in texts:
        total += len(poisoning.result_findings(text))
        shingles, identifiers = flow_fingerprint.fingerprint(flow_fingerprint.leaf_text({"content": [{"text": text}]}),
                                                             salt, flow_fingerprint.MAX_HASHES)
        total += len(shingles) + len(identifiers)
    print("checked", len(texts), total)


if __name__ == "__main__":
    main()
