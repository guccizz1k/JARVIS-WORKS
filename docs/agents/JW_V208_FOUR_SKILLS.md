# JARVIS-WORKS V20.8 · 검토용 외부 스킬 4종

**상태:** 원본 도입 후보 / 비운영 / 비활성. 원래 J1–J6, 기존 `AGENTS.md`, 보안 및 승인 규칙이 모든 외부 스킬보다 우선한다. UI/UX 개발은 중단 상태.

- Cloudflare `security-audit`: 보안 공격 클래스, 근거 기록, 독립 검증 및 원본 검증기(테스트 포함). 실제 대상 코드 실행은 **OS 격리·네트워크 차단**이 확보된 경우에만 진행하며, 허가 없는 모의 공격 금지.
- Ponytail `ponytail`: 변경 전 실제 콜러·데이터 흐름 조사, 최소 수정과 기존 부품 재사용. 금융 계산, 입력 검증, 인증, 개인정보, 회귀 테스트 삭제 금지.
- ECC `change-impact`: 변경 전후의 API·DB·보안·CI·복구 영향 분석. ECC 314개 스킬이나 자동 훅을 일괄 설치하지 않음.
- Impeccable `impeccable`: 정지된 UI/UX 작업을 건드리지 않고 감사·접근성 참고자료만 연결. **네이티브 CLI, 브라우저 확장, 자동 다운로드는 설치·실행하지 않음.** 실제 Impeccable 엔진 검사는 NOT RUN.

## Trust and supply chain
- 출처와 전체 커밋·Git blob 고정: `docs/agents/JW_V208_FOUR_SKILLS_MANIFEST.json`.
- 네 라이선스 전문: `docs/third_party/licenses/`.
- 원본 스킬 파일과 참고자료는 기존 제품의 런타임에서 import/execute되지 않는다.
- 서드파티 명령, 웹 요청, 외부 API, 결제, Secrets, tenant 데이터에 권한 부여 금지.
- 원본 Cloudflare 검증기 자체 테스트는 읽기 전용으로 오프라인 실행하며 기존 릴리스 조건을 대체할 수 없다.

## Gates
`python scripts/ci_v208_four_skills.py --repo .`
`python -m unittest discover -s tests -p 'test_v208_four_skills.py' -v`
`node --test .agents/skills/security-audit/validate-findings.test.cjs .agents/skills/security-audit/validate-coverage-ledger.test.cjs`

일반 5-Gate + **동일 SHA 전체 J1–J6** 성공 이후에도 실제 보안 공격 발견 성과, Ponytail 전후 비용, ECC 전체 에이전트 작동, Impeccable 렌더링 감사는 별도 실전 검증 전까지 NOT MEASURED/NOT RUN.

**롤백:** Draft PR 닫고 검토 브랜치 폐기. app, db, main, 프로덕션 및 실데이터 변경 없음.
