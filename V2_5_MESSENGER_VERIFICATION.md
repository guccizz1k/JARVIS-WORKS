# JARVIS WORKS V2.5 — 대화 페이지네이션·SSE 동기화 후보 검증

**상태: 격리된 로컬 검토 후보 / 전체 PARTIAL / 실제 기업 데이터 사용 금지**  
**확인일: 2026-10-19**

## 원본·수정 범위

- 원본: `JARVIS-WORKS-V2.4-MESSENGER-UNREAD-UX-REVIEW-CANDIDATE.zip` (변경 없이 별도 보존).
- 변경: `app/messenger.py`, `app/static/app.js`, `app/static/style.css`, `app/static/index.html`, `README.md`.
- 신규: `tests/test_messenger_v25.py`, `tests/browser_messenger_v25.py`, `proof/v25_messenger_1440px.png`, `proof/v25_messenger_390px.png`, 이 보고서.
- GitHub `guccizz1k/JARVIS-WORKS` main, 기존 V2.4 ZIP, 운영 서버, DB, 다른 프로젝트는 수정하지 않았다.

## V2.5 동작

1. **오래된 기록 접근:** `GET /api/messenger/threads/{id}/messages/page`에 `before` 또는 `after` 커서와 `limit=1..100` 지원. 기본 50개. `before`는 과거 페이지, `after`는 누락 없이 순차 신규 페이지로 이동한다. 회사/대화에 속하지 않은 커서는 404, 비정상·충돌 쿼리는 422로 거부한다. 기존 최근 100개 API는 이전 호환용으로 그대로 유지했다.
2. **클라이언트 대화 이력:** `이전 대화 더 보기` 버튼을 눌러 50개씩 prepend. 기존 스크롤 위치와 초안 유지. 대화가 많아져도 기존 기록을 자동 삭제하거나 최신 100개로 강제 대체하지 않는다. 화면에서 전송 완료 시 초안 입력을 비우고 이전에 로드한 기록은 유지한다. 같은 파일을 다시 선택할 수 있도록 업로드 input 초기화.
3. **수신 갱신:** SSE `GET /api/messenger/threads/{id}/events`는 새 메시지·텍스트 수정·발주서 수신 확인을 감지하는 **변경 신호만** 보낸다. 실제 메시지 내용은 인증된 페이지/증분 API에서 가져온다. 백엔드는 SQLite 변경 상태를 약 1초 간격으로 확인한다. 브라우저 EventSource 실패 시 4.5초 간격 기존 폴링을 계속한다. 연결 100초마다 갱신하며 세 번 연속 SSE 실패 시 SSE를 중단하고 폴링으로 안전하게 내려간다. **실시간 전송 지연의 운영 보장은 없다.**
4. **세션/자격 재검증:** SSE가 열린 뒤에도 매 확인 주기마다 로그인 세션과 대화 참가·기업 자격을 재확인한다. 로그아웃, 세션 취소, 이용 자격 취소 뒤 기존 스트림이 데이터를 더 받지 못하도록 종료한다. 타 회사 구독은 404 거부.
5. **빈 대화 목록 갱신:** 기존 대화가 하나도 없는 회사도 4.5초 폴링으로 새로 도착한 기업 대화를 발견해 목록에 노출한다.

## 보존한 요구사항

- 회사명으로 검색하고 목록 스크롤로 기업 선택, 즉시 채팅, `+` 사진·파일·발주서 전송.
- 메시지 삭제 API 없음 + DB 삭제 방지 트리거, 발송 후 30분 이내 원문 수정·이력 보존, 기업별 읽음 표시, 원본 첨부 증빙 불변, 기업별 접근제어.
- **채팅 시작 승인만 제거**. 견적/발주/입금의 별도 상업적 승인·증빙 규칙은 보존한다.
- 미검증 기업/미가입 기업에 대한 접근 제한과 20메시지/분 제한 유지.

## 5-Gate 검증 및 증거

| Gate | 상태 | 실제 실행·범위 |
|---|---|---|
| 1 코드·환경 | PASS | `python -m compileall -q app`, `node --check app/static/app.js` |
| 2 기능 정확성 | PASS (메신저 범위) | V2.2/V2.3/V2.4/V2.5 메신저 **28/28 PASS**. 새 테스트는 1,103개 메시지 전체 페이지 순회, 수신 증분, 커서 오류·타기업 접근, 30분 수정 이력, SSE 준비/변경/자격회수/로그아웃 포함 |
| 3 안정성·회귀 | PASS (선정 범위) | 메신저·보안·워크플로·PostgreSQL **오프라인 정책 검사** 묶음 **104/104 PASS**, 기존 Smart Import **37/37 PASS**, 추가 보안·백업·자동화 묶음 **25/25 PASS**. 총 **166개 서로 중복 없는 테스트 PASS**. 이는 PostgreSQL 라이브 DB 격리 증거가 아니다. |
| 4 UI·UX | PASS (시뮬레이션) | Chromium 데스크톱 1440×900 / 모바일 뷰포트 390×844, 실 HTML/CSS/JS + in-process FastAPI TestClient 브리지. 137개 대화, 50개씩 이어 불러오기, 초안 및 스크롤 유지, 타기업 발송 후 갱신, 직접 전송 후 기록 유지, 신규 대화 목록 갱신과 `+` 메뉴 확인. 결과 PNG 2장 보존. 실제 iPhone Safari/외부 HTTP 네트워크 시험은 NOT RUN. |
| 5 운영·배포 | BLOCKED | 실제 기업 실명/사업자 인증, 운영 PostgreSQL RLS, 기업별 데이터 암호화/키 관리, 악성코드 검역·안전 파일 저장소, 보관·법정 삭제 정책, WebSocket/SSE 실제 네트워크 부하/재연결 실측, 대량 동시사용 시험, 고객사 PC/iPhone 검증, 운영 배포 모두 완료되지 않음. |

### 전체 테스트 제한

- 전체 프로젝트 `pytest -q` 일괄 실행은 시간 제한으로 종료되어 **207개 테스트 전체 PASS는 주장하지 않는다**.
- 위 166개는 서로 중복하지 않는 선택 파일 묶음에서 각각 통과한 실제 수치다. 기존 문서 도입/견적 가져오기 등 나머지 테스트 약 41개를 포함한 단일 통합 결과는 NOT COMPLETED.
- 본 UI 시험은 Chromium+TestClient 브리지. SSE 변경 신호와 세션 권한 회수는 Python 비동기 generator 테스트를 통과했으나, **실제 HTTP 스트리밍 프록시/운영 서버를 통한 전달·알림 지연 테스트는 NOT RUN**.
- 데이터가 큰 채팅은 1,103개 메시지를 조회하여 누락/중복이 없는지 자동 검증했다. 운영 SLA나 처리량 수치는 측정하지 않았다.

## 미완성·기존 제한

- SQLite 내장 BLOB 첨부: 파일당 5MiB, 회사당 40MiB. 백신/악성파일 무해화 검사 및 엔터프라이즈 저장소 대체가 아니다.
- 메시지 페이지는 SQLite `rowid`를 내부 순서로 활용한다. 일반 읽기·쓰기 중에는 일관되지만 DB 덤프/재구성/VACUUM 등에서 rowid 재지정 가능성을 고려해야 한다. 회사별 읽음 커서도 기존 V2.4에서 같은 rowid를 사용하며, 운영 전 영속 메시지 시퀀스 기반으로 전환 검증이 필요하다.
- 기존 대화 목록 상한 최근 200개, 검색 페이지 offset 기반, 폴링/SSE 동시 부하와 장기 스트림은 상용 운용에 부적합할 수 있다.
- 기업 검증은 시뮬레이션. 법인 사업자번호 실제 정부 조회·계정 유일성 확인은 구현되지 않았다.
- 타 프로젝트 TOOLKIT/CLEAN KIT/BACCARAT/JARVIS-CORE 변경 없음.

## 재현

```sh
python -m compileall -q app
node --check app/static/app.js
PYTHONPATH=. pytest -q tests/test_messenger_v22.py tests/test_messenger_v23.py tests/test_messenger_v24.py tests/test_messenger_v25.py
PYTHONPATH=. pytest -q tests/test_messenger_v22.py tests/test_messenger_v23.py tests/test_messenger_v24.py tests/test_messenger_v25.py tests/test_security.py tests/test_security_center.py tests/test_workflows.py tests/test_pg_rls_v19.py tests/test_pg_rls_v20.py tests/test_pg_rls_v21.py
PYTHONPATH=. pytest -q tests/test_smart_import.py
PYTHONPATH=. pytest -q tests/test_automation_entry.py tests/test_encrypted_evidence_v17.py tests/test_rls_plan_v18.py tests/test_secure_backup_v18.py tests/test_security_hardening_v17.py tests/test_security_v18.py
PYTHONPATH=. python tests/browser_messenger_v25.py
```

**최종 판정: PARTIAL.** 로컬 검증 후보는 제작·보존했지만 GitHub push/PR/merge, 공개 서비스 배포, 실기기 검증, 전체 회귀·운영 인증은 수행하지 않았다.
