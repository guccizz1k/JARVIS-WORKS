# CINEMA × PostgreSQL 거래 엔진 — 최종 통합·결함 수정 보고서 (검토 후보, 미배포)

상태 표기: PASS / PARTIAL / FAIL / BLOCKED / NOT RUN / NOT MEASURED. 테스트 개수는 출시 근거가 아닙니다.
**이 후보는 통합 완료도, 인수도, 출시 가능도 아닙니다.** 아래 14·15항에 남은 항목과 필요한 승인을 모두 적었습니다.
저장소는 PUBLIC입니다. 비밀값·실제 고객 문서·개인정보는 커밋하지 않았고, 모든 시험 데이터는 합성입니다.

## 1. 기준·최종 SHA

| 항목 | 값 |
|---|---|
| 기준 브랜치 / 커밋 | `review/jw-pg-integration-20261104` / `08ea29867e962d4ac5be0e942fc1488528494428` |
| 작업 브랜치 | `review/jw-cinema-pg-engine-20261104` (로컬 전용, **원격 push·PR 없음**) |
| 1) `4392768` | 원본 후보(ZIP의 `original-claude.bundle` HEAD `439276824fb5…`와 동일함을 확인, 아래 3항) |
| 2) `82c8a66` | 감사 보안 패치 `02-security-and-data-integrity-fixes.patch`(S1·S2) + 회귀 J41–J47 |
| 3) `6c316e9` | S3 서버 보관 증빙(엔진·어댑터·브리지) |
| 4) `8dd3d75` | S5 엄격 opt-in 등록(기본 OFF) |
| 5) 최종 | 이 보고서·관계 분석 문서를 포함하는 커밋. 파일 안에 자기 SHA를 적을 수 없으므로 전달한 번들의 `git rev-parse HEAD`가 최종 SHA |

## 2. 변경 파일 목록 (기준 대비)

신규: `app/pg_cinema_trade_v1.py`, `app/pg_cinema_register_v1.py`, `app/cinema_bridge_v3.js`, `scripts/review/cinema_pg_write_engine.sql`, `scripts/review/cinema_pg_write_engine_test.sql`, `scripts/ci_cinema_pg_guard.py`, `scripts/ci_cinema_pg_sql_gate.py`, `.github/workflows/jw-cinema-pg-gates.yml`, `docs/review/cinema-pg-report.md`, `docs/review/cinema-pg-ledger-relationship.md`, `tests/test_cinema_pg_{guard,sql_contract,adapter_contract,bridge_js,entry_load,register,security_regressions}.py`.
수정(화이트리스트 내 기존 파일, 2개): `app/cinema_entry_v1.py`(+2줄: v3 스크립트를 v2 뒤에 이어 붙임), `app/pg_review_integrated_v202.py`(+4줄: import 1, preflight 2, 선택 등록 목록 1 — 기존 인증·권한 코드 무변경, 새 게이트가 꺼져 있으면 동작 변화 없음).
수정하지 않음: CINEMA 원본 HTML/CSS/WebGL, `app/static/`, `app/main.py`, 기존 v1/v2 브리지, 기존 테스트·워크플로·DB 객체.

## 3. 전달 ZIP 대조 및 패치 적용

* ZIP의 원본 패치와 `original-claude.bundle`을 로컬 후보(`4392768`)와 대조: **내용 동일(SHA-256 일치)** → 원본 패치를 **다시 적용하지 않음**.
* `02-security-and-data-integrity-fixes.patch`: `git apply --check` PASS 후 적용 → `82c8a66`.

## 4. 감사 결함 S1–S6 처리

| # | 내용 | 상태 | 증거 |
|---|---|---|---|
| S1 | DB 원문 오류가 HTTP로 노출 | **수정·PASS(스텁 범위)** | SQLSTATE별 고정 문구만 반환, 6개 SQLSTATE에 비밀 문자열 비노출 테스트 8건. 실제 FastAPI `TestClient` 실행은 NOT RUN(설치 불가; CI 워크플로에 단계 추가) |
| S2 | 잘못된 원장 값이 0원·현재 시각으로 표시 | **수정·PASS** | 실패 시 예외로 표시 차단. Node 하네스 J41–J47 + 되돌림 변이 사망 |
| S3 | 서버가 증빙 파일을 검증하지 않음 | **수정(SQL·어댑터·브리지)·PARTIAL** | 6항. 실제 HTTP·브라우저 E2E는 NOT RUN |
| S4 | 두 개의 거래 원장 | **분석·결정 요청(PARTIAL)** | `docs/review/cinema-pg-ledger-relationship.md`: 기존 객체 무접촉을 정적 확인, 단일 원천(안 A/B/C) 결정은 사용자 몫. DB 적용 없음 |
| S5 | 어댑터 미마운트 | **PARTIAL** | opt-in 등록 코드·테스트 완료(기본 OFF). 쓰기 로그인 역할(`jw_cinema_writer` 멤버십)이 없어 실제 마운트·동작은 NOT RUN/BLOCKED |
| S6 | PUBLIC 저장소·승인 경계 | **준수** | 비밀·실문서 없음, push/PR/ACL/배포 없음 |

## 5. 보호 대상 대조 (`python3 -I scripts/ci_cinema_pg_guard.py` → PASS)

CINEMA 원본 HTML blob `9bedf97fe718a94f07861e23670685af00619ca8` 동일 / `app/main.py` blob 동일 / `app/static/` tree 동일 / 기준 커밋이 조상 / 화이트리스트 밖 변경 0 / 삭제된 테스트 0 / 새 SKIP 0 / 외부 워크플로 변경 0 / `main` 아님. 모든 커밋 직전에 실행했습니다. **UI 렌더링·픽셀·DOM 비교는 NOT RUN**(브라우저 없음; 원본 해시 동일만 확인).

## 6. 납품 증빙 검증 (S3) — 구현과 한계

* 브라우저가 원본 파일(PDF/PNG/JPEG, 1바이트~5MB)을 올리면 **DB가 SHA-256을 다시 계산**(`CHECK content_sha256 = encode(sha256(content),'hex')`)하고 크기·형식·매직바이트를 검사. 테넌트별 중복 제거. 납품 기록은 증빙 행에 **외래키**로 묶이고, **기록자 = 업로더**여야 합니다.
* 관리자가 저장된 증빙을 열면(`POST …/evidence/{id}/open`, 열람 감사 행 기록) 그 뒤에만 `delivery_confirm`이 허용됩니다(다른 관리자 직무 분리 유지). 쓰기 역할에는 내용(bytea) 컬럼 SELECT 권한이 없습니다. 열람 응답은 `attachment`·`nosniff`·`no-store`.
* 브리지는 서버가 돌려준 해시만 기록 값으로 사용(로컬 해시는 전송 손상 교차검증용), 열람 시 받은 바이트를 다시 해시해 불일치면 저장·다운로드하지 않음.
* **한계(정직하게):** 이것은 "서버가 파일을 보관·재해시했고, 다른 관리자가 열람 후 사람이 확인했다"는 증거일 뿐 **물류·인수 사실의 확인이 아닙니다.** OCR·서명 진위 검증은 없습니다. 증빙은 DB에 저장되므로 실제 서류에는 개인정보가 포함될 수 있어, 보존기간·접근 통제·백업 포함 여부의 정책 결정이 필요합니다(합성 파일로만 시험).

## 7. 검증 결과 (실제 실행한 것만)

환경: 격리 컨테이너, PostgreSQL **16.15**(로컬 임시 클러스터), Node 22, Python 3. PyPI 접근 불가로 `fastapi`·`psycopg` 설치 불가.

| 시험 | 결과 |
|---|---|
| SQL 게이트(임시 DB, 실제 로그인 역할 포함) | **205/205 PASS** (G1 1, G2 40, G3 101, G5 63), 3회 연속 동일 |
| 순수 Python/JS 신규 테스트 | **150 passed**: 가드 30, SQL 계약 85, 어댑터 계약 13, 브리지(Node vm, 내부 63검사) 5, 진입 페이지 5, 등록 12 |
| 보안 회귀(S1·S2) | **8 passed**(fastapi 스텁 실행기 사용; 실제 fastapi는 NOT RUN) |
| SQL 변이 | 원 8종 **8/8 사망**(재실행·유효성 확인), S3 6종 **6/6 사망** |
| JS 변이 | 현재 브리지 대상 20종(S3 12 + 핵심 8) **20/20 사망** — 단, `JN6`(납품 대기 건을 완료로 계산)은 목표 단언이 아니라 하네스 충돌로 사망 처리되어 약한 증거 |
| 등록 모듈 변이 | 6종 **6/6 사망** |
| `py_compile`·`node --check` | PASS |

## 8. 기존 회귀 전체

기존 169개 회귀(및 현행 전체 회귀): **NOT RUN (BLOCKED)** — `fastapi`·`psycopg` 설치 불가. 신규 테스트 수와 합산하지 않았습니다. 워크플로(`jw-cinema-pg-gates.yml`)는 push 승인 후 Actions에서 실행하도록 작성했으며 **한 번도 실행되지 않았습니다**.

## 9. 실제 인증·CSRF·테넌트 격리

* SQL 범위 **PASS**: FORCE RLS, 쓰기 역할의 직접 테이블 쓰기 불가, 타 테넌트 접근 차단, 일반 사용자 승인 불가, 실제 로그인 역할 확인(G5).
* HTTP 범위(쿠키 세션·CSRF·테넌트 A/B/C): **NOT RUN**. 어댑터는 `ast`/텍스트 계약 테스트와 스텁 단위 테스트로만 확인했고 실제 FastAPI 요청은 실행하지 못했습니다.

## 10. 거래·메신저·자동화 E2E

* 거래(거래처→견적→수주→납품→명세→청구→입금→추적): SQL 흐름 **PASS**, 브리지는 가짜 서버+Node 하네스 **PASS**, **실서버·실브라우저 E2E는 NOT RUN**.
* 메신저 서버 연동: **BLOCKED** — 거래처↔상대 기업 매핑이 없고 UI 변경·v2 차단 해제가 필요(관계 문서 4항). 기존 차단(전송 막힘)은 그대로입니다.
* 업무 자동화 서버 연동: **BLOCKED** — 규칙 저장·실행 주체·DB 변경 승인이 필요(관계 문서 5항). 자동 실행·자동 확정은 없고, 수주·명세표 초안 생성은 사용자 버튼으로 가능합니다.

## 11. 실제 배포·HTTPS 증거

**없음 — NOT RUN.** Render 접근·배포 승인 없음, 어댑터 미마운트. 로컬 결과를 Render 결과로 보고하지 않습니다.

## 12. OCR·백업·복구·성능

**NOT MEASURED / BLOCKED.** OCR은 허가된 실제 문서 50건과 정답표가 없어 BLOCKED. 백업·복구 시간, RPO/RTO, P50/P95/P99는 측정하지 않았고 수치를 만들지 않았습니다(SQL 게이트 소요 시간은 성능 지표가 아님).

## 13. 정직성 플래그 유지

`bank_confirmed=false`(CHECK), 입금은 `internal_record_only`, 납품 확인은 사람(관리자)이 서버 보관 증빙을 열람한 뒤 한 확인. "서버 저장"은 "승인"이 아니며, 은행 정산·물류 도착은 확인된 바 없습니다. 출시 가능 여부: **불가(BLOCKED)** — 기존 운영 전환 차단 조건은 하나도 해제되지 않았습니다.

## 14. 남은 FAIL / PARTIAL / BLOCKED / NOT RUN

FAIL: 0건(알려진 실패 없음).

PARTIAL: S3(HTTP·브라우저 미검증), S4(결정 대기), S5(마운트 대기), G4 UI 보존(해시만).

BLOCKED: 메신저·자동화 연동, 기존 169 회귀, 쓰기 로그인 역할, OCR.

NOT RUN: PG17(로컬 16.15), 실제 FastAPI 요청, 워크플로 실행, 실브라우저 E2E, HTTPS 스테이징 E2E.

NOT MEASURED: 성능, 백업·복구, RPO/RTO.

알려진 구현 한계: 구매(매입) 거래 미지원, 부분 납품 명세표별 부가세 반올림은 일괄 반올림과 1원 단위 차이 가능, 사업자번호는 10자리 형식만 검증, 회원(member)의 청구서 발행 요청은 서버 대응이 없어 안내만 표시.

## 15. 필요한 사용자 승인·결정

1. 원격 push 및 Draft PR(Actions에서 PG17·fastapi 포함 회귀 실행 목적; 월 5만원 한도 내, 워크플로 2잡).
2. 신규 DB 역할 2개 및 기존 스키마·함수에 대한 `USAGE`/`EXECUTE` 추가, 쓰기 전용 비수퍼유저 로그인 역할의 `jw_cinema_writer` 멤버십(S5) — 어느 DB에 적용할지 포함. 현재 어디에도 적용하지 않음.
3. S4 단일 원천 결정(안 A/B/C), 증빙 파일의 DB 보관·보존기간 정책(6항).
4. 메신저: 거래처↔기업 매핑 신설 및 UI·v2 차단 변경 허용 여부. 자동화: 규칙 테이블·실행 주체 정책.
5. Render 스테이징 접근·배포 승인, OCR용 실제 문서 50건과 사용 허가.
