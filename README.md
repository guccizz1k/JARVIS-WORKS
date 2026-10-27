# JARVIS-WORKS — BUSINESS PRODUCT (CORE-first planned)
This repository contains B2B customer product code. Generic J TEAM/J1–J6 development orchestration has been copied to JARVIS-CORE review PR and is pending verified migration. Existing local copies stay only for compatibility. The CORE-first required private reusable workflow needs GitHub Actions private sharing enabled by the owner; see config/core_dependency.json. No production launch or main merge is implied.

# JARVIS WORKS V2.8 — 첨부파일/읽음기록 PostgreSQL 보안 하네스 강화 (미배포)

- **사용 중인 FastAPI 웹앱은 여전히 SQLite 기반 데모이며, 기업 실데이터 입력 금지**입니다. PostgreSQL 17용 V2.8 패치·공격 검사는 기존 V2.7 정책 위에 **일회성 격리 시험 DB**에서만 적용하는 별도 후보입니다.
- V2.7 발견 위험: 저장된 첨부파일 SHA-256 불일치 허용, 같은 기업의 다른 직원에 의한 메시지 첨부, 일반 텍스트 메시지에 첨부, 읽음 시각 사용자 지정. `security/postgres_messenger_rls_v28_hardening.sql`에서 저장 해시 재계산 검사, 원발신자·메시지 유형 확인, 서버 읽음 시각 통제를 추가했습니다.
- 새로운 수동 전용 PostgreSQL 17 시험: `.github/workflows/pg-rls-v28-gate.yml` 또는 `scripts/run_pg17_codespaces_v28.sh` (실행에 필요한 별도 승인·환경 필요). 기존 V2.7 SQL과 하네스는 보존합니다.
- **실 PostgreSQL RLS 공격 시험은 NOT RUN**, 현재 버전으로 서버를 실제 출시하지 않았습니다. SQLite 전용 성능 스모크는 로컬 단회 측정이며 상용 성능 기준이 아닙니다.
- 자세한 안전 조건: `docs/V2_8_POSTGRES_SECURITY_GATE.md`, 결과: `V2_8_MESSENGER_SECURITY_VERIFICATION.md`.

---

# JARVIS WORKS V2.7 — PostgreSQL 메신저 RLS 격리 시험 후보 (미배포)

- **현재 실행되는 웹 앱은 여전히 SQLite 데모입니다.** PostgreSQL 메신저 코드는 독립된 *일회성 PG17 시험 DB용 정책/공격 하네스*이며 FastAPI에 연결되지 않았습니다.
- 기업별 서명된 거래 세션을 사용한 양방향 메시지 읽기, 실제 발신 사용자 인증, 첨부/수정 이력 및 읽음 위치의 접근 범위, 트랜잭션 순번·읽음 워터마크를 검증하도록 설계했습니다.
- `security/postgres_messenger_rls_v27.sql`, `scripts/test_postgres_messenger_v27.py`, `scripts/run_postgres_isolation_ci.py`, `docs/V2_7_POSTGRES_MESSENGER_GATE.md` 참조.
- **정적 검증은 실 PostgreSQL 보안 검증과 다릅니다.** 실제 PostgreSQL 17 라이브 격리·부하·복구 검증과 운영용 PG 어댑터·이전·퇴사권한/사업자 진위 확인은 **NOT RUN / NOT IMPLEMENTED**.
- 이전 버전 원본·데모 데이터·GitHub와 운영 배포는 변경하지 않은 로컬 검토 후보입니다. 실제 거래 문서를 입력하지 마세요.

---

# JARVIS WORKS V2.6 — 기업 메신저 영속 순서·동시성 검증 후보 (미배포)

- V2.5의 메시지 페이지네이션·SSE·읽음 UI를 유지하면서 변경 가능성이 있는 SQLite `rowid` 의존성을 제거했다.
- 기존 메시지·대화·읽음 위치를 변경하지 않고 새 영속 `message_seq`, `connection_seq`, `last_read_seq`로 일회성 순방향 이전한다. 신규 메시지 순번은 트리거에서 원자적으로 발급한다.
- 동일한 시각의 대화방 생성/신규 메시지 순서 충돌을 수정하고 메시지 내부 순번은 외부 API로 노출하지 않는다.
- **제품/보안 게이트:** 여전히 격리된 SQLite 데모이며 실제 기업 데이터 투입 금지. 실제 PostgreSQL RLS·사업자 인증·대규모 부하·실기기/운영 배포는 미완료.
- 변경 및 테스트 보고는 `V2_6_MESSENGER_VERIFICATION.md` 참조. GitHub 원본 미변경.

---

# JARVIS WORKS V2.5 — 기업 메신저 기록·SSE 검토 후보 (미배포)

- 변경 내역 및 5-Gate 검증: `V2_5_MESSENGER_VERIFICATION.md` 참고.
- 기업 검색/즉시 대화/사진·파일·발주서와 기존 회계·업무 기능 보존. 50개씩 과거 대화, 증분 수신, SSE 신호 + 4.5초 폴링 백업을 추가했다.
- **실제 기업 정보 금지**: SQLite 데모, 미검증 실명 사업자 확인, 라이브 PostgreSQL RLS, 악성파일 검사·운영 배포 미완.
- 본 자료는 GitHub main과 운영 배포에 반영하지 않은 격리 후보이다.

---

# JARVIS WORKS V2.0 — PostgreSQL Advanced Isolation Candidate (not deployed)

- Updated PostgreSQL synthetic policy/fixture: signed tenant context, 8 validated tenant-composite FKs, no audit/security event mutations by ordinary application role, privilege and `pg_temp` preflight, rebind resistance.
- Added a separate ephemeral PostgreSQL 17 GitHub Actions attack gate **to be run after a review-branch upload**. It has **NOT** been published to GitHub or executed; *live PostgreSQL tenant isolation = NOT RUN*.
- SQLite browser application, V1.6 quotation automation, MFA/backup security candidates are preserved; full PostgreSQL app adapter is **NOT IMPLEMENTED**.
- Read `V2_0_POSTGRES_SECURITY_REPORT.md` and `docs/V2_0_ISOLATED_PG_TEST_GUIDE.md` before any test or migration. **No real customer data.**

# JARVIS WORKS V1.8 — Security Hardening Candidate (not deployed)

- MFA authenticator setup now issues **8 single-use 128-bit recovery codes**. Hash-only server storage; codes displayed once. Login accepts a recovery code *instead of* OTP after password verification, consumes it atomically, rate-limits invalid attempts, and keeps tenant isolation. Code rotation requires password + fresh OTP or unused recovery code and revokes sessions.
- `scripts/secure_backup.py` creates encrypted, tamper-checked offline snapshots with a **separate** secret `JW_BACKUP_KEY` and no intermediate plaintext backup file. `scripts/backup_db.py` now delegates to this protected mode. **BACKWARD-INCOMPATIBLE: plaintext backup output is intentionally discontinued**. Restores are explicit and do not overwrite an existing target.
- `security/postgres_rls_proposal.sql` and `scripts/check_postgres_rls.py` provide a proposed PostgreSQL tenant policy and audit foundation. **They are NOT wired to the SQLite application, and have NOT been executed on PostgreSQL**. Real DB-enforced tenant read isolation is NOT IMPLEMENTED.
- `JW_ENV=PRODUCTION` and other casing variants now fail closed like lowercase `production`.
- Existing app remains an isolated **DEMO/LOCAL DEVELOPMENT CANDIDATE**, with full product deployment prohibited. Never enter real customer data. Read `SECURITY_V1_8_REPORT.md` for tests, limitations and deployment gates.

# JARVIS WORKS V1.7 — Security hardening candidate (not deployed)

**중요:** 이 코드는 기존 V1.6의 별도 보안 검증 후보입니다. GitHub main/V1.5/V1.6 브랜치, Codespaces, 운영 환경은 변경하지 않았습니다. **실제 기업 개인정보/기밀 사용 금지.**

이번 변경은 `SECURITY_V1_7_REPORT.md`에 상세 기술되어 있습니다.

- 회사 간 잘못된 DB 참조 관계를 거부하는 SQLite 트리거 (**조회 RLS 아님**).
- 개인별 TOTP MFA 등록·검증·재사용 차단 (`JW_DATA_KEY` 필요, 복구 수단 미구현).
- 파일 분석 별도 프로세스, CPU/메모리/시간 제한 (완전한 격리 컨테이너 아님).
- 선택적 ClamAV 악성파일 검사 (개발 기본값 검사는 꺼져 있음).
- 문서 추출 JSON 선택적 Fernet 암호화 및 백업 후 구 데이터 수동 암호화 이전.
- 운영 모드는 기업별 DB 조회 강제 격리 등의 보안 요건 미완성으로 시작 차단.

개발/시뮬레이션 테스트:

```bash
python -m pip install -r requirements-dev.txt
PYTHONPATH=. pytest -q
node --check app/static/app.js
```

기존 가상 데이터를 통한 데모 시작: `sh run_demo.sh`. MFA를 시험하려면 보안 키를 별도 설정해야 합니다. 데모 전용 서버/포트는 Private을 유지하세요.

---

# JARVIS WORKS V1.6 — Quotation SMART IMPORT (validation candidate)

**New:** PDF/XLSX quotation (`견적서`) upload → deterministic field verification → original document review → explicit approval → **draft quotation only**, with source provenance and strict duplicate controls. Existing automatic purchase order path, security center and dashboard are preserved. No automatic approval, order, invoice or money movement is implied by quotation import.

- Local QA: **120/120 pytest PASS**; desktop Chromium quotation import, purchase-order import, missing-fields flow, and old desktop/mobile quotation-to-payment regression PASS.
- Detailed scope, security limits and reproducibility: [`V1_6_DESIGN_AND_VERIFICATION.md`](V1_6_DESIGN_AND_VERIFICATION.md).
- This candidate is not deployed, not production-secure, and not suitable for real enterprise PII or accounting.

---

# V1.5 Automation-first UX candidate (not merged to main)

- The primary sidebar and initial landing page is **문서 업로드 · 자동 처리**; Dashboard has upload CTA.
- Safe tenant-filtered upload preview queue (`GET /api/imports/queue`), no source document bytes included.
- **Only structured order documents are actually imported today**; quote, delivery, invoice, payment are planned and explicitly unsupported rather than auto-recorded incorrectly.
- Read `V1_5_AUTOMATION_FIRST_DESIGN.md` for the approved end-to-end workflow and phased implementations.

# JARVIS WORKS — 웹 전용 B2B 업무관리 V1.4 보완 검토 후보

기업용 **거래처 → 견적 → 수주·발주 → 문서 간 차이 검증 → 청구·입금 → 대시보드** 웹앱입니다. 기업 PC의 Chrome·Edge 등 웹 브라우저를 주 사용 환경으로 하는 한국어 화면을 제공합니다. 앱 설치는 필요하지 않으며 개발·관리 작업은 모바일 브라우저에서도 진행할 수 있습니다. 계정·거래 문서는 현재 API 수준에서 **회사 ID 필터로 논리적으로 분리**합니다. 물리적인 회사별 DB 분리는 아직 구현되지 않았습니다.

> **제품 분류: 웹 전용 시연/로컬 검증용 MVP, 실제 기업 개인정보 투입 금지.** 금융·회계 결산 프로그램, 국세청 전자세금계산서 발행기 또는 은행 계좌 조회기가 아닙니다. 외부 보안 감사, 실사용자 부하 시험, 서버 운영 배포는 아직 진행되지 않았습니다. 실제 고객 정보나 영업상 비밀로 데모를 시험하지 마세요. 기본 로그인 쿠키는 HTTPS만 사용하며, `sh run_demo.sh`는 **localhost에서만** 안전하지 않은 HTTP를 허용합니다. 외부 포트 공개를 금지합니다.

## V1.4 검증 후보 — 원본 누락 정보 보완 / 발주 중복 차단

- 출처·총액·품목별 금액·문서 종류를 검증할 수 있는 정형 엑셀/텍스트 PDF에서 **거래처명·수주일·납기일** 중 누락된 값만 사용자 보완 대상으로 제공합니다.
- 보완 전에는 발주/견적/거래처를 생성할 수 없고, 보완 후 서버 재검증과 새 검토 식별 해시가 발급됩니다. 이전 버전 확인은 무효가 됩니다.
- 원본에서 읽은 수량·품목·단가·금액·과세 정보는 검토 화면에서 수정할 수 없습니다. 금액이 틀리면 올바른 원본 파일로 다시 업로드해야 합니다.
- 재업로드 파일명이 다르더라도 **같은 회사·외부 발주번호**가 이미 등록돼 있으면 중복 생성을 차단합니다. 파일 자체 SHA-256 중복 검사도 유지합니다.
- 표에 모르는 추가 열이 있는 경우 조용히 버리지 않고 차단하며, 표 제목/날짜의 안전한 한국어 동의어를 보강했습니다.
- 품목별 수주 집계는 품목코드가 동일해도 이름이 다른 경우 분리하며, 단위가 섞인 수량에 일괄 `개`를 붙이지 않습니다.
- `V1_4_DESIGN_AND_VERIFICATION.md`에 적용 범위와 미구현, 테스트 결과가 있습니다. 현재 사용 중인 Codespaces 서버에 자동 반영되지는 않습니다.

## V1.3 검증 후보 — SMART IMPORT (2026-10-18, 로컬만 적용)

- `.xlsx` / 검색 가능한 `.pdf` 발주·주문·수주 문서 업로드 → 필수항목 추출 → 정수 KRW 재계산 → 사용자 원본 확인 → 승인 후에만 발주·거래처 및 집계 생성.
- 지원하는 추가 필드: 발주번호, 프로젝트명, 납품장소, 담당자, 결제조건, 특기사항, 품목코드, 규격, 단위.
- 회사·수주일·납기일·품목별·단위별 주문량과 금액 집계. 미지원 문서·숫자 오기재·미인식 추가 필드는 **추정하여 통과시키지 않고 차단**.
- 테스트: 자동 73건 PASS, 동일 샘플 PDF/XLSX 동등 추출 PASS, PC 브라우저 업로드→검토→확인→발주 생성 PASS. 테스트 범위 이외의 100% 인식 정확도는 보장할 수 없음.
- 자세한 제약/증거: `V1_3_DESIGN_AND_VERIFICATION.md` / `samples/` / `proof/` 참조.
- **현재 GitHub main 또는 Codespaces 실행본은 자동 변경하지 않았습니다.** 배포 전 회사별 격리·MFA 등 운영 보안 확보가 필요합니다.

## V1.2 신규 기능 (해외 ERP·재무 SaaS 패턴 연구 후 독립 구현)

- **관리자 전용 보안 관제 센터:** 소속 계정 목록, 유효 접속 세션, 최근 보안 이벤트 및 로그인 실패 통계 조회. 다른 기기/직원 세션을 관리자 권한으로 종료 가능. **MFA·DB 강제 격리·IP 위협 탐지는 아직 구현하지 않았습니다.**
- **목록 검색·필터:** 현재 화면에 로드된 거래처·견적·발주·청구·변경이력 검색, 상태별 필터, `/` 키 검색 바로가기. 서버 전체 DB 검색은 아직 미지원.
- 해외 벤치마킹 근거 `BENCHMARK_2026_10.md`, 검증 증거 `V1_2_RELEASE_REPORT.md` 및 반응형 실제 브라우저 미리보기 `previews/` 참고.

## 제공 기능 6개

1. **거래처 관리:** 기업명·사업자번호·담당자·연락처의 등록·수정, 기존 거래 연결 보존.
2. **견적 관리:** 품목별 수량·정수 KRW 단가, 견적 초안·발송·승인, 인쇄/PDF 저장, 원본 금액 보존.
3. **수주·발주:** 승인 견적에서 발주 생성, 납품일·진행 상태, 변경 사유 기록, 납품 완료 처리.
4. **문서 검증:** 견적↔발주의 품목명·수량·단가 누락/추가/차이를 표시하고, 변경 내역 확인 전 완료·청구를 제한.
5. **청구·입금:** 발주 기반 청구서 생성, 기한·부분입금·미수금, 중복 입금 차단, 관리자 입금 기록 취소 및 감사 이력.
6. **대시보드:** 거래 건수, 누적 입금, 미수금, 납기·입금 지연 및 변경 확인 대기 표시.

**금액 정책:** 수량과 가격은 정수, 합계는 `수량 × 단가`의 합, 부가세 과세를 선택한 경우 공급가액 합계의 10%를 원 단위 반올림(ROUND_HALF_UP)합니다. 면세는 부가세 0원입니다. 실제 세무 계산 방식은 기업과 세무 전문가의 확인이 필요합니다. 계산값은 서버 DB의 거래 항목에서 다시 산출되며 브라우저의 값은 미리보기로만 사용됩니다. 

**원본 보존:** 문서가 승인/발행되면 품목 변경이 제한됩니다. 거래처 상호가 바뀌더라도 기존 문서는 작성 시점의 거래처명 스냅샷을 유지합니다. 과거 버전 DB에서 옮긴 문서는 이전 상호 이력을 알 수 없어 마이그레이션 시점의 거래처명으로 초기화됩니다.

## 즉시 실행 (GitHub Codespaces 또는 Linux)

```bash
python -m pip install -r requirements.txt
sh run_demo.sh
```

브라우저에서 포트 `8000`을 열고 로그인합니다. 데모 계정은 **한빛테크** `demo@hanbit.example`, **바다유통** `demo@bada.example`, 공통 비밀번호는 `Demo!2026secure`입니다. 두 회사의 데이터는 서로 보이지 않습니다. 이 비밀번호는 반드시 데모 환경에서만 사용합니다.

개발·관리 작업은 iPhone + Safari의 Codespaces로도 진행할 수 있습니다. 실제 직원 사용 환경은 인터넷 접속이 가능한 회사 PC의 웹 브라우저입니다. 별도 설치 앱은 만들지 않습니다. Codespaces로 진행한다면, 먼저 GitHub 비공개 저장소에 이 ZIP을 풀어 올려 Codespace를 실행하고 터미널에서 위 두 줄만 실행합니다. **PORTS → 8000 → 브라우저 열기**를 탭하면 시연할 수 있습니다. 외부에 포트를 공개하지 마세요.

## 웹 보안 V1.1 변경사항 (보존)

- 로그인 인증을 브라우저 `sessionStorage`의 Bearer 토큰에서 서버 관리 세션과 `HttpOnly; Secure; SameSite=Strict` 쿠키로 변경했습니다. 로그인 응답은 세션 비밀 값을 반환하지 않습니다.
- 모든 인증된 상태 변경 요청에 CSRF 토큰을 요구합니다. `Origin`과 `Sec-Fetch-Site` 검사도 적용했습니다. HTTPS 접속에는 HSTS, 콘텐츠 보안정책(CSP), 클릭재킹 방지 헤더 등을 보냅니다.
- 로그인 세션은 서버에서 12시간 상한을 갖고, 로그아웃 시 서버에서 무효화합니다. 기존 Bearer 세션은 더 이상 허용하지 않습니다. 이전 DB 파일을 사용해도 거래 내역은 유지하고 기존 세션은 폐기합니다.
- 신규 거래처 감사 로그에는 이메일·담당자·전화번호의 원문을 중복 기록하지 않습니다. **이전 버전에 이미 저장된 감사 로그의 개인정보는 자동 삭제하지 않았습니다.** 삭제·보존 정책과 승인 절차는 따로 필요합니다.
- `JW_ENV=production`에서는 데모 사용자 시드 및 안전하지 않은 개발 쿠키 모드를 차단합니다.
- **미구현 보안 핵심:** MFA/패스키, 직원별 세분 권한, 회사별 DB 차단계층(RLS/전용 DB), 저장 데이터 암호화·키 관리, IP별 차단/WAF, 자동화된 침입 탐지, 자동 백업/복구 훈련 및 보안 진단. 아래 `SECURITY_DESIGN.md` 참고.

## 데모가 아닌 로컬 파일럿 (관리자 1명 초기 생성)

`DEMO_SEED`를 설정하지 않은 상태에서 **첫 실행 전에** 아래 환경변수를 지정합니다.

```bash
export BOOTSTRAP_ORG='회사명'
export BOOTSTRAP_EMAIL='admin@example.com'
export BOOTSTRAP_PASSWORD='12자 이상 임의의 강한 비밀번호'
export JARVIS_DB_PATH='/비공개/영속저장소/works.db'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

외부 웹 공개 전에 다음 요건을 충족해야 합니다. 실제 외부 서비스 운영은 TLS/HTTPS, 비밀번호 관리, 안전한 서비스 배포, 접근 제어, 백업 복구/암호화, 모니터링, 개인정보 고지 및 권한 관리가 완료된 후에만 진행해야 합니다. SQLite 파일은 서버 영속 디스크에 위치시켜야 하며, 휘발성 컨테이너만으로 운영하면 재시작 시 유실될 수 있습니다.

## 검증 명령

```bash
python -m pip install -r requirements-dev.txt
PYTHONPATH=. pytest -q
node --check app/static/app.js
# Chromium + Playwright가 설치된 테스트 환경에서만:
PYTHONPATH=. python tests/browser_smoke.py
```

## 로컬 데이터 백업

```bash
python scripts/backup_db.py
```

V1.8부터 백업은 **JW_BACKUP_KEY 별도 암호화 키가 없으면 실패**하며, `.jwbackup` 암호화 파일만 생성됩니다. 같은 키를 별도 보안 저장소에 보존하지 않으면 복원할 수 없습니다. 데이터베이스 크기 48MiB 이내의 로컬 후보 전용 구현이며 자동 백업·키 회전·운영 복구 훈련은 미구현입니다.

```bash
python scripts/secure_backup.py restore backups/<백업명>.jwbackup /별도/복원/works.db
```

실제 운영용 PostgreSQL과 별개이며 현재 라이브 SQLite DB는 평문 상태입니다.

## 현재 한계 및 추가 개발 조건

- 인보이스는 **업무용 청구서**이며 국세청 전자세금계산서 발급 기능이 아닙니다.
- 은행 API, 계좌 입금 자동 대사, 전자서명, AI OCR, PDF 파일에서의 구조화 데이터 추출은 없습니다.
- 현재 관리자 전용 직원 목록은 **읽기 전용**입니다. 직원 초대·초기 비밀번호 재설정·역할 변경 UI는 아직 없습니다.
- 국내 다수 기업의 실제 양식, 복잡한 할인·선금·부분납품·반품·외화·세율 변경 사례는 검증되지 않았습니다. 한 발주당 청구서 한 장만 지원합니다.
- 관리자 입금 취소는 **계좌 환불이 아닌 기록 정정**입니다. 추가 금융 송금을 수행하지 않습니다.
- 데모 계정과 데이터는 운영 시스템에 혼합하면 안 됩니다.
- 서버 테스트와 Chromium 데스크톱·모바일 뷰포트의 UI 시뮬레이션을 검증했습니다. **iPhone Safari 실기기 검사 / 고객사 실데이터 시험 / 운영 배포는 NOT RUN**입니다.

## 차별화 기능 확장 원칙

첫 고객사 인터뷰 후, 가장 많이 발생하는 오류와 반복 입력 시간을 먼저 측정합니다. PDF·엑셀 자동 추출, 외부 ERP 연결, 다단계 승인, 계약 관리, 거래 위험 알림 고도화는 유료 수요가 확인될 때 별도 버전으로 추가합니다. 기존 6개 기능과 저장 데이터의 호환성을 보존합니다.

## 저장소 및 배포 준비

- `docs/DEPLOYMENT_READINESS.md`에 운영 전 필수 보안·데이터 관리·테스트 체크리스트를 정리했습니다.
- GitHub 저장소는 **Private**로 유지합니다. 소스 게시와 실제 인터넷 서비스 공개는 별도 작업입니다.
- 운영 배포 전 MFA, RLS 또는 기업별 전용 DB, 직원 관리/권한, HTTPS 쿠키, 암호화·복구, 보안 진단을 선행해야 합니다.
- 로그인 HTML의 데모 자격증명 기본값은 제거했습니다. 데모 모드에서 테스트 계정을 선택하는 버튼은 남아 있습니다.

## V1.9 PostgreSQL tenant isolation — advanced security candidate (NOT DEPLOYED)

- Replaced the previous **forgeable `jw.org_id` policy** with a transaction-scoped HMAC-validated identity claim. See `security/postgres_rls_proposal.sql` and `docs/V1_9_RLS_HARDENING.md`.
- Added strict catalog audits, an isolated synthetic schema fixture and runnable adversarial PostgreSQL integration test script (requires a separately provisioned throwaway PG server and two test DSNs).
- **PostgreSQL is not installed or connected to the FastAPI runtime in this environment.** Live RLS tests and tenant DB migration are **NOT RUN**. SQLite production-start prevention remains active. Never represent this as production-isolated or ready for real company data.

## V2.2 candidate: company-to-company trade messenger (local demo only)

- Verified demo companies can request/accept a trade chat; organization names are displayed.
- Text messages are append-only evidence with restricted editing for 30 minutes and preserved revisions. No ordinary delete API.
- Approved connections can exchange a structured, immutable snapshot of an existing purchase order only if the legal receiver's business number matches the order's customer. Receiver acknowledgment does not execute accounting or legal approval.
- **Not production:** business identity verification/onboarding, independent employee approver signatures, PDF attachments, realtime push and PostgreSQL live RLS validation are not completed. See `V2_2_MESSENGER_DESIGN_AND_VERIFICATION.md`.

### V2.3 simplified company messenger (review candidate)
Company search and scroll with server pagination, instantaneous chats between verified companies, minimal message bubbles, `+` photo/file/purchase-order menu, polling of the active conversation, audited text edits for 30 minutes and immutable attached evidence are available in isolated demo/test mode. A chat message is not acceptance or a confirmed financial transaction. See `V2_3_MESSENGER_UI_VERIFICATION.md` for test results and production blockers.

## V2.9–V3.4 continuous integration candidate (local review only)

- Staff suspension/restoration is now available in the **security center**; administrator password reauthentication is required; sessions are immediately revoked and never resurrected. The original 7-column user schema is preserved by a dedicated staff-status table.
- The new `app/pg_messenger_review.py` is **not connected to FastAPI or any production PostgreSQL database**. Only localhost, disposable PostgreSQL 17 CI DB and restricted test role are permitted if psycopg is independently installed.
- `tests/test_staff_lifecycle_v29.py`, `tests/test_pg_review_adapter_v30.py`, `tests/test_recovery_drill_v32.py` and `tests/browser_staff_v29.py` cover this development candidate. See `docs/V3_INTEGRATION_READINESS.md` for all unfinished release blockers and the actual verification report for measurements.
- **Do not use real business data, install this as a production service, or treat offline RLS tests as live PostgreSQL authorization proof.**
