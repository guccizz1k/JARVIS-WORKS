# JARVIS WORKS V2.6 — 기업 메신저 영속 순서·동시성·회귀 검증

**날짜:** 2026-10-19 (Asia/Seoul)  
**제품 상태:** 격리된 로컬 후보. GitHub 원본 및 운영 배포 변경 없음. **실제 기업 데이터 입력 금지.**

## 1. 기존 상태·원본 보호

- 기반 후보: `JARVIS-WORKS-V2.5-PAGINATION-SSE-REVIEW-CANDIDATE.zip` (읽기 전용 원본으로 유지).
- 보호 기능: 거래처·견적·발주·문서 비교·청구·입금·대시보드·보안 관제·MFA 후보·기존 문서 import, 회사 메신저/검색/사진·파일/발주서/메시지 편집 감사 이력/읽음 커서/SSE 재연결·폴링.
- 기존 소스 변경: `app/messenger.py` (영속 순번, 읽음 위치 이전, 목록 정렬, 고정밀 생성시각), `README.md`만. V2.5의 나머지 원본 파일/기존 스크린샷은 바이트 그대로 보존.
- 신규: `tests/test_messenger_v26.py`, `proof/v26_messenger_1440px.png`, `proof/v26_messenger_390px.png`, `proof/v26_pytest_214.log`, `V2_6_EVIDENCE_SHA256.txt`, 본 보고서.
- 원격 GitHub push, PR, merge, Codespaces 쓰기, 외부 서버 운영, 유료 빌드 **NOT RUN**.

## 2. 결함 원인과 해결

1. **SQLite `rowid` 의존성:** 기존 V2.5의 메신저 페이지네이션·읽음 위치는 `rowid`를 이용했다. 메시지 키가 TEXT PRIMARY KEY이므로 SQLite `VACUUM`·덤프/재구성 과정에서 `rowid` 순서가 바뀔 수 있어 기존 증빙 커서에 안정성이 없었다.
2. **영속 메시지 시퀀스:** `messenger_messages.message_seq`를 추가하고 기존 메시지를 원래 `rowid` 오름차순으로 한 번만 이전한다. 신규 메시지는 DB AFTER INSERT 트리거가 동일 SQLite 쓰기 트랜잭션 안에서 유일한 증가 순번을 할당한다. UNIQUE/조회 인덱스와 수정 차단 트리거를 추가했다. 재실행 때 기존 순번은 재할당하지 않는다.
3. **읽음 커서 보존:** `messenger_read_positions.last_read_seq`로 전진 이전한다. 기존 `last_read_rowid`는 호환용 열로 유지하되 신규 판정에 사용하지 않는다. 기존 행의 원래 `rowid`가 아직 유효할 때 메시지 순번으로 매핑한다. 일치하지 않는 이전 위치는 보수적으로 0으로 처리한다. 읽음 역행은 허용하지 않는다.
4. **대화방 시간 동률:** 기존 메신저 V2.4 정렬 테스트에서 두 개 이상의 대화가 같은 초에 생성될 경우 순서가 불안정했다. 대화별 `connection_seq`를 추가하고 고정밀 시각(새 대화/신규 전송만)을 기록해 최신 활동과 생성 순서를 일관되게 정렬한다.
5. **API 정보 최소화:** 영속 내부 메시지 순번은 응답에 공개하지 않는다. 클라이언트 커서는 기존과 동일한 메시지 UUID를 사용하며, UUID는 반드시 인증된 본인 대화에 속해야 한다.
6. 기존 메시지/첨부/발주서의 원문, 기존 문서 금액, 메시지 수정 내역, 기업별 접근권한은 재작성하거나 삭제하지 않았다.

## 3. 5-Gate 검증

| Gate | 결과 | 근거 |
|---|---|---|
| 1. 코드·환경 | PASS | `python -m compileall -q app`, `python -m py_compile tests/test_messenger_v26.py`, `node --check app/static/app.js` |
| 2. 기능 정확성 | PASS (선정 범위) | 신규 V2.6 7개 테스트: 177건 메시지 순번·페이지·읽음 유지, 80건 8-worker 병렬 전송, 기존 V2.5 SQL DB 순방향 마이그레이션, 동일 시각 대화방 정렬, UUID 커서·테넌트 조회 제한, 수정 이력/불변 검증 |
| 3. 데이터·회귀 | PASS (로컬 테스트) | 전체 Python 테스트 결과는 아래 실행 로그의 최종 값을 기준으로 한다. SQLite `VACUUM`, 온라인 백업, 설치 재실행, 읽음 증가/역행 방지, INSERT 직후 순번 자동 할당을 검사 |
| 4. UI/UX | PASS (Chromium 시뮬레이션) | `tests/browser_messenger_v25.py`를 변경된 백엔드로 재실행. 데스크톱 1440×900, 모바일 390×844. 과거 50개씩 더 불러오기, 타기업 메시지 갱신, 입력 초안·스크롤 유지. **실제 iPhone Safari/고객사 PC 아님** |
| 5. 운영·보안 | PARTIAL/BLOCKED | SQLite 단일 로컬 파일 동시 쓰기와 테스트 픽스처 격리만 검증. 실제 PostgreSQL 17 RLS, 수평 확장/원격 SSE/프록시, 대량 동시 기업 부하·운영 SLA, 실사업자 인증, 보관·법정 삭제, 백신/CSP/CDR, 개인정보 규제 준수는 미검증 |

### 자동 테스트 결과

- V2.6 메신저 신규 테스트: **7/7 PASS**.
- V2.2~V2.6 메신저 테스트: **35/35 PASS**.
- **전체 Python 자동 테스트: 214/214 PASS** (`proof/v26_pytest_214.log`: `214 passed in 106.13s`). 전체 테스트 중 외부 서버 및 PostgreSQL 실제 격리·공개망 스트리밍은 포함되지 않는다.
- Chromium: **PASS** (기존 V2.5 DOM/API 브리지, 변경된 V2.6 서버 사용). JPEG/실사용 기기 네트워크 속도를 측정한 결과가 아님.

### 재현 명령

```sh
python -m compileall -q app
python -m py_compile tests/test_messenger_v26.py
node --check app/static/app.js
PYTHONPATH=. pytest -q tests/test_messenger_v22.py tests/test_messenger_v23.py tests/test_messenger_v24.py tests/test_messenger_v25.py tests/test_messenger_v26.py
PYTHONPATH=. pytest -q
PYTHONPATH=. python tests/browser_messenger_v25.py
```

## 4. 데이터 이전·복구 조건 및 미완료 사항

- 기존 DB는 **백업과 복원 시험이 끝난 격리 사본**에서만 V2.6을 실행해야 한다. 순번을 만들 때 현재 `rowid`를 참조하므로, 순번 이전 전에 무단 `VACUUM`을 수행해서 원래 읽음 커서를 훼손한 DB를 자동 복구하지 못한다.
- 트리거는 서버 SQLite 쓰기 경쟁을 직렬화한다. 별도 호스트의 데이터베이스 공유, 여러 애플리케이션 서버의 고가용성, 네트워크 지연, 초당 처리량/최대 동시 기업 수를 증명하지 않는다.
- 소스는 여전히 데모 SQLite 메신저다. 실 PostgreSQL RLS에 메시지·첨부를 연결한 구현은 별도 선행 개발과 라이브 테넌트 공격 테스트가 필요하다.
- 기존 `last_read_rowid`를 보존하지만 V2.6부터는 `last_read_seq`만 판단에 사용한다. 메시지는 삭제할 수 없으며 법정 정정/삭제 요청과 증빙 보존의 충돌은 사업자 정책 및 법률 검토가 필요하다.
- V2.5의 SSE·4.5초 폴링 구조 자체는 재구현하지 않았다. 실 네트워크 WebSocket 실시간 보장이라고 표현하지 않는다.
- 화면 캡처: `proof/v26_messenger_1440px.png`, `proof/v26_messenger_390px.png`. 캡처 생성은 실제 Chromium이지만 실제 인터넷 배포가 아니다.

기존 `MANIFEST.sha256` 및 버전별 이전 검증 자료는 이력 증빙으로 보존되며, V2.6 변경분에 대한 검증용 해시는 별도 `V2_6_EVIDENCE_SHA256.txt`를 사용한다.

**출시 판정: PARTIAL.** 로컬 구현·검증 후보이며, 실제 기업 등록·동시 운영·안전 저장소·데이터 격리·실기기 검증 및 승인된 배포가 완료되기 전 상용 출시하지 않는다.
