# JARVIS WORKS V2.4 — 메신저 사용성·읽음 상태 강화 후보 검증

**기준 원본:** 2026-10-19 Library의 `JARVIS-WORKS-V2.3-SIMPLE-MESSENGER-REVIEW-CANDIDATE.zip`. GitHub `guccizz1k/JARVIS-WORKS`의 `main`은 2026-10-19 확인 시 V1.2.0이며, 이 파일은 GitHub에 게시하지 않은 **격리 후보**이다. 타 프로젝트/원본 저장소/운영 서버/실 고객 데이터는 수정하지 않았다.

## 목적 및 확정 계약 보존
- 기업명 검색과 스크롤 탐색, 기업 클릭 즉시 채팅, `+` 사진/파일/발주서, 메시지·원본 첨부·수정 이력 보존, 삭제 불가, 30분 텍스트 수정, 기업 간 파일 접근 통제를 보존했다.
- 메신저에서 상대 승인 없이 대화한다는 요구는 지켰다. **견적·발주·청구 등 금전적 거래의 별도 승인 절차는 제거하지 않았다.**
- 수신 동기화는 4.5초 폴링이다. WebSocket 실시간 푸시와 운영체제 알림은 새로 구축하지 않았다.

## V2.4 실제 변경
1. `app/messenger.py`: 기업별 읽음 커서 `messenger_read_positions`를 **추가형** SQLite 스키마로 설치; 대화 목록 API에 상대 회사 메시지의 읽지 않은 수 추가; 최신 활동 우선 정렬(동일 초 시간 충돌에서는 메시지가 있는 대화를 우선하고 thread rowid 순서 사용); 서버에서 인증된 본인 대화의 메시지 ID만 읽음 확인할 수 있는 POST `/api/messenger/threads/{connection_id}/read` 신설. 커서의 단조 증가 보장, 다른 기업 접근·다른 대화 메시지 ID 거부.
2. `app/static/app.js`: 대화 목록에 최대 `99+` 읽지 않음 숫자 배지; 화면 진입 시 최신 메시지까지 자동 스크롤; 메시지 보기 또는 끝까지 스크롤했을 때만 읽음 확인; 수신 폴링 도중 사용자의 초안·스크롤 보존.
3. `app/static/style.css`: 읽지 않음 배지와 사이드바 내부 세로 스크롤 보강. 기존 사이드 메뉴가 뷰포트 아래로 밀려 직접 클릭할 수 없던 문제 해결.
4. `app/static/index.html`: 후보 버전 표시 갱신.
5. 신규 `tests/test_messenger_v24.py`, `tests/browser_messenger_v24.py`; proof 이미지 2장.

## 5-Gate 실제 증거
| Gate | 판정 | 수행 내역 |
|---|---|---|
| 1. 문법·환경 | PASS | Python `compileall -q app`, Node `--check app/static/app.js` |
| 2. 메신저 기능 | PASS | V2.2+V2.3+V2.4 합계 **20/20**: 수신자 읽지 않음, 읽음 커서 단조 증가, 스크롤/검색, 중복·수정·첨부/발주 전달 회귀 등 |
| 3. 보안·회귀 | PASS (선정 범위) | 세션/CSRF/테넌트 격리·문서 업무·PostgreSQL **오프라인 정책** 테스트 **76/76**. PostgreSQL 라이브 DB 연결 증거 아님. |
| 4. 브라우저 UI | PASS (로컬 브리지) | 실 Chromium 1440×900/390×844, 실제 HTML/CSS/JS + FastAPI TestClient 통신 브리지. 메뉴 클릭, 채팅 12건 최하단 표시, 읽음 갱신, 기업 검색, `+` 메뉴. `proof/v24_messenger_1440px.png`, `proof/v24_messenger_390px.png`. 실제 운영 HTTP/실기기 시험 아님. |
| 5. 배포·운영 | BLOCKED | 실제 기업 등록 인증, PostgreSQL RLS live 공격시험, MFA/암호화, 악성코드 스캐닝, 보호되는 파일 저장소·백업·보관 정책, iPhone Safari 실기기 및 운영 배포 미완. |

### 부분 실행 및 제한
- 전체 `pytest -q` 일괄 실행은 제한 시간 내 종료하지 못했다. 따라서 **전체 프로젝트 테스트 PASS를 주장하지 않는다**. 특히 기존 import 테스트 묶음의 장시간 실행 원인 분석은 남아 있다.
- UI는 Chromium 자동화 환경의 **in-process API 브리지**를 사용했다. 인터넷을 통한 운영 배포나 사용자의 iPhone Safari에서 측정한 결과가 아니다.
- 메시지 읽음 표시란 회사 계정 기준의 **보기 커서**이지 법적 수신 확인이나 거래 승인이 아니다.
- 메시지 목록은 기존대로 최근 100건 조회, 대화 목록은 최근 200개. 전체 과거 메시지 탐색/대화 무한 스크롤은 미완이며, 다량 수신 시 과거 100건 모두를 볼 수 없을 수 있다.
- 데모 첨부는 기존 SQLite BLOB/5MiB/회사 40MiB 제한. 악성 파일 진단이나 파일 무해화를 수행하지 않는다.

## 결과 및 실행 순서
**전체: PARTIAL / 로컬 V2.4 후보 보존 완료 / GitHub push·PR·운영 배포: NOT RUN.**
1. 다음 개발 우선순위: 오래된 메시지 페이지 조회와 기업별 메시지 부하 시험; 테스트 전체 수행의 장시간 정체 원인 제거.
2. 운영 전 필수: 기업 실명 검증과 1개 기업 다계정 방지 정책, PostgreSQL RLS live 공격 검증, 파일 보안 저장소·스캐닝·보관·백업·접근 감사, 실제 고객사 PC 브라우저 시험.
3. 이후: WebSocket/SSE 또는 신뢰성 있는 푸시 및 여러 사용자의 다기기 동기화. **사용자 명시 승인 전 GitHub 게시 및 운영 공개 금지.**

## 재현 명령
```sh
python -m compileall -q app
node --check app/static/app.js
PYTHONPATH=. pytest -q tests/test_messenger_v22.py tests/test_messenger_v23.py tests/test_messenger_v24.py
PYTHONPATH=. pytest -q tests/test_security.py tests/test_security_center.py tests/test_workflows.py tests/test_pg_rls_v19.py tests/test_pg_rls_v20.py tests/test_pg_rls_v21.py
PYTHONPATH=. python tests/browser_messenger_v24.py
```
