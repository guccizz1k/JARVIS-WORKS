# JARVIS WORKS V8.6 — PostgreSQL 이행 사전검사

## 기능·범위

- 기존 `app/main.py` **무변경**, 기존 SQLite 실행 동작 변경 없음.
- `app/pg_cutover_gate_v86.py`: 소스 SQLite 스냅샷을 읽기 전용 연결로 검사. 메타데이터, 외래키, 인증/세션 스키마, 사용자 중복, 260k PBKDF2-SHA256 호환성, 해시 형식 및 조직 참조 일관성 확인.
- `scripts/check_pg_v86_cutover.py`: SQL 비실행/비파괴 명령형 준비 상태 보고서. 보고서에 원본 이메일·비밀번호 해시·MFA 암호문·세션 토큰·DB 접속 문자열·파일 경로를 출력하지 않음.
- `preflight_live_connections`: 독립된 인증/거래 PostgreSQL 연결 각각에 `sslmode=verify-full` 적용. 세션 로그인 역할의 권한, 교차 역할 사용 권한, 민감 테이블 직접 접근, PG17 및 실제 TLS 여부 읽기 전용 검증.

## 실제 검증과 구분

- 별도 `jw_auth_stage_v85`와 `jw_app_dev`는 **NOLOGIN**, 서버용 LOGIN 계정은 미구성. 인증·거래 네트워크 통합을 PASS라고 할 수 없음.
- 자동화된 더미/모의 커넥터 테스트는 실제 TLS/DB 연결의 대체 증거가 아님.
- 원본 고객 SQLite 스냅샷이 없으면 마이그레이션 사전검사는 BLOCKED.
- SQLite 기존 세션 토큰은 마이그레이션을 **수행하지 않음**. 계정 정보 이전·쿠키 재발급·사용자 재로그인에는 별도 승인과 독립 백업·복구 검증 필요.
- V8.5 서버 인증 함수는 비밀번호/OTP 검증을 애플리케이션에 의존하므로 제한된 인증 로그인 유출 방지·비밀 저장·IP별 속도 제한·실 TLS E2E 테스트 없이 운영 연결 금지.
- 기존 `jw_dev` 정책·트리거를 삭제하거나 RLS를 비활성화하지 않음.

## 자동 검사 실행

```bash
# 민감 정보 없는 사전검사 보고서: 누락된 입력은 BLOCKED로 보고
python scripts/check_pg_v86_cutover.py

# 스냅샷이 준비된 경우에만 원본 읽기 전용 검사
python scripts/check_pg_v86_cutover.py --sqlite-snapshot /secure/local/snapshot.sqlite

# 비밀 관리자에 서로 다른 인증/거래 로그인 DSN이 구성된 경우에만
python scripts/check_pg_v86_cutover.py --check-connections
```

두 DB 연결은 앱 서버 환경 변수 `JW_PG_AUTH_STAGE_DSN`, `JW_PG_STAGE_DSN`을 사용하며, **절대 채팅·로그·ZIP에 값을 기록하지 않는다**. 라이브 DB 연결 시험은 서버 네트워크에서 실시해야 한다.

## 변경 제한

GitHub 원격, 운영 앱, Supabase 인증/업무 데이터, 역할 권한을 변경하지 않았음. `jw_dev` 운영/출시 전환은 BLOCKED.
