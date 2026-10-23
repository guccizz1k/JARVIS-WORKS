# JARVIS WORKS — 기업 PC 웹서비스 배포 준비

상태: 로컬 검증용 데모. 운영 환경 **미배포**.

## 확정 운영 환경
- 사용자: 기업 직원, 인터넷 연결된 PC 브라우저 (Chrome, Edge)
- 서비스: HTTPS 웹사이트, 앱 설치 없음
- 개발자: GitHub/Codespaces 등 브라우저 기반 관리 가능
- 저장소: 비공개. 실제 회사 정보·API 키·데이터베이스 파일은 Git에 넣지 않음

## 운영 공개 전 차단 조건
1. 기업별 데이터 접근을 서버/DB 계층에서 강제 (예: PostgreSQL RLS). 테넌트 교차 접근 공격 테스트 필요
2. 직원 초대·탈퇴·권한 회수, 관리자 MFA 적용 및 계정 복구 정책
3. HTTPS, 세션 쿠키, CSRF, CSP, 로깅, 속도 제한, 보안 설정 독립 평가
4. 데이터 암호화/키 교체, 별도 암호화 백업, 실제 복구 연습 및 목표 RPO/RTO 확정
5. 운영·테스트 분리, 시크릿 매니저, 모니터링/알람, 접근 로그 최소수집·보관/파기
6. 계약/개인정보 처리 방침과 위탁/국외 이전 등 법적 의무 검토
7. 실 브라우저·실 데이터 양식 검증, 외부 보안 진단, 장애 복구·성능 시험

## 현재 테스트 명령 (로컬만)
```sh
python -m pip install -r requirements-dev.txt
PYTHONPATH=. pytest -q
node --check app/static/app.js
```

## 다음 안전한 실행
- GitHub 소스 확인
- Codespaces에서 private port 8000 로 데모 수행. **Public 포트 전환 금지.**
- 운영 환경은 별도의 설계/검증 이후 승인받고 배포


## V1.7 hard stop

`JW_ENV=production` explicitly fails on startup even with a valid MFA key and antivirus because database-enforced tenant read isolation and other critical controls are not implemented. This must **not** be bypassed with a different environment name to serve real customers.

`JW_DATA_KEY` must be a secret-manager-supplied Fernet key, identical across workers and backups. Loss of this key makes already encrypted import metadata and MFA credentials unrecoverable. Key rotation and MFA recovery are outstanding.

For historical source JSON stored before encryption, stop the service, take an additional offsite encrypted backup, then run `PYTHONPATH=. python scripts/migrate_evidence_encryption.py` with `JARVIS_DB_PATH` and `JW_DATA_KEY`. The script refuses to overwrite its `.pre-encryption.bak` backup and verifies SQLite integrity. Keep that backup protected, as it contains plaintext historical data.

Do not claim ClamAV is deployed unless `JW_UPLOAD_SCAN=clamav` and successful scanner/virus-definition checks have been demonstrated. Default development mode (`off`) does not perform malware scanning.

## V1.9 advanced RLS release blocker

The V1.8 policy based only on writable `jw.org_id` was forgeable by SQL injection and has been replaced **in this V1.9 candidate only**. The PostgreSQL policy now requires an MFA-bound, transaction-specific DB-signed tenant claim. SQLite application remains unchanged and production-blocked. **No PostgreSQL server was available in the working environment:** policy syntax, functional SQL behavior, transaction pool reuse, schema migration, and cross-tenant integration are NOT RUN. Do not enable external traffic or import real data. See `docs/V1_9_RLS_HARDENING.md`.
