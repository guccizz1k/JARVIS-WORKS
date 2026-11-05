# CINEMA PG — P1(S4 이중 원장 클레임) · P2(로그인 역할) 설치 · 롤백 · 복구 절차서

상태: **후보(미적용)**. 개발 DB·운영 DB 어디에도 적용되지 않았다. 이 문서의 모든 실행 단계는 별도 사용자 승인 후에만 수행한다.
대상 파일: `scripts/review/cinema_pg_s4_dev_migration.sql`, `cinema_pg_s4_dev_rollback.sql`, `cinema_pg_p2_login_role.sql`, `cinema_pg_p2_login_role_rollback.sql`

## 1. 적용 전 승인 조건 (모두 충족해야 함)

1. 실제 PostgreSQL 17 CI(`jw-cinema-pg-p1-p2-pg17.yml`)가 해당 SHA에서 성공했다. (PG16 로컬 결과는 보충 증거일 뿐이다.)
2. 개발 DB 적용에 대한 사용자의 명시 승인이 있다.
3. 개발 DB 백업(또는 PITR 복구 지점)을 확인했다.
4. 실행 역할이 **비슈퍼유저 + BYPASSRLS** 이고 레거시 4개 테이블(`quotes, orders, invoices, payments`)의 소유자이며, `jw_cinema_owner`/`jw_cinema_writer`에 대해 ADMIN 전용 기준선 멤버십을 가진다. (읽기 전용으로 사전 확인: 2026-11-05 개발 DB에서 `postgres` = `super=false bypassrls=true createrole=true`, 기준선 `admin=1 inherit=0 set=0`.)
5. 다섯 개 원장 테이블(`quotes, orders, invoices, payments, cinema_pg_quotes`)이 **비어 있다**. 한 건이라도 있으면 설치는 스스로 거부한다.

## 2. 설치 (S4)

- 실행: 하나의 트랜잭션으로 실행한다. `psql -v ON_ERROR_STOP=1 --single-transaction -f cinema_pg_s4_dev_migration.sql` 또는 Supabase `apply_migration`(여러 문장이 한 번의 단순 질의로 전송되어 암묵적 한 트랜잭션).
- 트랜잭션 밖에서 실행하면 멤버십 지문이 사라져 마지막 검사에서 `25P01`로 실패한다(안전 방향 실패).
- 영향: 레거시 4개 테이블과 `cinema_pg_quotes`에 `SHARE ROW EXCLUSIVE` 잠금을 커밋까지 보유한다. **읽기는 허용, 쓰기는 대기**한다. 잠금 대기는 5초(`lock_timeout`)에서 `55P03`으로 실패하며 아무것도 남기지 않는다.
- 설치가 하는 일: 테이블 1개(`cinema_pg_ledger_claims`), 함수 2개, 트리거 10개 추가. 기존 테이블 데이터·정책·ACL은 바꾸지 않는다.
- 임시 권한(소유자 역할 멤버십, 스키마 CREATE, 레거시 TRIGGER, 필요한 경우에만 `cinema_pg_quotes` SELECT)은 같은 트랜잭션에서 회수되며, 설치 전 `pg_auth_members`(CINEMA 역할 관련 전 행 · 6개 컬럼)와 역할 속성 지문이 끝에서 다시 일치해야 한다. 다르면 전체가 취소된다.
- 클레임 트리거는 **AFTER INSERT** 이다. 실제로 삽입된 행에 대해서만 클레임이 생긴다(`ON CONFLICT DO NOTHING`, 다른 BEFORE 트리거가 행을 건너뛴 경우 고아 클레임 없음).

### 설치 후 읽기 전용 검증

```sql
select count(*) from pg_trigger where tgname like 'cinema\_pg\_s4\_%' and not tgisinternal and tgenabled='O';   -- 10
select count(*) from jw_dev.cinema_pg_ledger_claims;                                                          -- 0
select roleid::regrole, member::regrole, grantor::regrole, admin_option, inherit_option, set_option
  from pg_auth_members where roleid::regrole::text like 'jw\_cinema\_%';                                       -- 설치 전과 동일
```

## 3. 롤백 (안전 전용)

`cinema_pg_s4_dev_rollback.sql`은 **아무 데이터도 쓰인 적 없는 상태에서만** S4를 제거한다.

- 하나의 DO 블록(원자적). 잠금 → 확인 → 삭제 순서이며 잠금은 고정 순서(`quotes, orders, invoices, payments, cinema_pg_quotes, cinema_pg_ledger_claims`)로 `lock_timeout 5s`.
- 클레임 테이블 또는 원장 5개 중 하나라도 1행 이상이면 `55000`으로 **거부**하고 아무것도 바꾸지 않는다(트리거·함수·테이블·권한·멤버십 그대로).
- 진행 중인 쓰기 트랜잭션이 있으면 잠금 대기 중 커밋되더라도 잠금을 잡은 뒤에 세므로 그 데이터를 보고 거부한다. 5초를 넘기면 `55P03`으로 실패한다.
- 끝에서 S4 객체 부재, 임시 권한 부재, 멤버십·역할 속성·ACL이 시작 시점과 동일함을 스스로 검증한다.
- 실행 역할 조건은 설치와 같다(비슈퍼유저, BYPASSRLS).

## 4. 이미 데이터가 있는 환경의 복구 (별도 승인 · 이 스크립트로 하지 않음)

클레임은 삭제되지 않는 것이 설계 보증이므로(행이 지워져도 테넌트의 원장 선택은 유지), 데이터가 있는 환경에서 자동 롤백 스크립트는 **제공하지 않는다**. 필요하면 아래 순서로 새로 검토·승인한다.

1. 쓰기 동결(앱 정지 또는 읽기 전용 전환)과 백업/PITR 지점 확인.
2. 읽기 전용 정합성 점검: 테넌트별 클레임 원장과 실제 행의 원장이 일치하는지.
   ```sql
   select r.org_id, r.l as rows_in, c.ledger as claimed
   from (select org_id,'legacy' l from jw_dev.quotes union select org_id,'legacy' from jw_dev.orders
         union select org_id,'legacy' from jw_dev.invoices union select org_id,'legacy' from jw_dev.payments
         union select org_id,'cinema' from jw_dev.cinema_pg_quotes) r
   left join jw_dev.cinema_pg_ledger_claims c on c.org_id=r.org_id
   where c.ledger is distinct from r.l;                   -- 0행이어야 정상
   ```
3. 클레임 테이블과 원장 행 수를 내보내 체크섬을 보관.
4. 선택지: (a) 롤백하지 않고 앞으로 수정(forward-fix), (b) 승인된 별도 복구 SQL을 작성 → 리뷰 → PG17 CI → 사용자 승인 후 실행.
5. 어떤 경우에도 임의의 `TRUNCATE`/`DELETE`로 클레임을 지우지 않는다(테넌트가 다른 원장으로 이동 가능해짐).

## 5. P2 로그인 역할

- 설치: `cinema_pg_p2_login_role.sql`(비밀번호 없음 → 설정 전에는 로그인 불가). 비밀번호는 대시보드 또는 `\password`로 직접 설정하고 Render 환경변수에만 저장한다. 채팅·CI·저장소에 두지 않는다.
- 롤백: `cinema_pg_p2_login_role_rollback.sql`. 멤버십·역할 속성은 설치 전 상태로 돌아간다(하네스 `P2.20`, `P2.21`).
- 미검증: TLS(로컬 소켓으로는 검증 불가), 실제 Supabase pooler 경유 동작.

## 6. 이번 수정으로 달라진 점 (검토 필요)

| 변경 | 이유 | 영향 |
|---|---|---|
| 롤백이 데이터가 있으면 거부 | 독립 검토 P0: 클레임/업무 데이터 소실 위험 | 데이터가 있는 환경은 §4 절차 |
| 클레임 트리거 BEFORE → AFTER INSERT | 고아 클레임 3경로를 하네스가 재현(S4O.01~03) | 설계 변경. 교차 원장 삽입은 여전히 문장 단위로 차단 |
| 설치/롤백이 BYPASSRLS 실행자 요구 + `row_security=off` 카운트 | `cinema_pg_quotes`의 FORCE RLS 소유자 정책이 소유자에게 0행만 보여 기존 `pre2` 검사가 공허했음 | 실행 역할 요건 추가(개발 DB `postgres`는 충족) |
| 원장 테이블 잠금 + `lock_timeout 5s` | 검사와 설치/삭제 사이 경합 제거 | 설치·롤백 중 짧은 쓰기 대기 |
| 러너의 기존 SELECT 상태를 기억 | 개발 DB `postgres`는 `pg_read_all_data`를 상속해 이미 SELECT 보유 | 부족할 때만 임시 부여·회수 |
| 멤버십·역할 속성 지문 | 독립 검토 P1 | 설치 전후 불일치 시 전체 취소 |

## 7. 아직 증명되지 않은 것

- 실제 PostgreSQL 17에서의 실행(로컬은 PG16 보충 실행만 가능했음).
- GitHub Actions 서비스 컨테이너의 `127.0.0.1:5432:5432` 포트 바인딩 호환성.
- Supabase 개발 DB에서의 적용 결과(적용하지 않았음).
