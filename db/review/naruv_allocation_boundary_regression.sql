-- Read-only actual deployed allocation function regression, isolated QA.
-- 2026-11-27: 5724 allocation cases, 4 sale refund cases, zero mismatches.
BEGIN READ ONLY;
SET LOCAL statement_timeout='10s';
SET LOCAL ROLE naruv_native_owner;
WITH cases AS (
 SELECT a::numeric AS amount,t::bigint AS total,p::bigint AS previous,q::bigint AS qty
 FROM generate_series(0,25) a CROSS JOIN generate_series(1,10) t
 CROSS JOIN LATERAL generate_series(0,t-1) p CROSS JOIN LATERAL generate_series(1,t-p) q
 UNION ALL
 SELECT 1000000000000000000000::numeric,1000000000000::bigint,p,q
 FROM (VALUES (0::bigint,1::bigint),(999999999999::bigint,1::bigint),(0::bigint,1000000000000::bigint),(499999999999::bigint,2::bigint)) v(p,q)
), checked AS (
 SELECT *,naruv_finance.allocation(amount,total,previous,qty) AS actual,
 floor(amount*(previous+qty)/total+0.5)-floor(amount*previous/total+0.5) AS expected
 FROM cases
), sales AS (
 SELECT price,step,naruv_finance.allocation(200,2,step,1) AS net,naruv_finance.allocation(20,2,step,1) AS vat,
 naruv_finance.allocation(4*price,2,step,1) AS cost FROM (VALUES (105),(205)) p(price) CROSS JOIN generate_series(0,1) step
)
SELECT (SELECT count(*) FROM checked) AS allocation_cases,
 (SELECT count(*) FROM checked WHERE actual IS DISTINCT FROM expected OR actual<0 OR actual>amount) AS allocation_mismatches,
 (SELECT count(*) FROM sales) AS sale_refund_cases,
 (SELECT count(*) FROM sales WHERE net+vat<>110 OR cost<>2*price OR net-cost<>100-2*price) AS sale_refund_mismatches;
ROLLBACK;
