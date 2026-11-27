-- REVIEW ONLY. Do not apply to postgres or production.
-- Observed 2026-11-27 on isolated hosted QA: 35 candidates across 24 tables.
-- All 35 index shapes created and verified on transaction-local empty LIKE clones
-- with existing indexes copied, then rolled back. No source data copied.
-- Advisor reported 33; stricter full nonpartial btree prefix check reports 35.
-- Representative 20,000 synthetic rows: bitmap heap scan -> index scan,
-- estimated planner cost 178.49 -> 2.51; matched rows 2 -> 2.
-- This is not measured latency or workload improvement; no index removal.
-- Requires approved fresh disposable DB and separate A/B benchmark.
BEGIN;
SET LOCAL statement_timeout='30s';
SET LOCAL lock_timeout='2s';
DO $guard$ BEGIN
 IF current_database() !~ '^naruv_qa_workload_[a-f0-9]{12}$'
 OR session_user<>'postgres' OR current_user<>'postgres'
 OR current_setting('server_version_num')::int<>170012
 OR to_regclass('naruv_qa_probe.fixture') IS NULL
 OR (SELECT count(*) FROM naruv_qa_probe.fixture)<>2
 THEN RAISE EXCEPTION 'DISPOSABLE_INDEX_SCOPE'; END IF;
END $guard$;
CREATE INDEX qa_fk_21b45ffd4af9145878740553 ON jw_dev.messenger_connections (org_b);
CREATE INDEX qa_fk_e5857dfba93ef53eaa030433 ON jw_dev.messenger_edits (message_id);
CREATE INDEX qa_fk_c036f7fadbf39a15331a1370 ON jw_dev.messenger_messages (connection_id);
CREATE INDEX qa_fk_5829745dac282d9dc19db002 ON jw_dev.quote_items (quote_id);
CREATE INDEX qa_fk_7114b4d8ca1c0e0f942e5e44 ON jw_dev.quotes (customer_id);
CREATE INDEX qa_fk_346a9a8133ad73349510eb58 ON jw_dev.sessions (user_id);
CREATE INDEX qa_fk_c79cc4c9f899d289c38dfaa7 ON jw_dev.users (org_id);
CREATE INDEX qa_fk_1fb68d04bf1e018e16ddf0c1 ON naruv_accounting.journals (org_id, period_start);
CREATE INDEX qa_fk_1bbf7fcfd0302701fbb95858 ON naruv_bundle.events (org_id, bundle_id);
CREATE INDEX qa_fk_cd3d7e50e001a70f3e9777d4 ON naruv_customer_bridge.crosswalk (org_id, source_id, entity, normalized_id);
CREATE INDEX qa_fk_9367fcaafce0a6d3e8ae8498 ON naruv_customer_bridge.crosswalk (org_id, stage_id);
CREATE INDEX qa_fk_895edf048ba82c3759328f97 ON naruv_draft.period_amendments (org_id, worker_id, period);
CREATE INDEX qa_fk_2b2b60a83571b970ec7700a4 ON naruv_hosted_identity_review.sessions (actor_id);
CREATE INDEX qa_fk_271e74ac70f065f162b00a1d ON naruv_hosted_identity_review.users (org_id);
CREATE INDEX qa_fk_9271a3c75dec3d28e0e8d4e3 ON naruv_inventory.balances (org_id, warehouse_id);
CREATE INDEX qa_fk_3269f666fed435136f85709c ON naruv_inventory.items (org_id, source_id, entity, normalized_id);
CREATE INDEX qa_fk_db2ed4773bc4e4742d137f79 ON naruv_inventory.movements (org_id, from_warehouse);
CREATE INDEX qa_fk_951618191050f900da7a413c ON naruv_inventory.movements (org_id, source_id, normalized_id);
CREATE INDEX qa_fk_5e5a1057131ef49a58e59296 ON naruv_inventory.movements (org_id, to_warehouse);
CREATE INDEX qa_fk_f1e368c2b9ac882b76f0d5ef ON naruv_native_review.records (org_id, stage_id);
CREATE INDEX qa_fk_a1fa2f544fe864e1344c33ba ON naruv_production.boms (org_id, source_id, product_id);
CREATE INDEX qa_fk_99b83ae82b307bae25686ee0 ON naruv_production.components (org_id, bom_id, source_id);
CREATE INDEX qa_fk_17add032c6c26dbc325aa735 ON naruv_production.components (org_id, source_id, material_id);
CREATE INDEX qa_fk_0ce82901eb214d03ac687779 ON naruv_production.events (org_id, bom_id);
CREATE INDEX qa_fk_d70ccb33c6b8f6e20ff4dfc2 ON naruv_production.events (org_id, order_id);
CREATE INDEX qa_fk_4d0d41e96bfb830bc8b7906b ON naruv_production.orders (org_id, bom_id);
CREATE INDEX qa_fk_3f018df10c64e0a446b6e822 ON naruv_production.orders (org_id, warehouse_id);
CREATE INDEX qa_fk_f3946968c33a728716da8a38 ON naruv_trade.documents (org_id, counterparty_id);
CREATE INDEX qa_fk_301ab320c421b363893d8ce9 ON naruv_trade.documents (org_id, source_id, item_id);
CREATE INDEX qa_fk_d6ee3a12e8457961b6f1994a ON naruv_trade.documents (org_id, warehouse_id);
CREATE INDEX qa_fk_6389b1069d6fc590b8751ca6 ON naruv_trade.documents (quote_id);
CREATE INDEX qa_fk_219048039489a937a0cf00b6 ON naruv_trade.documents (quote_line_id);
CREATE INDEX qa_fk_364c7559fd72f159cb9e9ab5 ON naruv_trade.events (org_id, doc_id);
CREATE INDEX qa_fk_1dd6a47993ccf81bdcc9ac0e ON naruv_trade.events (org_id, movement_id);
CREATE INDEX qa_fk_2d214c7edf11f8a67630a357 ON naruv_valuation.cost_journals (org_id, period_start);
COMMIT;
