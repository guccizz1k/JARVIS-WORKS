-- JW-PG17-AUTHZ-SQL-V1: current metadata only, no customer rows or passwords.
-- Compare only with same query/profile, not Python canonical JSON hashes.
WITH RECURSIVE
obj AS (
 SELECT 'schema'::text k,n.nspname::text nm,''::text sub,n.nspowner owner,n.nspacl acl
 FROM pg_catalog.pg_namespace n WHERE n.nspname='jw_dev'
 UNION ALL SELECT 'relation:'::text||c.relkind::text,c.relname::text,'',c.relowner,c.relacl
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p','v','m','S','f')
 UNION ALL SELECT 'column',c.relname::text,a.attname::text,c.relowner,a.attacl
 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT 'routine:'::text||p.prokind::text,p.proname::text,pg_catalog.pg_get_function_identity_arguments(p.oid),p.proowner,p.proacl
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='jw_dev'
 UNION ALL SELECT 'type:'::text||t.typtype::text,t.typname::text,'',t.typowner,t.typacl
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='jw_dev'
),
dacl AS (
 SELECT d.defaclrole owner,coalesce(n.nspname::text,'') ns,d.defaclobjtype::text k,d.defaclacl acl
 FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace
 WHERE d.defaclnamespace=0 OR n.nspname='jw_dev'
),
seed AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN ('jw_app_dev','jw_auth_stage_v85')
 UNION SELECT owner FROM obj
 UNION SELECT a.grantee FROM obj,LATERAL pg_catalog.aclexplode(acl) a WHERE a.grantee<>0
 UNION SELECT a.grantor FROM obj,LATERAL pg_catalog.aclexplode(acl) a
 UNION SELECT owner FROM dacl WHERE ns='jw_dev'
 UNION SELECT a.grantee FROM dacl,LATERAL pg_catalog.aclexplode(acl) a WHERE ns='jw_dev' AND a.grantee<>0
 UNION SELECT a.grantor FROM dacl,LATERAL pg_catalog.aclexplode(acl) a WHERE ns='jw_dev'
),
links AS (
 SELECT roleid a,member b FROM pg_catalog.pg_auth_members
 UNION SELECT member,roleid FROM pg_catalog.pg_auth_members
 UNION SELECT roleid,grantor FROM pg_catalog.pg_auth_members
 UNION SELECT member,grantor FROM pg_catalog.pg_auth_members
 UNION SELECT owner,a.grantor FROM dacl,LATERAL pg_catalog.aclexplode(acl) a
 UNION SELECT owner,a.grantee FROM dacl,LATERAL pg_catalog.aclexplode(acl) a WHERE a.grantee<>0
),
scope(oid) AS (
 SELECT oid FROM seed
 UNION SELECT l.b FROM scope s JOIN links l ON s.oid=l.a
),
owners AS (SELECT jsonb_build_array(o.k,o.nm,o.sub,r.rolname::text) v FROM obj o LEFT JOIN pg_catalog.pg_roles r ON r.oid=o.owner),
acls AS (
 SELECT jsonb_build_array(o.k,o.nm,o.sub,o.acl IS NULL,coalesce(
 (SELECT jsonb_agg(v ORDER BY v::text COLLATE "C") FROM
 (SELECT jsonb_build_array(g.rolname::text,CASE WHEN a.grantee=0 THEN NULL ELSE m.rolname::text END,a.privilege_type,a.is_grantable) v
 FROM pg_catalog.aclexplode(o.acl) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor LEFT JOIN pg_catalog.pg_roles m ON m.oid=a.grantee) x),'[]'::jsonb)) v FROM obj o
),
defaults AS (
 SELECT jsonb_build_array(r.rolname::text,d.ns,d.k,coalesce(
 (SELECT jsonb_agg(v ORDER BY v::text COLLATE "C") FROM
 (SELECT jsonb_build_array(g.rolname::text,CASE WHEN a.grantee=0 THEN NULL ELSE m.rolname::text END,a.privilege_type,a.is_grantable) v
 FROM pg_catalog.aclexplode(d.acl) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor LEFT JOIN pg_catalog.pg_roles m ON m.oid=a.grantee) x),'[]'::jsonb)) v
 FROM dacl d JOIN pg_catalog.pg_roles r ON r.oid=d.owner WHERE d.ns='jw_dev' OR d.owner IN (SELECT oid FROM scope)
),
role_rows AS (
 SELECT jsonb_build_array(r.rolname::text,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconnlimit) v
 FROM pg_catalog.pg_roles r JOIN scope s ON s.oid=r.oid
),
members AS (
 SELECT jsonb_build_array(p.rolname::text,m.rolname::text,g.rolname::text,a.admin_option,a.inherit_option,a.set_option) v
 FROM pg_catalog.pg_auth_members a JOIN pg_catalog.pg_roles p ON p.oid=a.roleid JOIN pg_catalog.pg_roles m ON m.oid=a.member JOIN pg_catalog.pg_roles g ON g.oid=a.grantor
 WHERE a.roleid IN (SELECT oid FROM scope) OR a.member IN (SELECT oid FROM scope)
),
all_rows AS (
 SELECT 'owners' k,v FROM owners UNION ALL SELECT 'acl',v FROM acls UNION ALL SELECT 'defaults',v FROM defaults UNION ALL SELECT 'roles',v FROM role_rows UNION ALL SELECT 'members',v FROM members
),
categories(k) AS (VALUES ('owners'),('acl'),('defaults'),('roles'),('members'))
SELECT 'JW-PG17-AUTHZ-SQL-V1' format,c.k category,count(a.v) records,
 encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce(jsonb_agg(a.v ORDER BY a.v::text COLLATE "C") FILTER(WHERE a.v IS NOT NULL),'[]'::jsonb)::text,'UTF8')),'hex') sha256,
 (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('jw_app_dev','jw_auth_stage_v85')) required_roles,
 (SELECT count(*) FROM obj) object_count,
 (SELECT count(*) FROM obj WHERE owner NOT IN (SELECT oid FROM pg_catalog.pg_roles)) unknown_owners,
 current_setting('server_version_num')::int BETWEEN 170000 AND 179999 pg17
FROM categories c LEFT JOIN all_rows a ON a.k=c.k GROUP BY c.k ORDER BY c.k;
