def _stage(token_hash,csrf,prior,source,entity,fmt,stage_id,digests,raw):
    digest,canonical,snapshot=digests
    import psycopg
    try:
        # Snapshot read: release identity locks before expensive parsing.
        with _ingest_cursor(token_hash,csrf,prior) as (cur,org):
            cur.execute("SELECT * FROM naruv_native_review.read_source(%s,%s,%s)",(source,entity,csrf))
            row=cur.fetchone()
            if not row:
                raise HTTPException(404,"SOURCE_NOT_FOUND")
            revision,existing_ids=row[0],tuple(row[1])
        target=make_target_snapshot(org,source,entity,revision,list(existing_ids))
        candidate=prepare_file_stage(raw,format=fmt,organization_id=org,source_id=source,entity=entity,target=target)
        if not hmac.compare_digest(candidate.stage_sha256,digest) or not hmac.compare_digest(target.snapshot_sha256,snapshot):
            raise HTTPException(409,"NARUV_PREVIEW_CHANGED")
        rows=json.dumps([dict(x) for x in candidate.canonical_rows],ensure_ascii=False,sort_keys=True,separators=(",",":"))
        if not hmac.compare_digest(hashlib.sha256(rows.encode('utf-8')).hexdigest(),canonical):
            raise HTTPException(409,"NARUV_PREVIEW_CHANGED")
        # Fresh restricted transaction; store_stage atomically rechecks the
        # current session, auth epoch, quota, source revision and expected IDs.
        with _ingest_cursor(token_hash,csrf,prior) as (cur,current_org):
            if current_org!=org:
                raise HTTPException(409,"SESSION_SCOPE_CHANGED")
            cur.execute("""SELECT naruv_native_review.store_stage(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (stage_id,source,entity,fmt,candidate.raw_sha256,candidate.byte_count,digest,canonical,
                         candidate.preflight.rows_sha256,snapshot,target.revision,
                         list(target.existing_source_ids),rows,csrf))
            result=cur.fetchone()
            if not result or result[0] not in ("STAGED","ALREADY_STAGED"):
                raise HTTPException(503,"NARUV_TRANSACTION_UNAVAILABLE")
            return {"status":result[0],"stage_id":stage_id,"stage_sha256":digest,
                    "canonical_rows_sha256":canonical,"target_snapshot_sha256":snapshot,
                    "row_count":candidate.preflight.row_count,"row_import_authorized":False}
    except MappingBlocked as exc:
        reason=str(exc)
        raise HTTPException(422,reason if re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}",reason) else "FILE_REJECTED") from None
    except psycopg.Error as exc:
        raise _db_error(exc) from None
