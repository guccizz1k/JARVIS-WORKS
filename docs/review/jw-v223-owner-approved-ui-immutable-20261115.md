# V22.3 owner-approved UI — immutable source custody, review only

The owner's exact original is `app/static/approved_v223_owner_original.html`.

- SHA256: `953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d`
- Git blob: `a1712541b46167c21e9779d41bb198745df2ffc0`
- File bytes: 229028
- Black/lime approved visual baseline; NOT V22.2 silver UI.
- This original uses local browser `jw3.db` and IndexedDB for business records and local password hashes. It has not been integrated with server session, tenant, CSRF and business database. DO NOT serve it as production business app or claim login is integrated.
- No original lines changed. Review branch; main and Render untouched. Refer to P2 CSS/secure-preview candidate from project QA for isolated UI work.
- To integrate: use separately gated review-only server mode, independent protected business APIs; no browser-auth/local-data fallback and no auto data migration.
- Release and production deployment remain NO-GO.
