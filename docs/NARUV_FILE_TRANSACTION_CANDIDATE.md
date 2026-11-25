# NARUV ONE — file-bound transaction candidate

Parent: 620c2c5dc6d582ed5456d12095d8844d7278f2a5 (draft PR #164). Upstream runs 45570710744 and 45570710732 passed, eight jobs. Those results cover the parent, not this extension.

The additive adapter revalidates the original bytes and reviewed stage against locked tenant/source/entity state, preserves unit and business_number, and stores source bytes and SHA-256, stage and preflight digests, and reviewed rows. The disposable SQL binds approval to a staged file, prohibits ordinary stage mutations and revokes old direct issue/reserve/fixture commit entry points for lab tenants only. Commit writes synthetic records, revision, snapshot and receipt atomically. It does not grant production import authority.

Pre-publication review found that the previous loopback server-address assumption is unsuitable for Docker port mapping. The job obtains its own service container IPv4 from Docker inspect; Python and SQL compare the actual server address before staging or schema creation. Database name, version, role, fixed local CI connection and existing disposal guards are retained. This is a trusted isolated lab, not product authentication.

Local evidence: 16 contract tests passed in five processes on original candidate; 16 passed again after service-address correction. Upstream parser boundary in the local contract suite uses test doubles. Nine real PG17 cases are defined; actual execution remains pending until GitHub Actions reports it. Three fresh matrix services execute the contract and integration suites without weakening prior jobs. Test script trailing newline normalized only; no behavioral change from that normalization.

No real customer data or credentials, production DB, UI, API, deployment, main, backups or recovery keys modified. Do not merge this draft. Raw-file retention/encryption and deletion, production service identity/least privilege, actual ERP schema and authentication/UI integration remain future work. Do not infer production readiness from a lab pass.
