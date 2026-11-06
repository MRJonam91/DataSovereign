# DataSovereign 1.0 architecture

The implementation extends the public alpha at `7a4b6c9`.

DataSovereign runs on Windows for one user and listens on loopback. Its acceptance path is import → select documents → create expiring delegation → read → revoke → inspect audit → backup and recover.

## Release scope

1. **Explicit consent:** every new delegation snapshots selected active documents in one collection. Omitting `resource_ids` selects the documents currently in that collection; future imports never enter an existing delegation. Empty or out-of-collection selections are rejected. Existing alpha delegations are migrated to snapshots of their currently accessible resources.
2. **Integrity and lifecycle:** imported plaintext receives a SHA-256 checksum, verified after DPAPI decryption. Corruption, missing blobs and substituted valid ciphertext produce a controlled error and an audit event. Upgrade records checksums for readable alpha documents and reports unreadable resources without deleting them. Trash hides a document and removes it from every delegation; restore requires new consent before an old app can read it.
3. **Recovery:** downloadable backup ZIP contains DPAPI-encrypted blobs and a DPAPI-encrypted, authenticated manifest. It remains tied to the Windows account/device; opaque resource IDs and entry counts remain visible. Restore is allowed only into an empty vault, validates format, paths, IDs, sizes and checksums before writing, and restores all historical delegations as revoked. Plaintext export remains available for portability. A metadata database copy is retained before upgrading an alpha vault.
4. **Audit and responsiveness:** indexed collection/resource joins and keyset audit pagination/filtering; bounded JSON and upload bodies; blocking disk/DPAPI operations outside the event loop. The UI lists real documents, provides document selection, trash/restore, integrity checks, backup/recovery, refresh and more audit events. Tokens leave the URL fragment after startup and are retained in the browser tab's session storage until locked or closed.
5. **Release:** version `1.0.0`, bilingual upgrade instructions, Windows CI on Python 3.11 and 3.14, installed-wheel smoke tests, independent review, GitHub release with wheel and source distribution.

## Constraints

- API remains `/v1`; grant responses gain `resource_ids` and `scope: snapshot`.
- Original files remain outside the managed vault. OS isolation and enforcement of declared purpose remain out of scope.
- Keep the existing default data directory `%LOCALAPPDATA%/DataSovereign/alpha` so upgrades find the user's vault.
- Maximum document 10 MiB; plaintext export 50 MiB; encrypted backup/restore 64 MiB, at most 10,000 ZIP entries and 2 MiB metadata.
- Database migration is transactional and idempotent. No plaintext token is stored or backed up. Schema version is checked before writes.
- Restore validates all documents before committing; failed restore must leave the destination empty. Existing vaults are never overwritten.
- Downloads remain `no-store`. Authorization and validation errors never echo submitted tokens or full request bodies.

## Acceptance and review

Tests cover alpha migration/reopen, future imports, cross-collection selection, empty scope, revoked/expired grants, corruption and swapped blobs, trash/recovery, backup tampering/path traversal/size limits, invalid host/origin/admin credentials, and full audit export. The final reviewer checks regressions against the published base, privacy limits and the release process. The security boundary is documented in the [threat model](security/alpha-threat-model.md).
