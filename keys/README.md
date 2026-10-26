# Signing keys

One minisign (Ed25519) key pair signs both the nightly threat-DB bundle and the app `.pkg` releases.

| File | Where | Role |
|---|---|---|
| `keys/parabellum-db.pub` | committed here | embedded in `parabellumd` at build time (`crates/pb-updater/build.rs`, or env `PARABELLUM_DB_PUBKEY`); the client verifies `parabellum-db.tar.gz.minisig` **before** unpacking, then every digest of `manifest.json` |
| `~/.parabellum/parabellum-db.key` | owner's Mac only, never in the repo | backup of the secret key |
| `MINISIGN_SECRET_KEY` | GitHub Actions secret | used by `nightly-db.yml` and `release.yml` |

Create them once with `scripts/setup-signing-keys.sh` (or `make keys`): it generates an
**unencrypted** pair (CI must sign unattended — the GitHub secret store is the protection), refuses to
overwrite an existing key without `--force`, and sets the secret with `gh` when available.

## Trust model

* Whoever holds the secret key can push a bundle every client accepts (hashes, YARA rules, DNS lists,
  allowlisted Team IDs) and a `.pkg` the auto-updater installs. Keep it only in the GitHub secret and
  an offline backup. Repository write access is equivalent (workflows can use the secret): protect
  `main` and require reviews for workflow changes.
* The client never trusts the transport (GitHub releases): signature first, then manifest digests,
  then `DbManifest::validate`, atomic swap with rollback.
* CI cross-checks every signature against this committed public key before publishing, so a secret
  that does not match the key embedded in clients fails the job instead of breaking updates.

## Rotation (compromise or scheduled)

1. `scripts/setup-signing-keys.sh --force` (backs up the old secret, writes a new pair, updates the
   GitHub secret).
2. Commit `keys/parabellum-db.pub`, tag a new release: the new daemon embeds the new key.
3. Installed clients only know the old key: install the new `.pkg` manually (or sign that one release
   with the old key first, then rotate). Nightly bundles signed with the new key are rejected by old
   clients until they are updated — the daemon keeps its current DB in the meantime (fail-safe).
4. After a compromise, also rotate `ABUSECH_AUTH_KEY` and review recent `db-*` releases.
