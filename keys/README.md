# Signing keys

Two minisign (Ed25519) key pairs, two levels of trust. Details: `docs/SECURITY-SUPPLY-CHAIN.md`.

| Public key (committed) | Signs | Secret key lives in |
|---|---|---|
| `keys/parabellum-db.pub` | nightly threat-DB bundle, pipeline state, promoted ML models | GitHub environment `db-signing` (branch `main` only): `MINISIGN_SECRET_KEY` + `MINISIGN_KEY_PASSWORD` |
| `keys/parabellum-release.pub` | app `.pkg` releases only | GitHub environment `release` (tags `v*` only, required reviewer): `MINISIGN_RELEASE_SECRET_KEY` + `MINISIGN_RELEASE_KEY_PASSWORD` |

Both public keys are embedded in `parabellumd` at build time (`crates/pb-updater/build.rs`). The client
verifies the DB signature **before** unpacking, then every digest of `manifest.json`. A `.pkg` is only
installed when its signature comes from the release key **and** its trusted comment names a version newer
than the installed one (`Parabellum <version> (<sha>)`): no rollback to an older signed release.

Both secret keys are **password-protected**; the key file and its password are two separate environment
secrets, handed to minisign on stdin by `scripts/ci-minisign.sh` (temporary `0600` file, wiped even on
failure, signature re-verified against the committed public key). No secret key stays on the Mac:
`scripts/secure-local-keys.sh status | encrypt | migrate | purge`.

Create them with `scripts/setup-signing-keys.sh` (DB) and `scripts/setup-release-key.sh` (release): a typed
password (never written to disk), no `.bak`, secrets sent straight to their environment.

## Trust model

* Whoever holds the DB key can push a bundle every client accepts (hashes, YARA rules, DNS lists,
  allowlisted Team IDs) but cannot make the daemon install a program as root: that takes the release key.
* Only jobs that declare the environment receive its secrets, and only on the allowed refs. Repository
  write access is still powerful (it can change workflows on `main`): protect `main` and require reviews
  (`make protect-repo`).
* The client never trusts the transport (GitHub releases): signature first, then manifest digests,
  then `DbManifest::validate`, atomic swap with rollback.

## Rotation (compromise or scheduled)

1. `scripts/setup-signing-keys.sh --force` or `scripts/setup-release-key.sh --force` (new pair, secret
   sent to its environment).
2. Commit the new `.pub`, tag a new release: the new daemon embeds the new key.
3. Installed clients only know the old key: install the new `.pkg` manually (or sign that one release
   with the old release key first, then rotate). Bundles signed with a new DB key are rejected by old
   clients until they are updated: the daemon keeps its current DB in the meantime (fail-safe).
4. After a compromise, also rotate `ABUSECH_AUTH_KEY` and review recent `db-*` releases.
