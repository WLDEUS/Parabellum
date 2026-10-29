# Threat-DB pipeline

Nightly build of the signed bundle consumed by `pb-updater` / `pb-engine`. Layout and manifest:
`crates/pb-core/src/db.rs` (contract). Workflow: `.github/workflows/nightly-db.yml` (02:17 UTC).

```sh
python -m pipeline.build --out dist/db \
  --previous prev/parabellum-db.tar.gz --state prev/pipeline-state.tar.gz \
  --corpus-cache .cache/corpus --ml-dir ml-latest --pb-features target/release/pb-features --sign
```

| Exit code | Meaning |
|---|---|
| 0 | bundle built (and signed with `--sign`) |
| 2 | sanity guard refused it (malware hashes or blocked domains dropped > 50 %, or empty bundle); nothing is published, clients keep yesterday's bundle. Override: `--allow-shrink` / workflow input `allow_shrink` |
| 1 | error |

Env: `ABUSECH_AUTH_KEY` (abuse.ch), `MINISIGN_SECRET_KEY` (`--sign`), `MALWARE_CORPUS=1` (detection
measurement), `GITHUB_RUN_NUMBER` (the `N` of version `YYYY.MM.DD.N`).
Outputs: `parabellum-db.tar.gz` + `.minisig`, `manifest.json` (same bytes as inside the tarball),
`pipeline-state.tar.gz` + `.minisig` (per-source data for tomorrow's carry-over, never shipped to
clients), `report.json` (errors, FP-gate rejections, detection numbers, broker count, component pins),
`shadowrocket-reject.list` (DOMAIN-SET for Shadowrocket, published in `db-latest`, not in the bundle),
`stage/` (unpacked bundle). Bundle layout: `docs/db-bundle.md`.
`pipeline/publish.sh dist/db` uploads to `db-<version>` and `db-latest` (manifest last) and prunes
dated releases older than 14 days.

## Steps

1. **Fetch** every source of `sources.toml` independently. A failed source is reported
   `fresh: false` with its last successful `fetched_at`, and its data is carried over (domains from the
   state, YARA files from the previous bundle, hashes through the rolling index, ML model, broker list and
   component pins from the previous bundle).
2. **Normalise**: domains lowercased/IDNA, hosts/adblock/URL syntaxes reduced to hostnames, IPs dropped,
   shared platforms (`data/shared_hosts.txt`: github.com, drive.google.com, Discord CDN…) and their
   parents never blocked, allowlisted names (`data/dns_allowlist.txt`) removed, subdomains of listed
   parents pruned.
3. **Validate YARA** with `yara-x==1.22.0` (same minor as the Rust crate): each file compiled alone,
   failures dropped, rule identifiers made globally unique.
4. **FP gate**: `data/clean_corpus.toml` (pinned vendor archives + Homebrew arm64 bottles) is
   downloaded/extracted into the cache (tar, zip, xar/pkg + gzip/pbzx cpio payloads in pure Python; DMG
   with `7zz`/`7z`). Every rule matching a clean file is removed (`yara_rules_rejected_fp`), clean
   hashes go to `hashes/allow.sha256` and out of the malware set. `fp_rate` = clean files still
   flagged by the bundle (YARA + hash DB + ML at its threshold) / files scanned.
5. **Detection** (opt-in, below).
6. **Assemble**, sanity guard, deterministic `tar.gz` (sorted, mtime 0, uid/gid 0, files and dirs
   only, gzip mtime 0), minisign.

## Hash database choices

* All-platform MalwareBazaar SHA-256 from a **365-day rolling window**, capped at the **2 M newest**
  (64 MB `malware.sha256`, binary-searched by the client). The window needs first-seen dates, which the
  bundle does not store: they live in the state (`hashes/index.tsv.gz`). Bootstrap: the full export is
  only requested while the index holds < 1000 hashes.
* macOS samples (file types `macho`/`dmg`/`pkg`, macOS family tags) carry a name and size: they produce
  `hashes/malware_names.tsv` (sorted by hash) and `clamav/parabellum.hsb`
  (`sha256:size:Parabellum.Osx.<Family>:73`, size `*` when unknown — wildcard sizes need flevel 73 per
  the ClamAV docs) and are kept beyond the window (cap 200 k).

## Sources and verification (2026-10-25/26)

| Source | How it was verified |
|---|---|
| abuse.ch (MalwareBazaar, URLhaus, ThreatFox) | Official pages bazaar.abuse.ch/api, urlhaus.abuse.ch/api, threatfox.abuse.ch/export: `Auth-Key` header for the query APIs, key **in the URL path** for `…/v2/files/exports/<KEY>/<file>`; keyless export URLs answer `410 Gone` since 2026-10-21 (opnsense/core#11078, public migrations). Documented files: MB `recent.csv`, URLhaus `recent.csv`/`online.csv`, ThreatFox `full.csv.zip`. **Not verified**: MB `full.csv.zip` (bootstrap only, failure is harmless). abuse.ch is unreachable from the build container: parsing is tested on fixtures only |
| HaGeZi, OISD, StevenBlack | Downloaded from raw.githubusercontent.com, formats and licences read (GPL-3.0, GPL-3.0, MIT) |
| Elastic protections-artifacts | Repo cloned: 49 macOS files / 96 rules, all compile with yara-x 1.22, zero hit on the clean corpus. Fetched in CI from `codeload.github.com` (blocked in the build container) |
| signature-base (DRL 1.1) | 9 macOS files fetched and compiled, zero hit on the clean corpus |
| Homebrew bottles | Anonymous ghcr.io pulls use `Authorization: Bearer QQ==` (Homebrew `brew.sh`); bottle URL/SHA-256 from `formulae.brew.sh/api/formula/<name>.json`. ghcr.io unreachable from the container: untested live |
| Trusted Team IDs | Read from the code signatures of official artefacts (see `data/trusted_team_ids.txt`) |
| Zero Breach Toolkit (2026-10-28) | Source read (`cli.py`, `feeds.py`, `report.py`, `contract.py`, `docs/VERIFYING.md`): releases carry `zero-breach-toolkit.py`, `SHA256SUMS.txt` and detached `.asc` signatures made with the Ed25519 key `C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C` (`tools/make_release.py` also attaches `archivegenocide-signing-key.asc`). `pipeline/zbt.py` discovers asset names at runtime, imports the key from keys.openpgp.org, the release's `*key*.asc` or `data/zbt-signing-key.asc` (not committed yet: the key could not be downloaded from the build container), and refuses anything not signed by that exact primary key or whose SHA-256 differs. **Not verified live**: the GitHub API, the asset names of a real release, keyserver availability (blocked in the container) |
| GDPR brokers (2026-10-29) | Datenanfragen `datenanfragen/data` (CC0, schema read: `slug`, `name`, `email`, `web`, `webform`, `categories`, `relevant-countries`) and Eraser `digisamroc/eraser` `data/brokers.yaml` (MIT: `id`, `name`, `email`, `website`, `opt_out_url`, `region`, `category`) cloned at the pinned commits: 237 + 764 entries → 954 after dedupe (eu 235, global 10, us 709). `codeload.github.com` / `raw.githubusercontent.com` URLs not fetched from the container (git clone used) |
| sing-box (2026-10-29) | `SagerNet/sing-box` `.github/workflows/build.yml` read: darwin archives `sing-box-<v>-darwin-<arch>.tar.gz` holding `sing-box-<v>-darwin-<arch>/sing-box`, every release artefact attested with `actions/attest` (build provenance). Latest stable 1.14.4 per `docs/changelog.md`. **Not verified live**: the GitHub API `digest` field and `gh attestation verify` on a real asset (API blocked in the container) |

## GDPR brokers and component pins

* `privacy.py` → `privacy/brokers.json`: see `docs/db-bundle.md`. Pins live in `sources.toml`
  (`datenanfragen_commit`, `eraser_commit`); **bumping them is a reviewed change** — the daemon emails the
  user's identity to every address of the list.
* `pins.py` → `components/pins.json`: newest stable sing-box `>= 1.12 < 2`, digest cross-check, arm64 Mach-O
  check, `gh attestation verify --repo SagerNet/sing-box`; any failure keeps the previous pin.

## Detection measurement and the GitHub Acceptable Use caveat

With `MALWARE_CORPUS=1` and a key, the build downloads up to 40 macOS samples first seen in the last
2 days, decrypts them **in memory** (`pyzipper`, password `infected`), writes containers/Mach-O to a
private temp dir (0700, files 0600, never executable) only while scanning, deletes them immediately,
never executes, caches or uploads them, and reports only counts + SHA-256 (`report.json`,
`stats.detection_rate`). The hash DB is excluded (samples come from the same feed).

GitHub's Acceptable Use Policies forbid using GitHub to host or distribute malware and restrict
non-CI use of Actions runners. Transient analysis without storage is a grey zone, so the step is
**off by default** on GitHub (workflow input `malware_corpus`). Prefer running it on a Linux box you
control (never on the Mac you protect):

```sh
make -C pipeline venv && . .venv-pipeline/bin/activate
ABUSECH_AUTH_KEY=… make -C pipeline corpus-local     # prints the detection report
```

## Development

`make -C pipeline test lint` (pytest + ruff, no network), `make -C pipeline build-offline` (local data
and GitHub-hosted lists only). Add a source = one `[[source]]` block in `sources.toml` (fetchers:
`mb_export`, `mb_api_macos`, `urlhaus_export`, `threatfox_export`, `domain_list`, `yara_tarball`,
`yara_raw`, `yara_local`, `local_file`, `ml_local`, `zbt_release`, `privacy_brokers`, `component_pin`).
