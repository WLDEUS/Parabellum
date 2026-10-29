# Threat-DB bundle

Contract: `crates/pb-core/src/db.rs` (manifest, constants, `BrokersFile`, `ComponentPins`). Built nightly by
`pipeline/` (`.github/workflows/nightly-db.yml`), published to the `db-latest` release, signed with minisign
(`keys/parabellum-db.pub`). The client verifies the `.minisig` before unpacking, then every digest of
`manifest.json`.

| Path | Content | Optional |
|---|---|---|
| `manifest.json` | `DbManifest`: version `YYYY.MM.DD.N`, sources (name, kind, url, licence, count, fresh), SHA-256 of every file, stats | no |
| `hashes/malware.sha256` | sorted raw 32-byte SHA-256 digests | no |
| `hashes/malware_names.tsv` | `<sha256>\t<family>` (macOS samples), sorted by hash | yes |
| `hashes/allow.sha256` | known-good digests (FP exclusions) | yes |
| `yara/*.yar` | rule sources validated with yara-x (FP gate applied) | yes |
| `clamav/parabellum.hsb` | ClamAV hash signatures | yes |
| `dns/{malware,ads,trackers}.txt`, `dns/allowlist.txt` | one domain per line, a domain also blocks its subdomains | yes |
| `allow/team_ids.txt` | trusted Apple Developer Team IDs | yes |
| `ml/macho_model.json`, `ml/model_meta.json` | Mach-O classifier | yes |
| `osquery/hunting.json` | osquery hunting pack | yes |
| `zbt/…` | Zero Breach Toolkit (GPG-verified in CI) + indicators | yes |
| `privacy/brokers.json` | `BrokersFile` (format 1): organisations that receive GDPR erasure requests — see below | yes |
| `components/pins.json` | `ComponentPins` (format 1): third-party archives the daemon may install, pinned by SHA-256 — see below | yes |

## `privacy/brokers.json`

```json
{"format": 1,
 "sources": {"datenanfragen": "<commit>", "eraser": "<commit>"},
 "brokers": [{"id": "criteo", "name": "Criteo", "email": "dpo@criteo.com", "website": "https://www.criteo.com/",
              "region": "eu", "category": "ads", "source": "datenanfragen"}]}
```

* `region`: `eu` (Datenanfragen, CC0: categories ads / addresses / credit agency → `ads` / `addresses` /
  `credit`, relevant for France or everyone, email required), `global` / `us` (Eraser, MIT: `marketing`,
  `people-search`, `background-check`).
* `email` and/or `opt_out_url` (HTTPS) are always present; `website` optional. Ids are unique slugs.
* Both upstreams are fetched at commits pinned in `pipeline/sources.toml`: the daemon emails the user's identity
  to these addresses, so the data only changes through a reviewed pin bump. Fewer than 50 entries → the previous
  file is kept. The daemon (`pb-privacy`) re-validates every entry (email syntax, HTTPS URLs, known region).

## `components/pins.json`

```json
{"format": 1,
 "pins": {"sing-box": {"version": "1.14.4", "asset": "sing-box-1.14.4-darwin-arm64.tar.gz",
                       "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-darwin-arm64.tar.gz",
                       "sha256": "<hex>", "binary": "sing-box-1.14.4-darwin-arm64/sing-box",
                       "verified_by": "github-attestation:SagerNet/sing-box"}}}
```

sing-box ships no signature the Mac can check. The pipeline takes the newest stable release (`>= 1.12`, `< 2`),
cross-checks the asset SHA-256 with the release API `digest`, requires an arm64 Mach-O at `binary`, and runs
`gh attestation verify <asset> --repo SagerNet/sing-box` (GitHub build provenance, Sigstore). The daemon then
installs the download only if its SHA-256 equals the pin. Any failure keeps the previous pin.

## Next to the bundle (not signed)

`shadowrocket-reject.list` in `db-latest`: the merged malware + ads + trackers lists (allowlist applied) as a
Surge/Shadowrocket `DOMAIN-SET` (`.domain` per line), for the external VPN backend:
`DOMAIN-SET,https://github.com/WLDEUS/Parabellum/releases/download/db-latest/shadowrocket-reject.list,REJECT`.
