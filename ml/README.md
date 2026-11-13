# Mach-O and script classifiers (weekly)

`.github/workflows/ml-train.yml` (Sundays 17:41 UTC, before that night's DB build) runs:

```sh
python -m ml.train --pb-features target/release/pb-features --out out/ml \
  --dataset-in prev/dataset.csv.gz --metrics-in prev/metrics.jsonl --current-model current \
  --decision-in prev/decision.json --corpus-cache .cache/corpus
bash ml/publish.sh out/ml
```

* **Features** come from `pb-features` (crate `pb-ml`), the same extractor the daemon uses.
* **Dataset** (`ml-dataset` release, `dataset.csv.gz`): `sha256,label,features_version,<names…>`,
  cumulative, deduplicated by SHA-256, rows of another `features_version` dropped. Positives: new
  MalwareBazaar samples of type `macho` (direct Mach-O only, never binaries found inside malicious
  DMGs). Negatives: Mach-O of the clean corpus (`pipeline/data/clean_corpus.toml`) + optional
  `ml/data/extra_clean_features.jsonl` from the owner's Mac (see `ml/data/README.md`; needed to reach
  the 1000-negative minimum quickly). No sample is ever stored.
* **Shrink guard**: `decision.json` records `n_rows` and `prev_rows`. Training refuses (exit 1, nothing
  published) when the downloaded dataset has fewer readable rows than the published `decision.json`
  says, when `metrics.jsonl` is missing, or when the merge would drop rows (a `features_version`
  change). A release that exists but cannot be downloaded fails the job. Override after a deliberate
  layout change: workflow input `allow_dataset_shrink` (`--allow-dataset-shrink`).
* **Split**: SHA-256 hash buckets — 20 % holdout, 15 % validation, 65 % train — stable week to week.
* **Model**: LightGBM binary, ≤ 300 trees (early stopping), 31 leaves, `scale_pos_weight`, numerical
  splits only, deterministic. Threshold = smallest value with FPR ≤ 0.1 % on validation (next float32
  above the (k+1)-th highest clean score, valid for `>=` and `>`).
* **Promotion gate**: replace `ml-latest` only if, on the holdout, FPR ≤ 0.1 % and TPR ≥ the current
  model's TPR (current model evaluated from its JSON dump exactly like `pb_ml::GbdtModel`). Otherwise
  the old model stays; `decision.json` + `metrics.jsonl` (history) say why.
* **Minimum data**: < 200 positives or < 1000 negatives → no training (dataset still accumulated).
* **Export**: `macho_model.json` = `booster.dump_model()` (feature names checked against
  `pb-features --names`, dump re-evaluated in Python and compared with LightGBM),
  `model_meta.json` = `{"features_version","threshold","version":"YYYY.MM.DD","metrics":{auc,
  tpr_at_threshold,fpr_at_threshold,n_pos,n_neg,trained_at}}`, plus `macho_model.txt` (native format).

Policy reminder: an ML score alone only makes a file *suspicious* (enforced by `pb-engine`).

Sample downloads on GitHub runners carry the Acceptable Use caveat described in
`pipeline/README.md`; set the repository variable `ML_FETCH_MALWARE=0` to disable them and run
`ABUSECH_AUTH_KEY=… python -m ml.train … --dataset-in <downloaded dataset>` on a Linux box instead,
then upload `dataset.csv.gz` to `ml-dataset`.

## v2 (features v2, script classifier)

**Mach-O features v2** (`FEATURES_VERSION = 2`, 211 features, `pb-features --describe`): entitlement
risk score / private / TCC / apple-events keys, 7 more import families (TCC, Apple Events, executable
memory, env, ObjC runtime, file deletion, code-signing API), structural strings (distinct URL hosts,
IP URLs, non-standard ports, IPv4, base64 / hex blobs, `osascript -e`, `-authonly`, `curl -F`,
`| sh`, `base64 -d`, `sudo -S`, keychain DB, hidden tmp paths…), section entropy mean / std /
`__cstring` / `__const` / overlay / high-entropy byte ratio, CMS hints (secure timestamp, Developer
ID, development / App Store / Apple certificates, notarization-capable), CodeDirectory hardening
flags, SHA-1-only, tool-generated identifiers, signature not at the end of `__LINKEDIT`, load-command
anomalies (duplicate / weak non-system dylibs, absolute rpaths, non-standard dyld, missing UUID,
overlapping segments, out-of-bounds sections, entry outside `__TEXT`, misaligned / inconsistent
command sizes) and universal-binary consistency (file type / signature mismatch between slices, size
ratio, overlaps, unknown CPU). Bumping the layout drops the old rows from training: run once with
`refeaturize_max` (workflow input) to re-download the old positives by SHA-256, and regenerate
`ml/data/extra_clean_features.jsonl` on the Mac.

**Script classifier** (`python -m ml.train --kind script`, `pb-features --kind script`, crate
`pb-ml::script`, `SCRIPT_FEATURES_VERSION = 1`, 358 features): type detection (FasdUAS, shebang,
extension, sniffing), UTF-16 / compiled-AppleScript text views, base64 / hex / `\xNN`
de-obfuscation (depth 2, 1 MiB), lexical + obfuscation statistics, 48 indicator families (AMOS-style
password dialogs, `dscl -authonly`, `security find-generic-password`, `curl | bash`, decode pipes,
launchd / login-item persistence, `ditto` / `zip` + `curl -F` exfiltration, browser / wallet paths,
Gatekeeper / TCC tampering, Terminal hiding, JXA / Python / JS / Perl risky APIs, reverse shells…),
URL / IPv4 / blob counts and 256 hashed token n-gram buckets.

* Positives: MalwareBazaar script file types + macOS tags (`ml/data/script_sources.toml`). The `sh`
  type is dominated by Linux IoT droppers (documented there); family weighting limits their weight.
* Negatives: every script of the clean corpus (Homebrew pkg, installers, CPython stdlib, node's npm,
  git…) + `ml/data/script_corpus.toml` (script-heavy Homebrew formulae, SHA-256 from the formulae API)
  + optional `ml/data/extra_clean_script_features.jsonl` from the Mac (see `ml/data/README.md`;
  the only source of AppleScript / `/usr/bin` script negatives).
* Minimum data: 100 positives and 2000 negatives. Outputs and release assets are prefixed
  `script_` (`script_dataset.csv.gz`, `script_model.json`, `script_model_meta.json`…); the nightly DB
  ships them as `ml/script_model.json` + `ml/script_model_meta.json`.

**Training (both kinds)**: identical feature vectors collapsed (earliest kept, both-label vectors
dropped); time split of dated positives (MalwareBazaar `first_seen`: oldest 65 % train, next 15 %
validation, newest 20 % holdout), packages / families kept on one side of the hash split;
`1/sqrt(group size)` class-balanced sample weights (no `scale_pos_weight`); early stopping on the
time-split validation; threshold for FPR <= 0.1 % on validation negatives; Platt (small validation)
or isotonic calibration fitted on validation and stored in the meta (`calibration`; the threshold
stays on the raw score, the engine shows the calibrated probability). Published `metrics`:
`roc_auc`, `pr_auc`, `tpr_at_threshold`, `fpr_at_threshold`, `tpr_at_fpr_0_1`, `brier`, `n_pos`,
`n_neg`, `holdout_pos`, `holdout_neg`, `holdout_since`, `families`, `best_iteration`, `trained_at`
(shown by the app through `DbStatus.models`).

Manual run: *Actions > Weekly ML training > Run workflow* with `kind` = both | macho | script,
`max_new_samples`, `no_malware`, `refeaturize_max`.
