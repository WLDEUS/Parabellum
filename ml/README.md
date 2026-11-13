# Mach-O classifier (weekly)

`.github/workflows/ml-train.yml` (Sundays 04:41 UTC) runs:

```sh
python -m ml.train --pb-features target/release/pb-features --out out/ml \
  --dataset-in prev/dataset.csv.gz --metrics-in prev/metrics.jsonl --current-model current \
  --corpus-cache .cache/corpus
bash ml/publish.sh out/ml
```

* **Features** come from `pb-features` (crate `pb-ml`), the same extractor the daemon uses.
* **Dataset** (`ml-dataset` release, `dataset.csv.gz`): `sha256,label,features_version,<names…>`,
  cumulative, deduplicated by SHA-256, rows of another `features_version` dropped. Positives: new
  MalwareBazaar samples of type `macho` (direct Mach-O only, never binaries found inside malicious
  DMGs). Negatives: Mach-O of the clean corpus (`pipeline/data/clean_corpus.toml`) + optional
  `ml/data/extra_clean_features.jsonl` from the owner's Mac (see `ml/data/README.md`; needed to reach
  the 1000-negative minimum quickly). No sample is ever stored.
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

# Domain model (daily)

`.github/workflows/ml-domains.yml` (19:43 UTC, before the 21:17 UTC nightly DB build) runs
`python -m ml.domains.train` then `bash ml/domains/publish.sh out/ml-domain`.

* **Features**: `pb-domain-features` (crate `pb-intel`), the extractor the daemon uses: lexical shape,
  randomness, abused TLDs, shared hosting platforms, punycode / homoglyphs, typosquat distance and
  brand-in-subdomain against `pipeline/data/brands.txt` (the exact file ships with the model; its SHA-256
  is in the meta and checked by the pipeline and the client).
* **Positives**: listed domains from the signed `pipeline-state.tar.gz` of `db-latest` (URLhaus,
  ThreatFox, phishing-filter, HaGeZi TIF), kept with their first-seen day in `ml-domain-dataset`.
  **Negatives**: Tranco top-1M + its subdomain variant, minus anything listed (not stored).
* **Split**: positives first seen in the last 14 days = holdout (new campaigns) once history exists;
  hash buckets otherwise. Alert threshold: FPR <= 0.05 % on validation negatives; block threshold:
  FPR <= 0.01 %. Gate: holdout FPR <= 0.05 % and TPR >= the current model's.
* **Release** `ml-domain-latest`: `domain_model.json`, `domain_model_meta.json`
  (`threshold`, `block_threshold`, `brands_sha256`, metrics), `domain_brands.txt`, `domain_top.txt`
  (popular registrable domains the client never scores).

Policy: the client only alerts on model verdicts; blocking is opt-in (`intelligence.block_ml_domains`) and
never applies to the rules-only fallback used before a model exists.
