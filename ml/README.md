# Mach-O classifier (weekly)

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
