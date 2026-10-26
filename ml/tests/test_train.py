import json
import sys
import textwrap

from ml import train

from .conftest import NAMES, synth_rows


def test_train_and_gate_promotes_then_keeps(tmp_path):
    rows = synth_rows(400, 2500)
    first = train.train_and_gate(rows, NAMES, 1, 1_792_929_600, tmp_path / "m1", None)
    assert first["trained"] and first["promoted"], first
    assert (tmp_path / "m1" / "macho_model.json").is_file()
    # Same data again: equal TPR -> promoted (>=); against a harder current model it is kept.
    second = train.train_and_gate(rows, NAMES, 1, 1_792_929_600, tmp_path / "m2", tmp_path / "m1")
    assert second["current"] is not None and second["current_note"] == "ok"
    assert second["promoted"] == (second["new"]["tpr"] >= second["current"]["tpr"])
    meta = json.loads((tmp_path / "m1" / "model_meta.json").read_text())
    meta["threshold"] = 0.0  # a current model flagging everything has FPR 1 -> drift -> replaced
    (tmp_path / "m1" / "model_meta.json").write_text(json.dumps(meta))
    third = train.train_and_gate(rows, NAMES, 1, 1_792_929_600, tmp_path / "m3", tmp_path / "m1")
    assert third["promoted"] and "drifted" in third["reason"]


def test_run_with_fake_pb_features_and_min_data_guard(tmp_path):
    fake = tmp_path / "pb-features"
    fake.write_text(
        textwrap.dedent(f"""\
        #!{sys.executable}
        import json, sys
        if sys.argv[1:] == ["--names"]:
            print(json.dumps({NAMES!r}))
        """)
    )
    fake.chmod(0o755)
    extra = tmp_path / "extra.jsonl"
    lines = [
        json.dumps({"sha256": r.sha256, "label": 0, "features_version": 1, "features": r.features})
        for r in synth_rows(0, 50, seed=3)
    ]
    extra.write_text("\n".join(lines) + "\n")
    out = tmp_path / "out"
    args = train.parse_args(
        ["--pb-features", str(fake), "--out", str(out), "--extra-clean", str(extra), "--no-malware", "--now", "1"]
    )
    assert train.run(args) == 0
    decision = json.loads((out / "decision.json").read_text())
    assert decision["trained"] is False and "not enough data" in decision["reason"]
    assert decision["n_neg"] == 50 and not (out / "model").exists()
    assert len((out / "metrics.jsonl").read_text().splitlines()) == 1
    # Second run appends to the metrics history and reuses the dataset.
    args2 = train.parse_args(
        [
            "--pb-features",
            str(fake),
            "--out",
            str(tmp_path / "out2"),
            "--dataset-in",
            str(out / "dataset.csv.gz"),
            "--metrics-in",
            str(out / "metrics.jsonl"),
            "--no-malware",
            "--extra-clean",
            str(tmp_path / "none"),
        ]
    )
    assert train.run(args2) == 0
    assert len((tmp_path / "out2" / "metrics.jsonl").read_text().splitlines()) == 2
    assert json.loads((tmp_path / "out2" / "decision.json").read_text())["n_neg"] == 50
