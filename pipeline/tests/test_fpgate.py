from pipeline.fpgate import fp_rate, run_fp_gate
from pipeline.yara_rules import RuleFile

from .conftest import MACHO


def test_fp_gate_removes_matching_rules(tmp_path):
    clean = tmp_path / "corpus"
    clean.mkdir()
    (clean / "tool").write_bytes(MACHO + b"CLEAN_MARKER legit")
    (clean / "install.sh").write_bytes(b"#!/bin/sh\necho hello\n")
    (clean / "notes.txt").write_bytes(b"nothing")
    files = [
        RuleFile(
            "x__fp.yar",
            "x",
            'rule FP_Rule { strings: $a = "CLEAN_MARKER" condition: $a }\n'
            'rule Good_Rule { strings: $a = "EVIL_ONLY" condition: $a }\n',
        ),
        RuleFile(
            "x__dep.yar", "x", 'rule Base { strings: $a = "hello" condition: $a }\nrule Uses_Base { condition: Base }\n'
        ),
        RuleFile("x__ok.yar", "x", 'rule Unrelated { strings: $a = "NEVER_THERE" condition: $a }\n'),
    ]
    paths = sorted(clean.iterdir())
    res = run_fp_gate(files, paths)
    kept = {f.name: f.rules for f in res.kept}
    assert kept == {"x__fp.yar": ["Good_Rule"], "x__ok.yar": ["Unrelated"]}
    rejected = {(r.file, r.rule) for r in res.rejected}
    assert ("x__fp.yar", "FP_Rule") in rejected and ("x__dep.yar", "Base") in rejected
    assert res.dropped_files == ["x__dep.yar"]
    assert res.files_scanned == 3 and res.files_matched_before == 2
    assert len(res.clean_hashes) == 2  # Mach-O + script; plain text is not allowlisted
    assert len(res.macho_files) == 1


def test_fp_rate():
    assert fp_rate(0, 0, 0, 0) is None
    assert fp_rate(1000, 0, 0, 1) == 0.001
