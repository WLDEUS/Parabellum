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


def _flaky_scans(monkeypatch, fail):
    """Make ``scan_file`` raise when ``fail(rule file names of the scanner, path)`` is true."""
    import pipeline.fpgate as fpgate

    real_compile, real_new, real_scan = fpgate.compile_all, fpgate.new_scanner, fpgate.scan_file
    names_of_rules: dict[int, list[str]] = {}
    names_of_scanner: dict[int, list[str]] = {}

    def compile_all(files):
        rules = real_compile(files)
        names_of_rules[id(rules)] = [f.name for f in files]
        return rules

    def new_scanner(rules, timeout_s=30):
        sc = real_new(rules, timeout_s)
        names_of_scanner[id(sc)] = names_of_rules[id(rules)]
        return sc

    def scan_file(scanner, path):
        if fail(names_of_scanner[id(scanner)], path):
            raise TimeoutError("timeout")
        return real_scan(scanner, path)

    monkeypatch.setattr(fpgate, "compile_all", compile_all)
    monkeypatch.setattr(fpgate, "new_scanner", new_scanner)
    monkeypatch.setattr(fpgate, "scan_file", scan_file)


def _gate_files(tmp_path):
    clean = tmp_path / "corpus"
    clean.mkdir()
    (clean / "big.bin").write_bytes(MACHO + b"CLEAN_MARKER " * 10)
    (clean / "small").write_bytes(MACHO + b"nothing to see")
    rules = [
        RuleFile("x__fp.yar", "x", 'rule FP_Rule { strings: $a = "CLEAN_MARKER" condition: $a }\n'),
        RuleFile(
            "x__slow.yar",
            "x",
            'rule Slow_A { strings: $a = "NEVER_1" condition: $a }\nrule Slow_B { condition: Slow_A }\n',
        ),
        RuleFile("x__ok.yar", "x", 'rule Fine { strings: $a = "NEVER_2" condition: $a }\n'),
    ]
    return sorted(clean.iterdir()), rules


def test_scan_error_is_not_a_pass(tmp_path, monkeypatch):
    # Regression (M2): a timeout used to count as "no match", so the rule matching the clean file
    # in the same scan (FP_Rule) shipped. Now the file is rescanned rule file by rule file.
    paths, rules = _gate_files(tmp_path)
    _flaky_scans(monkeypatch, lambda names, p: p.name == "big.bin" and "x__slow.yar" in names)
    res = run_fp_gate(rules, paths)
    assert {f.name: f.rules for f in res.kept} == {"x__ok.yar": ["Fine"]}
    rejected = {(r.file, r.rule): r.sample for r in res.rejected}
    assert rejected[("x__fp.yar", "FP_Rule")] == "big.bin"
    assert "scan error" in rejected[("x__slow.yar", "Slow_A")] and ("x__slow.yar", "Slow_B") in rejected
    assert res.dropped_files == ["x__fp.yar", "x__slow.yar"]  # x__fp.yar: no rule left
    assert res.timeouts == 1 and res.unscannable == []


def test_combined_timeout_alone_drops_nothing(tmp_path, monkeypatch):
    # The combined scan times out but every rule file scans fine on its own: only real FPs go.
    paths, rules = _gate_files(tmp_path)
    _flaky_scans(monkeypatch, lambda names, p: p.name == "big.bin" and len(names) > 1)
    res = run_fp_gate(rules, paths)
    assert {f.name for f in res.kept} == {"x__slow.yar", "x__ok.yar"}
    assert {(r.file, r.rule) for r in res.rejected} == {("x__fp.yar", "FP_Rule")}
    assert res.timeouts == 1 and res.unscannable == []


def test_unscannable_clean_file_is_reported(tmp_path, monkeypatch):
    paths, rules = _gate_files(tmp_path)
    _flaky_scans(monkeypatch, lambda names, p: p.name == "small")
    res = run_fp_gate(rules, paths)
    assert res.unscannable == ["small"]
    assert {f.name for f in res.kept} == {"x__slow.yar", "x__ok.yar"}  # not the rules' fault
