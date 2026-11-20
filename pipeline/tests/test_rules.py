"""Our rules (rules/*.yar): compile with yara-x and fire on synthetic positives, not on look-alikes."""

import base64
import json
import re
from pathlib import Path

import pytest
import yara_x

from pipeline.yara_rules import load_local_rules, rule_spans, validate

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
REQUIRED_META = {"author", "description", "family", "severity", "reference", "date"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


@pytest.fixture(scope="module")
def scanner() -> yara_x.Scanner:
    c = yara_x.Compiler()
    for f in sorted(RULES_DIR.glob("*.yar")):
        c.new_namespace(f.stem)
        c.add_source(f.read_text(), origin=f.name)
    return yara_x.Scanner(c.build())


def hits(scanner: yara_x.Scanner, data: bytes) -> set[str]:
    return {r.identifier for r in scanner.scan(data).matching_rules}


def test_all_rule_files_valid_with_metadata():
    files = load_local_rules(RULES_DIR, "parabellum")
    rep = validate(files)
    assert rep.rejected_files == [] and rep.renamed_away == []
    assert len(rep.accepted) == len(files) >= 10
    for f in files:
        assert yara_x.compile(f.text).scan(b"").matching_rules == ()
        _, spans = rule_spans(f.text)
        for name, start, end in spans:
            block = f.text[start:end].split("strings:")[0]
            meta = dict(re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"', block, re.MULTILINE))
            assert set(meta) >= REQUIRED_META, (f.name, name, REQUIRED_META - set(meta))
            assert meta["severity"] in SEVERITIES
            assert meta["reference"].startswith("https://")
            assert name.startswith("Parabellum_MacOS_")


SAMPLES_FILE = Path(__file__).with_name("rule_samples.json")


def _load() -> tuple[dict[str, bytes], list[bytes]]:
    """Positives (rule -> bytes) and benign look-alikes. Stored base64-encoded: in clear text they would
    make this repo trip its own rules (and other scanners)."""
    raw = json.loads(SAMPLES_FILE.read_text())
    positives = {k: base64.b64decode(v) for k, v in raw["positives"].items()}
    return positives, [base64.b64decode(v) for v in raw["lookalikes"]]


POSITIVES, LOOKALIKES = _load()


@pytest.mark.parametrize("rule", sorted(POSITIVES))
def test_rule_fires_on_synthetic_positive(scanner, rule):
    assert rule in hits(scanner, POSITIVES[rule])


def test_every_rule_has_a_positive(scanner):
    files = load_local_rules(RULES_DIR, "parabellum")
    all_rules = {r for f in validate(files).accepted for r in f.rules}
    assert all_rules == set(POSITIVES)


@pytest.mark.parametrize("benign", LOOKALIKES)
def test_rules_quiet_on_lookalikes(scanner, benign):
    assert hits(scanner, benign) == set()
