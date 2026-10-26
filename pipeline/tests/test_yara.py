import io
import tarfile

from pipeline.yara_rules import (
    RuleFile,
    bundle_name,
    iter_tarball_members,
    remove_rules,
    rule_names,
    rule_spans,
    validate,
)

GOOD = """import "math"
// rule Fake_In_Comment { condition: true }
rule A : tag1 { strings: $a = "rule NotARule" condition: $a }
private rule B { condition: filesize > 0 }
rule C { condition: B and filesize < 10 }
"""
BROKEN = 'rule Broken { strings: $a = "x" condition: $b }'


def test_rule_names_ignore_comments_and_strings():
    assert rule_names(GOOD) == ["A", "B", "C"]
    header, spans = rule_spans(GOOD)
    assert header.startswith('import "math"')
    assert [s[0] for s in spans] == ["A", "B", "C"]


def test_remove_rules_keeps_others():
    out = remove_rules(GOOD, ["A"])
    assert rule_names(out) == ["B", "C"] and 'import "math"' in out


def test_validate_drops_broken_and_duplicates():
    files = [
        RuleFile("a.yar", "s", GOOD),
        RuleFile("b.yar", "s", BROKEN),
        RuleFile("c.yar", "s", "rule A { condition: true }\nrule D { condition: true }"),
        RuleFile("d.yar", "s", "rule A { condition: true }"),
    ]
    rep = validate(files)
    assert [f.name for f in rep.accepted] == ["a.yar", "c.yar"] or [f.name for f in rep.accepted] == ["a.yar"]
    names = {f.name: f.rules for f in rep.accepted}
    assert names["a.yar"] == ["A", "B", "C"]
    assert ("c.yar", "A") in rep.renamed_away and names.get("c.yar") == ["D"]
    rejected = dict(rep.rejected_files)
    assert "b.yar" in rejected and "d.yar" in rejected
    assert rep.rule_count == 4


def test_bundle_name():
    assert bundle_name("elastic", "yara/rules/MacOS_Trojan_X.yar") == "elastic__MacOS_Trojan_X.yar"
    assert bundle_name("x y", "a b.yara") == "x_y__a_b.yar"
    assert len(bundle_name("s", "n" * 200 + ".yar")) <= 90


def test_tarball_filtering():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in {
            "repo-sha/yara/rules/MacOS_A.yar": b"rule a { condition: true }",
            "repo-sha/yara/rules/Macos_B.yar": b"rule b { condition: true }",
            "repo-sha/yara/rules/Windows_C.yar": b"rule c { condition: true }",
            "repo-sha/README.md": b"x",
        }.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    got = dict(iter_tarball_members(buf.getvalue(), ["yara/rules/macos_*.yar"]))
    assert set(got) == {"yara/rules/MacOS_A.yar", "yara/rules/Macos_B.yar"}
