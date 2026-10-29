"""GDPR broker list: Datenanfragen + Eraser parsing, validation, merge, pinned fetch, carry-over."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from pipeline import privacy
from pipeline.http import FetchError

from .conftest import FakeHttp

DN = "c0ba27dda41f660eccd0e6290a83ab8de5c3b6c0"
ER = "ff6cd50e84dfca809a2e08c18b9358a7b3e2e448"


def company(slug: str, cats: list[str], countries: list[str], email: str | None = None, **extra: object) -> bytes:
    doc: dict[str, object] = {
        "slug": slug,
        "name": f"{slug.title()} SAS",
        "categories": cats,
        "relevant-countries": countries,
    }
    if email is not None:
        doc["email"] = email
    doc.update(extra)
    return json.dumps(doc).encode()


def dn_tarball(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def sample_tarball() -> bytes:
    top = f"data-{DN}"
    return dn_tarball(
        {
            f"{top}/companies/criteo.json": company(
                "criteo", ["ads"], ["all"], "dpo@criteo.com", web="https://www.criteo.com/", webform="http://x"
            ),
            f"{top}/companies/sls.json": company("sls-data", ["ads", "addresses"], ["fr"], "dpo@sls-data.fr"),
            f"{top}/companies/schufa.json": company("schufa", ["credit agency"], ["de"], "dpo@schufa.de"),
            f"{top}/companies/risk.json": company("riskident", ["credit agency"], ["all"], "contact@riskident.com"),
            f"{top}/companies/noemail.json": company("noemail", ["ads"], ["all"]),
            f"{top}/companies/bad.json": company("bad", ["ads"], ["all"], "not an email"),
            f"{top}/companies/shop.json": company("shop", ["commerce"], ["all"], "dpo@shop.fr"),
            f"{top}/companies/garbage.json": b"{not json",
            f"{top}/templates/fr/erasure.txt": b"x",
            f"{top}/companies/sub/evil.json": company("evil", ["ads"], ["all"], "a@evil.com"),
        }
    )


ERASER_YAML = b"""brokers:
    - id: spokeo
      name: Spokeo
      email: privacy@spokeo.com
      website: https://www.spokeo.com
      opt_out_url: https://www.spokeo.com/optout
      region: us
      category: people-search
    - id: acxiom
      name: Acxiom
      email: optout@acxiom.com
      region: global
      category: marketing
    - id: criteo
      name: Criteo (copy)
      email: DPO@criteo.com
      region: global
      category: marketing
    - id: riskident
      name: Other RiskIdent
      email: privacy@other.com
      region: us
      category: marketing
    - id: formonly
      name: Form Only
      opt_out_url: https://form.example/optout
      region: us
      category: people-search
    - id: nothing
      name: Nothing
      region: us
    - id: euro
      name: Euro Broker
      email: a@euro.eu
      region: eu
"""


def test_datenanfragen_selection() -> None:
    got = {b.id: b for b in privacy.parse_datenanfragen(sample_tarball())}
    assert set(got) == {"criteo", "sls-data", "riskident"}
    assert got["criteo"].region == "eu" and got["criteo"].category == "ads"
    assert got["criteo"].website == "https://www.criteo.com/"
    assert got["criteo"].opt_out_url is None  # http:// dropped
    assert got["sls-data"].category == "addresses"  # priority over ads
    assert got["riskident"].category == "credit"
    assert all(b.source == "datenanfragen" for b in got.values())
    with pytest.raises(FetchError):
        privacy.parse_datenanfragen(b"not a tarball")


def test_eraser_and_merge() -> None:
    er = privacy.parse_eraser(ERASER_YAML)
    assert [b.id for b in er] == ["spokeo", "acxiom", "criteo", "riskident", "formonly"]
    assert er[-1].email is None and er[-1].opt_out_url == "https://form.example/optout"
    merged = privacy.merge(privacy.parse_datenanfragen(sample_tarball()), er)
    ids = [b.id for b in merged]
    assert len(ids) == len(set(ids))
    # Criteo (same email, other case) deduplicated in favour of Datenanfragen; RiskIdent id collision.
    assert sum(1 for b in merged if b.email and b.email.lower() == "dpo@criteo.com") == 1
    assert "eraser-riskident" in ids and "riskident" in ids
    assert ids == sorted(ids)
    with pytest.raises(FetchError):
        privacy.parse_eraser(b"just: text")
    with pytest.raises(FetchError):
        privacy.parse_eraser(b"\xff\xfe")


def test_validation_helpers() -> None:
    assert privacy.is_email("q.m+x@sub.example.fr")
    for bad in ("q@localhost", "a b@x.fr", "<a@x.fr>", "a@-x.fr", "@x.fr", "a@x..fr"):
        assert not privacy.is_email(bad), bad
    assert privacy.https_url(" https://a.fr/x ") == "https://a.fr/x"
    assert privacy.https_url("https://a b") is None and privacy.https_url(None) is None
    assert privacy.slugify(" Foo Bar/Baz ") == "foo-bar-baz"


def test_fetch_pinned_and_carry_over(tmp_path) -> None:
    routes = {
        privacy.DATENANFRAGEN_TARBALL.format(commit=DN): sample_tarball(),
        privacy.ERASER_YAML.format(commit=ER): ERASER_YAML,
    }
    http = FakeHttp(routes)
    data, n = privacy.fetch(http, DN, ER, min_brokers=5)
    doc = json.loads(data)
    assert doc["format"] == 1 and doc["sources"] == {"datenanfragen": DN, "eraser": ER}
    assert n == len(doc["brokers"]) == privacy.count(data) == 7
    assert all("email" in b or "opt_out_url" in b for b in doc["brokers"])
    assert all(
        set(b) <= {"id", "name", "email", "website", "opt_out_url", "region", "category", "source"}
        for b in doc["brokers"]
    )
    with pytest.raises(FetchError, match="only 7 brokers"):
        privacy.fetch(http, DN, ER, min_brokers=50)
    with pytest.raises(FetchError, match="40-hex"):
        privacy.fetch(http, "main", ER)
    prev = tmp_path / "prev"
    (prev / "privacy").mkdir(parents=True)
    (prev / "privacy" / "brokers.json").write_bytes(data)
    assert privacy.carry_over(prev) == {privacy.BUNDLE_PATH: data}
    assert privacy.carry_over(tmp_path / "none") == {}
