from pipeline.domains import Exclusions, host_from_url, normalize_domain, parse_list, prune_subdomains, render


def test_normalize_domain():
    assert normalize_domain("Ads.Example.COM.") == "ads.example.com"
    assert normalize_domain("*.tracker.net") == "tracker.net"
    assert normalize_domain("bücher.de") == "xn--bcher-kva.de"
    for bad in ("1.2.3.4", "::1", "localhost", "com", "-bad.com", "a..b.com", "x.local", "", "a" * 64 + ".com"):
        assert normalize_domain(bad) is None, bad


def test_parse_formats():
    hosts = "# c\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n0.0.0.0 1.2.3.4\n::1 ip6-localhost\n0.0.0.0 x.org # c\n"
    assert parse_list(hosts, "hosts") == {"ads.example.com", "x.org"}
    adblock = "! comment\n||track.example.com^\n||a.com^$important\n||b.com^$third-party\n@@||ok.com^\n||c.com/path^\n"
    assert parse_list(adblock, "adblock") == {"track.example.com", "a.com"}
    plain = "# Title\nfoo.com\nBAR.com\nnot a domain\n1.1.1.1\n"
    assert parse_list(plain, "domains") == {"foo.com", "bar.com"}
    assert parse_list(hosts + adblock, "auto") >= {"ads.example.com", "track.example.com"}


def test_host_from_url():
    assert host_from_url("hxxp://Evil.example.com:8080/a.sh") == "evil.example.com"
    assert host_from_url("http://45.1.2.3/x") is None
    assert host_from_url("evil.net/payload") == "evil.net"


def test_prune_subdomains_and_render():
    doms = {"example.com", "a.example.com", "b.a.example.com", "other.org", "x.other.org.uk"}
    assert prune_subdomains(doms) == {"example.com", "other.org", "x.other.org.uk"}
    assert render({"b.com", "a.com"}) == "a.com\nb.com\n"


def test_shared_hosts_and_allowlist_exclusions():
    ex = Exclusions.from_lines(
        ["# allow", "apple.com"],
        ["github.com", "drive.google.com", "*.googleusercontent.com", "cdn.discordapp.com"],
    )
    candidates = {
        "github.com",  # shared host itself
        "google.com",  # parent of a shared host
        "drive.google.com",
        "doc-0s-1c-docs.googleusercontent.com",  # under a shared wildcard
        "discordapp.com",  # parent of the discord CDN
        "evil.github.io",  # user-specific subdomain: still blockable
        "metrics.apple.com",  # allowlisted parent
        "evil.com",
    }
    kept, removed = ex.apply(candidates)
    assert kept == {"evil.github.io", "evil.com"}
    assert removed == len(candidates) - 2
    assert ex.excluded("github.com") and not ex.excluded("evil.com")
