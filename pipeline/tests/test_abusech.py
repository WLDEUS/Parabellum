import pytest

from pipeline.abusech import fill_key, maybe_unzip, parse_threatfox_csv, parse_urlhaus_csv
from pipeline.http import FetchError, redact

from .conftest import zip_bytes

URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)      #
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-25 01:00:00","http://evil-payload.example.net/a.sh","online","2026-10-25 01:00:00","malware_download","sh","https://urlhaus.abuse.ch/url/1/","r"
"2","2026-10-25 01:00:00","http://45.9.1.2/x86","online","2026-10-25 01:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/2/","r"
"3","2026-10-25 01:00:00","https://github.com/someone/repo/raw/main/x.zip","online","2026-10-25","malware_download","zip","u","r"
"""

THREATFOX = """# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2026-10-25 00:00:00", "1", "c2.badguy.net", "domain", "botnet_cc", "x", "", "X", "", "100", "", "", "0", "r"
"2026-10-25 00:00:00", "2", "http://drop.example.org/p", "url", "payload_delivery", "x", "", "X", "", "75", "", "", "0", "r"
"2026-10-25 00:00:00", "3", "1.2.3.4:443", "ip:port", "botnet_cc", "x", "", "X", "", "100", "", "", "0", "r"
"2026-10-25 00:00:00", "4", "lowconf.example", "domain", "botnet_cc", "x", "", "X", "", "25", "", "", "0", "r"
"""


def test_urlhaus_domains_only():
    assert parse_urlhaus_csv(URLHAUS) == {"evil-payload.example.net", "github.com"}


def test_threatfox_zip_and_confidence():
    text = maybe_unzip(zip_bytes({"full.csv": THREATFOX.encode()}))
    assert parse_threatfox_csv(text, min_confidence=50) == {"c2.badguy.net", "drop.example.org"}


def test_key_substitution_and_redaction():
    url = fill_key("https://mb-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv", "s3cr3t")
    assert "s3cr3t" in url
    assert redact(f"GET {url}: 403", ["s3cr3t"]) == "GET https://mb-api.abuse.ch/v2/files/exports/***/recent.csv: 403"
    with pytest.raises(FetchError):
        fill_key("https://x/{ABUSECH_AUTH_KEY}/a", "")
