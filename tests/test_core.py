import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from php_patch_lag import channels  # noqa: E402
from php_patch_lag.core import (  # noqa: E402
    delay_minutes, group_advisories, make_channel_entry, poll_first_seen, update_poll_state,
    upstream_version, ver_key, version_ge)

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


def jfix(name):
    return json.loads(fixture(name))


class VersionTests(unittest.TestCase):
    def test_upstream_version(self):
        self.assertEqual(upstream_version("8.2.35-1+ubuntu24.04.1+deb.sury.org+1"), "8.2.35")
        self.assertEqual(upstream_version("1:8.3.6-0ubuntu0.24.04.13"), "8.3.6")
        self.assertEqual(upstream_version("8.5.0~rc1-1"), "8.5.0")

    def test_version_ge(self):
        self.assertTrue(version_ge("8.2.35-1+deb.sury.org", "8.2.35"))
        self.assertTrue(version_ge("8.2.36-1", "8.2.35"))
        self.assertFalse(version_ge("8.2.34-1", "8.2.35"))
        self.assertTrue(version_ge("8.10.0-1", "8.9.9"))  # numeric, not lexical
        self.assertFalse(version_ge("8.5.0~rc1-1", "8.5.0"))  # pre-release sorts below final

    def test_ver_key_orders_revisions(self):
        self.assertLess(ver_key("8.2.35-1"), ver_key("8.2.35-2"))
        self.assertLess(ver_key("8.2.35-9"), ver_key("8.2.35-10"))


class GroupingTests(unittest.TestCase):
    def setUp(self):
        self.releases = group_advisories(jfix("advisories.json"))

    def test_groups_by_time_and_skips_cveless(self):
        self.assertEqual([r["id"] for r in self.releases], ["2026-07-30", "2026-09-24", "2026-10-21"])

    def test_release_fields(self):
        r = self.releases[-1]
        self.assertEqual(r["branches"], {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"})
        self.assertEqual(r["cves"], ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(r["upstream_at"], "2026-10-21T13:34:13Z")  # earliest published_at
        self.assertEqual(r["upstream_precision"], "exact")
        self.assertIsNotNone(r["max_cvss"])
        self.assertEqual(r["max_severity"], "critical")
        self.assertEqual(r["cve_details"]["CVE-2026-109618"]["severity"], "critical")

    def test_gap_splits_groups(self):
        base = {"state": "published", "cve_id": "CVE-1", "vulnerabilities": [{"patched_versions": "8.2.1"}]}
        a = dict(base, published_at="2026-01-01T00:00:00Z")
        b = dict(base, cve_id="CVE-2", published_at="2026-01-01T05:00:00Z",
                 vulnerabilities=[{"patched_versions": "8.2.2"}])
        c = dict(base, cve_id="CVE-3", published_at="2026-01-01T20:00:00Z")
        r = group_advisories([c, b, a])
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0]["branches"], {"8.2": "8.2.2"})  # highest patched wins per branch
        self.assertEqual(r[1]["id"], "2026-01-01-2")  # same-day id collision gets a suffix


class DelayTests(unittest.TestCase):
    def test_delay(self):
        self.assertEqual(delay_minutes("2026-10-21T18:00:56Z", "2026-10-21T13:34:13Z"), 267)
        self.assertEqual(delay_minutes("2026-10-21T13:00:00Z", "2026-10-21T13:34:13Z"), -34)

    def test_channel_entry_latest_and_completeness(self):
        rel = {"upstream_at": "2026-10-21T13:34:13Z"}
        units = {"8.2": {"at": "2026-10-21T15:00:00Z"}, "8.3": {"at": "2026-10-21T16:00:00Z"}, "8.4": {"at": None}}
        e = make_channel_entry(rel, units, ["8.2", "8.3", "8.4"], "exact", "src")
        self.assertEqual(e["at"], "2026-10-21T16:00:00Z")
        self.assertEqual(e["first_fix_at"], "2026-10-21T15:00:00Z")
        self.assertEqual(e["first_fix_delay_minutes"], 86)
        self.assertFalse(e["complete"])
        self.assertEqual(e["delay_minutes"], 146)
        units["8.4"]["at"] = "2026-10-21T17:00:00Z"
        self.assertTrue(make_channel_entry(rel, units, ["8.2", "8.3", "8.4"], "exact", "src")["complete"])
        self.assertIsNone(make_channel_entry(rel, {"8.2": {"at": None}}, ["8.2"], "exact", "src"))


class PollTests(unittest.TestCase):
    def test_first_poll_is_baseline_then_new_versions_get_time(self):
        st = {}
        update_poll_state(st, ["8.2.34-1"], "2026-10-21T19:45:00Z")
        self.assertIsNone(st["8.2.34-1"]["first_seen"])
        self.assertEqual(st["8.2.34-1"]["baseline_at"], "2026-10-21T19:45:00Z")
        update_poll_state(st, ["8.2.34-1", "8.2.35-1"], "2026-10-21T19:50:00Z")
        self.assertEqual(st["8.2.35-1"]["first_seen"], "2026-10-21T19:50:00Z")
        self.assertEqual(st["8.2.35-1"]["precision"], "hourly-poll")
        update_poll_state(st, ["8.2.34-1", "8.2.35-1"], "2026-10-21T20:50:00Z")  # idempotent
        self.assertEqual(st["8.2.35-1"]["first_seen"], "2026-10-21T19:50:00Z")

    def test_manual_seed_does_not_prevent_baseline(self):
        st = {"8.2.35-1": {"first_seen": "2026-10-21T19:50:00Z", "source": "observed by GreenScript"}}
        update_poll_state(st, ["8.2.33-1", "8.2.35-1"], "2026-10-22T00:00:00Z")
        self.assertIsNone(st["8.2.33-1"]["first_seen"])
        self.assertEqual(st["8.2.35-1"]["source"], "observed by GreenScript")

    def test_lowest_fixed_version_is_credited(self):
        st = {"8.2.34-1": {"first_seen": None}, "8.2.35-1": {"first_seen": "A"}, "8.2.36-1": {"first_seen": "B"}}
        self.assertEqual(poll_first_seen(st, "8.2.35")[0], "8.2.35-1")
        self.assertEqual(poll_first_seen(st, "8.2.34")[0], "8.2.34-1")  # baseline: no time, not 8.2.35's
        self.assertIsNone(poll_first_seen(st, "8.2.37")[0])

    def test_per_cve_entry_first_and_all_fixed(self):
        rel = {"upstream_at": "2026-10-21T13:00:00Z"}
        per = {"CVE-1": {"at": "2026-10-21T14:00:00Z", "advisory": "USN-1", "version": "1"},
               "CVE-2": {"at": "2026-10-22T14:00:00Z", "advisory": "USN-2", "version": "2"},
               "CVE-3": {"at": None}}
        e = channels._per_cve_entry(rel, per, 1, "src", None)
        self.assertEqual((e["cves_fixed"], e["cves_total"], e["cves_ignored"]), (2, 3, 1))
        self.assertFalse(e["complete"])
        self.assertEqual(e["first_fix_delay_minutes"], 60)
        self.assertEqual(e["advisories"], ["USN-1", "USN-2"])
        per["CVE-3"] = {"at": "2026-10-23T00:00:00Z", "advisory": "USN-2", "version": "2"}
        e = channels._per_cve_entry(rel, per, 0, "src", None)
        self.assertTrue(e["complete"])
        self.assertEqual(e["at"], "2026-10-23T00:00:00Z")
        self.assertEqual(e["advisories"], ["USN-1", "USN-2"])

    def test_collect_poll_entry(self):
        class Ctx:
            state = {"poll": {"serverpilot-noble": {"sp-php8.2": {"8.2.35-1": {
                "first_seen": "2026-10-21T19:50:00Z", "precision": "5-min-poll", "source": "observed by GreenScript"}},
                "sp-php8.3": {"8.3.36-1": {"first_seen": None, "baseline_at": "2026-10-22T00:49:00Z"}}}}}
        rel = {"upstream_at": "2026-10-21T13:34:13Z", "branches": {"8.2": "8.2.35", "8.3": "8.3.36"}}
        e = channels.collect_poll(Ctx(), rel, "serverpilot-noble")
        self.assertEqual(e["at"], "2026-10-21T19:50:00Z")
        self.assertEqual(e["delay_minutes"], 376)
        self.assertEqual(e["first_fix_delay_minutes"], 376)
        self.assertEqual(e["precision"], "5-min-poll")
        self.assertFalse(e["complete"])
        self.assertIsNone(e["per_branch"]["8.3"]["at"])


class ParserFixtureTests(unittest.TestCase):
    def test_launchpad(self):
        entries, nxt = channels.parse_launchpad_page(jfix("launchpad_php8.2-fpm.json"))
        self.assertTrue(entries)
        self.assertTrue(nxt)
        hit = channels.ondrej_first_published(entries, "noble", "8.2.35")
        self.assertEqual(hit["published"], "2026-10-21T18:00:56Z")
        self.assertEqual(hit["arch"], "amd64")
        self.assertIsNone(channels.ondrej_first_published(entries, "noble", "8.2.99"))

    def test_phpnet_fixture_shape(self):
        d = jfix("phpnet_8.2.json")
        self.assertEqual(d["8.2.35"]["date"], "21 Oct 2026")

    def test_ubuntu_cve(self):
        p = channels.parse_ubuntu_cve(jfix("ubuntu_cve.json"))
        self.assertEqual(p["noble"]["status"], "released")
        self.assertEqual(p["noble"]["fixed_version"], "8.3.6-0ubuntu0.24.04.13")
        self.assertEqual(p["jammy"]["usn"], ("USN-8948-1", "2026-10-21T13:56:19Z"))

    def test_debian_cve(self):
        p = channels.parse_debian_cve(fixture("debian_cve.html"))
        self.assertEqual(p["bookworm"]["advisory"], "DLA-4848-1")
        self.assertEqual(p["trixie"]["version"], "8.4.27-1~deb13u1")
        self.assertEqual(p["trixie"]["status"], "fixed")

    def test_debian_msg_date(self):
        self.assertEqual(channels.parse_debian_msg_date(fixture("debian_msg.html")), "2026-10-21T13:45:09Z")

    def test_docker(self):
        commits = jfix("docker_commits.json")
        self.assertEqual(len(commits[0]["sha"]), 40)
        man = fixture("docker_library_php.txt")
        self.assertTrue(channels.docker_has_tag(man, "8.2.35"))
        self.assertFalse(channels.docker_has_tag(man, "8.2.3"))  # no prefix match
        self.assertFalse(channels.docker_has_tag(man, "8.2.36"))

    def test_packages_index(self):
        out = channels.parse_packages(fixture("packages_serverpilot.txt"), {"sp-php8.2": "8.2"})
        self.assertEqual(out["sp-php8.2"], ["8.2.33-1", "8.2.34-1", "8.2.35-1"])
        self.assertNotIn("sp-apache", out)


if __name__ == "__main__":
    unittest.main()
