#!/usr/bin/env python3
"""Collect PHP security releases and per-channel fix availability into data/.

Idempotent: only adds/updates, never deletes. Per-channel errors are logged and
skipped. Exit status is non-zero only when nothing at all could be fetched."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from php_patch_lag import channels, http
from php_patch_lag.core import VERSION_RE, branch_of, group_advisories, iso, parse_ts

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
BACKFILL_DAYS = 365
RECHECK_YOUNG_DAYS = 30   # incomplete entries younger than this are rechecked every run
RECHECK_OLD_DAYS = 7      # older incomplete entries are rechecked at most this often
ADVISORIES = "https://api.github.com/repos/php/php-src/security-advisories?per_page=100"
PHPNET = "https://www.php.net/releases/index.php?json&version=%s&max=30"

CHANNELS = {
    "ondrej-ubuntu-noble": lambda c, r: channels.collect_ondrej_ubuntu(c, r, "noble"),
    "ondrej-ubuntu-jammy": lambda c, r: channels.collect_ondrej_ubuntu(c, r, "jammy"),
    "docker-official": channels.collect_docker,
}
for _code in channels.UBUNTU_RELEASES:
    CHANNELS["ubuntu-" + _code] = (lambda s: lambda c, r: channels.collect_ubuntu(c, r, s))(_code)
for _suite in channels.DEBIAN_SUITES:
    CHANNELS["debian-" + _suite] = (lambda s: lambda c, r: channels.collect_debian(c, r, s))(_suite)
for _name in channels.POLL_CHANNELS:
    CHANNELS[_name] = (lambda n: lambda c, r: channels.collect_poll(c, r, n))(_name)


class Ctx:
    def __init__(self, state, now):
        self.state, self.now, self.cache = state, now, {}


def log(msg):
    print(msg, flush=True)


def load(name, default):
    try:
        with open(os.path.join(DATA, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save(name, obj):
    """Write only if content changed, so unchanged runs produce no commit."""
    text = json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    path = os.path.join(DATA, name)
    try:
        if open(path).read() == text:
            return
    except FileNotFoundError:
        pass
    os.makedirs(DATA, exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def phpnet_dates(branches):
    """{version: 'YYYY-MM-DD'} from php.net for the given branches (best effort)."""
    out = {}
    for b in branches:
        try:
            data = http.get_json(PHPNET % b)
        except Exception as e:
            log("php.net %s: %s" % (b, e))
            continue
        for v, info in data.items():
            try:
                out[v] = datetime.strptime(info["date"], "%d %b %Y").strftime("%Y-%m-%d")
            except (KeyError, ValueError):
                pass
    return out


def merge_release(existing, new):
    """Update advisory-derived fields of a stored release, keep its channels."""
    for k in ("branches", "cves", "max_cvss", "max_severity", "cve_details", "upstream_at", "upstream_precision"):
        existing[k] = new[k]
    return existing


def needs_check(rel, ch, state, now):
    cur = rel["channels"].get(ch)
    if cur and cur.get("complete"):
        return False
    age = now - parse_ts(rel["upstream_at"])
    if age < timedelta(days=RECHECK_YOUNG_DAYS):
        return True
    last = state.get("checked", {}).get(rel["id"], {}).get(ch)
    return not last or now - parse_ts(last) >= timedelta(days=RECHECK_OLD_DAYS)


def main():
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    releases = load("releases.json", [])
    state = load("state.json", {})
    ctx = Ctx(state, now)
    ok = 0

    # 1. upstream advisories -> releases
    try:
        adv = http.get_json(ADVISORIES)
        cutoff = now - timedelta(days=BACKFILL_DAYS)
        by_id = {r["id"]: r for r in releases}
        branches = {branch_of(v) for a in adv for vu in a.get("vulnerabilities") or []
                    for v in VERSION_RE.findall(vu.get("patched_versions") or "")}
        phpnet = phpnet_dates(branches)
        new_groups = [g for g in group_advisories(adv, phpnet) if parse_ts(g["upstream_at"]) >= cutoff]
        for g in new_groups:
            g.setdefault("channels", {})
            dates = {phpnet[v] for v in g["branches"].values() if v in phpnet}
            if dates:
                g["php_net_date"] = max(dates)
            if g["id"] in by_id:
                keep = by_id[g["id"]]
                merge_release(keep, g)
                if "php_net_date" in g:
                    keep["php_net_date"] = g["php_net_date"]
            else:
                by_id[g["id"]] = g
                log("new release %s %s" % (g["id"], g["branches"]))
        releases = list(by_id.values())
        ok += 1
    except Exception as e:
        log("ERROR advisories: %s" % e)
    for r in releases:
        r.setdefault("channels", {})
    releases.sort(key=lambda r: parse_ts(r["upstream_at"]), reverse=True)

    # 2. poll-based channels: record first-seen versions
    for name in channels.POLL_CHANNELS:
        try:
            channels.poll_index(ctx, name, iso(now))
            ok += 1
        except Exception as e:
            log("ERROR poll %s: %s" % (name, e))

    # 3. per-release channels
    for rel in releases:
        for ch, fn in CHANNELS.items():
            if not needs_check(rel, ch, state, now):
                continue
            try:
                entry = fn(ctx, rel)
                ok += 1
            except Exception as e:
                log("ERROR %s %s: %s" % (rel["id"], ch, e))
                continue
            if entry:
                prev = rel["channels"].get(ch)
                if prev != entry:
                    rel["channels"][ch] = entry
                    log("%s %s: at %s (+%d min)%s" % (rel["id"], ch, entry["at"], entry["delay_minutes"],
                                                     "" if entry["complete"] else " [partial]"))
            if now - parse_ts(rel["upstream_at"]) >= timedelta(days=RECHECK_YOUNG_DAYS) and not (
                    entry and entry.get("complete")):
                state.setdefault("checked", {}).setdefault(rel["id"], {})[ch] = iso(now)

    save("releases.json", releases)
    save("state.json", state)
    log("done: %d releases, %d successful fetch groups" % (len(releases), ok))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
