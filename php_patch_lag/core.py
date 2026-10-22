"""Pure logic: version comparison, advisory grouping, delay computation."""
import re
from datetime import datetime, timedelta, timezone

COLLECTOR_SOURCE = "first seen by collector"
GROUP_GAP = timedelta(hours=6)
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def parse_ts(s):
    """Parse an ISO-8601 timestamp (with Z / offset / naive=UTC) to aware UTC."""
    s = s.strip().replace("Z", "+00:00")
    if "." in s:  # trim microseconds to what fromisoformat accepts everywhere
        head, rest = s.split(".", 1)
        frac = re.match(r"\d+", rest).group(0)
        s = head + "." + frac[:6].ljust(6, "0") + rest[len(frac):]
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ver_key(v):
    """Sort key for a package version. Compares the upstream part numerically
    ("8.2.35" from "1:8.2.35-1+deb12u1"), then pre-release (~) below final,
    then the leading integer of the packaging revision."""
    v = v.split(":", 1)[-1] if re.match(r"^\d+:", v) else v
    up, _, rev = v.partition("-")
    pre = 0 if "~" in up else 1
    up = up.split("~", 1)[0]
    nums = tuple(int(x) for x in re.findall(r"\d+", up.split("+", 1)[0]))
    m = re.match(r"\d+", rev)
    return (nums, pre, int(m.group(0)) if m else 0)


def upstream_version(v):
    """'8.2.35-1+ubuntu24.04.1' -> '8.2.35'"""
    v = re.sub(r"^\d+:", "", v)
    return re.split(r"[-~+]", v, maxsplit=1)[0]


def version_ge(a, b):
    """True if package version a has an upstream version >= b (an x.y.z string)."""
    return ver_key(a)[:2] >= ver_key(b)[:2]


def branch_of(v):
    return ".".join(v.split(".")[:2])


def advisory_score(adv):
    c = adv.get("cvss") or {}
    if c.get("score") is not None:
        return float(c["score"])
    for k in ("cvss_v4", "cvss_v3"):
        s = (adv.get("cvss_severities") or {}).get(k) or {}
        if s.get("score") is not None:
            return float(s["score"])
    return None


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


LATE_DAYS = 2


def _patched_versions(adv):
    out = []
    for vuln in adv.get("vulnerabilities") or []:
        out += VERSION_RE.findall(vuln.get("patched_versions") or "")
    return out


def fix_date(adv, phpnet):
    """Date (YYYY-MM-DD) of the earliest php.net release containing the fix:
    the minimum php.net date over the advisory's patched versions, or None."""
    dates = [phpnet[v] for v in _patched_versions(adv) if v in phpnet]
    return min(dates) if dates else None


def group_advisories(advisories, phpnet=None, gap=GROUP_GAP, late_days=LATE_DAYS):
    """Group published, CVE-bearing advisories into releases.

    With `phpnet` ({version: 'YYYY-MM-DD'}), an advisory belongs to the release
    that first shipped its fix (earliest php.net date among its patched
    versions). If the advisory was published more than `late_days` after that
    date it is flagged `advisory_published_late` and does not set the
    release's upstream time; a release with only late advisories gets
    upstream_at = the php.net date (precision "day"). Advisories whose versions
    php.net does not know are clustered by published_at within `gap`.
    Per branch the highest patched version of the release wins.
    Returns releases oldest-first (caller sorts for output)."""
    phpnet = phpnet or {}
    items = []
    for a in advisories:
        if a.get("state") != "published" or not a.get("cve_id") or not a.get("published_at"):
            continue
        items.append((parse_ts(a["published_at"]), a))
    items.sort(key=lambda x: x[0])

    keyed, cluster, last = {}, 0, None
    for ts, a in items:
        fd = fix_date(a, phpnet)
        if fd:
            key = fd
        else:
            if last is None or ts - last > gap:
                cluster += 1
            last = ts
            key = "u%d" % cluster
        keyed.setdefault(key, []).append((ts, a, fd))

    releases, used = [], {}
    for key, members in keyed.items():
        fd = members[0][2]
        branches, cves, scores, details, ontime = {}, set(), [], {}, []
        for ts, a, _ in members:
            late = bool(fd) and (ts.date() - datetime.fromisoformat(fd).date()).days > late_days
            if not late:
                ontime.append(ts)
            cves.add(a["cve_id"])
            s = advisory_score(a)
            if s is not None:
                scores.append(s)
            d = {"severity": a.get("severity"), "cvss": s}
            if late:
                d.update({"advisory_published_late": True, "advisory_published_at": iso(ts),
                          "fixed_release_date": fd})
            details[a["cve_id"]] = d
            for v in _patched_versions(a):
                if fd and phpnet.get(v, fd) != fd:
                    continue  # shipped in a different (later) release
                b = branch_of(v)
                if b not in branches or ver_key(v) > ver_key(branches[b]):
                    branches[b] = v
        if not branches:
            continue
        if ontime:
            up, precision = min(ontime), "exact"
        else:
            up, precision = datetime.fromisoformat(fd).replace(tzinfo=timezone.utc), "day"
        rid = up.strftime("%Y-%m-%d")
        used[rid] = used.get(rid, 0) + 1
        if used[rid] > 1:
            rid += "-%d" % used[rid]
        releases.append({
            "id": rid,
            "branches": dict(sorted(branches.items())),
            "cves": sorted(cves),
            "max_cvss": max(scores) if scores else None,
            "max_severity": max((d["severity"] for d in details.values() if d["severity"]),
                                key=lambda s: SEVERITY_RANK.get(s, 0), default=None),
            "cve_details": dict(sorted(details.items())),
            "upstream_at": iso(up),
            "upstream_precision": precision,
        })
    releases.sort(key=lambda r: r["upstream_at"])
    return releases


def delay_minutes(at, upstream_at):
    """Minutes from upstream to a channel timestamp (both ISO strings). May be negative."""
    return int(round((parse_ts(at) - parse_ts(upstream_at)).total_seconds() / 60))


def latest_of(times):
    return iso(max(parse_ts(t) for t in times))


def make_channel_entry(release, units, expected, precision, source, unit_key="per_branch", notes=None):
    """Assemble a channel entry from per-unit results ({unit: {"at": iso|None, ...}}).
    `first_fix_at` is the earliest time any unit was fixed, `at` the latest among
    units that have one ("all fixed" once `complete`); `complete` is True only
    when every expected unit has a time. Returns None if no unit has a time."""
    have = {k: v for k, v in units.items() if v.get("at")}
    if not have:
        return None
    at = latest_of([v["at"] for v in have.values()])
    first = iso(min(parse_ts(v["at"]) for v in have.values()))
    entry = {
        "first_fix_at": first,
        "first_fix_delay_minutes": delay_minutes(first, release["upstream_at"]),
        "at": at,
        "delay_minutes": delay_minutes(at, release["upstream_at"]),
        "complete": all(k in have for k in expected),
        "precision": precision,
        "source": source,
        unit_key: units,
    }
    if notes:
        entry["notes"] = notes
    return entry


def poll_first_seen(state_pkg, patched):
    """ServerPilot / sury style first-seen logic.

    state_pkg: {version: {"first_seen": iso|None, "baseline_at": iso?, ...}} for one package.
    The relevant version is the *lowest* one >= patched (so a later release's
    package is never credited to an earlier release). Returns
    (version, entry) or (None, None)."""
    cands = [v for v in state_pkg if version_ge(v, patched)]
    if not cands:
        return None, None
    v = min(cands, key=ver_key)
    return v, state_pkg[v]


def update_poll_state(pkg_state, versions, now):
    """Record newly seen versions. First sighting of a package is a baseline
    (versions were already there; true time unknown, first_seen None)."""
    # Only manually seeded entries so far (no collector sighting) still counts as first sighting.
    is_baseline = not any(e.get("baseline_at") or e.get("source") == COLLECTOR_SOURCE
                          for e in pkg_state.values())
    changed = False
    for v in versions:
        if v in pkg_state:
            continue
        if is_baseline:
            pkg_state[v] = {"first_seen": None, "baseline_at": now}
        else:
            pkg_state[v] = {"first_seen": now, "precision": "hourly-poll", "source": COLLECTOR_SOURCE}
        changed = True
    return changed
