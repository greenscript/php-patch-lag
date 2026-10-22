"""Channel collectors. Each parse_* function is pure (fixture-testable); each
collect_* function fetches and returns a channel entry (or None).

collect_* signature: (ctx, release) -> entry | None. Network errors raise."""
import html
import re
from email.utils import parsedate_to_datetime

from . import http
from .core import (iso, parse_ts, make_channel_entry, upstream_version, version_ge,
                   poll_first_seen, ver_key)

LAUNCHPAD = ("https://api.launchpad.net/1.0/~ondrej/+archive/ubuntu/php"
             "?ws.op=getPublishedBinaries&binary_name=%s&exact_match=true&ws.size=300")
UBUNTU_CVE = "https://ubuntu.com/security/cves/%s.json"
DEBIAN_CVE = "https://security-tracker.debian.org/tracker/%s"
DOCKER_COMMITS = ("https://api.github.com/repos/docker-library/official-images/commits"
                  "?path=library/php&per_page=100&since=%s&page=%d")
DOCKER_RAW = "https://raw.githubusercontent.com/docker-library/official-images/%s/library/php"

UBUNTU_RELEASES = {"noble": "php8.3", "jammy": "php8.1"}
DEBIAN_SUITES = ("bookworm", "trixie")


# --- Ondrej Ubuntu PPA (Launchpad) -----------------------------------------

def parse_launchpad_page(page):
    """-> (entries [{series, arch, version, published}], next_link)"""
    out = []
    for e in page.get("entries", []):
        dp = e.get("date_published")
        if not dp:
            continue
        m = re.search(r"/ubuntu/([^/]+)/([^/]+)$", e.get("distro_arch_series_link", ""))
        if not m:
            continue
        out.append({"series": m.group(1), "arch": m.group(2),
                    "version": e["binary_package_version"], "published": iso(parse_ts(dp))})
    return out, page.get("next_collection_link")


def launchpad_binaries(ctx, name):
    key = ("lp", name)
    if key not in ctx.cache:
        entries, url = [], LAUNCHPAD % name
        while url:
            batch, url = parse_launchpad_page(http.get_json(url))
            entries += batch
        ctx.cache[key] = entries
    return ctx.cache[key]


def ondrej_first_published(entries, series, patched):
    """Earliest amd64 publication in `series` of an upstream version >= patched."""
    hits = [e for e in entries if e["series"] == series and e["arch"] == "amd64"
            and version_ge(e["version"], patched)]
    if not hits:
        return None
    return min(hits, key=lambda e: parse_ts(e["published"]))


def collect_ondrej_ubuntu(ctx, release, series):
    units = {}
    for branch, patched in release["branches"].items():
        hit = ondrej_first_published(launchpad_binaries(ctx, "php%s-fpm" % branch), series, patched)
        if hit:
            units[branch] = {"version": hit["version"], "at": hit["published"]}
    return make_channel_entry(
        release, units, release["branches"], "exact",
        "Launchpad getPublishedBinaries, ppa:ondrej/php, php<branch>-fpm amd64, %s" % series,
        notes="at = latest branch (all branches fixed); per_branch = first amd64 date_published")


# --- Ubuntu security (CVE tracker + USN) ------------------------------------

def parse_ubuntu_cve(data, codenames=UBUNTU_RELEASES):
    """-> {codename: {"status", "fixed_version", "usn": earliest notice (id, published) | None}}"""
    out = {}
    for code, pkg in codenames.items():
        status = fixed = None
        for p in data.get("packages", []):
            if p.get("name") != pkg:
                continue
            for s in p.get("statuses", []):
                if s.get("release_codename") == code:
                    status, fixed = s.get("status"), s.get("description") or None
        usn = None
        for n in data.get("notices", []):
            if code in (n.get("release_packages") or {}) and n.get("published"):
                ts = iso(parse_ts(n["published"]))
                if usn is None or ts < usn[1]:
                    usn = (n["id"], ts)
        out[code] = {"status": status, "fixed_version": fixed, "usn": usn}
    return out


def _per_cve_entry(release, per_cve, ignored, source, notes):
    """Entry for an OS release: units are the affected CVEs (advisory dates)."""
    affected = list(per_cve)
    entry = make_channel_entry(release, per_cve, affected, "exact", source, unit_key="per_cve", notes=notes)
    if entry is None:
        return None
    fixed = [u for u in per_cve.values() if u.get("at")]
    entry["cves_fixed"], entry["cves_total"] = len(fixed), len(per_cve)
    entry["advisories"] = sorted({u["advisory"] for u in fixed})
    entry["versions"] = sorted({u["version"] for u in fixed if u.get("version")})
    if ignored:
        entry["cves_ignored"] = ignored
    return entry


def collect_ubuntu(ctx, release, code):
    per_cve, ignored = {}, 0
    for cve in release["cves"]:
        key = ("ubuntu", cve)
        if key not in ctx.cache:
            ctx.cache[key] = parse_ubuntu_cve(http.get_json(UBUNTU_URL(cve)))
        info = ctx.cache[key][code]
        st = info["status"]
        if st in (None, "DNE", "not-affected"):
            continue
        if st == "ignored":  # Ubuntu decided not to ship a fix; does not block "all fixed"
            ignored += 1
            continue
        u = {"at": None}
        if st == "released" and info["usn"]:
            u = {"at": info["usn"][1], "advisory": info["usn"][0], "version": info["fixed_version"]}
        per_cve[cve] = u
    return _per_cve_entry(
        release, per_cve, ignored,
        "ubuntu.com/security/cves/<CVE>.json (USN published date); %s on %s" % (UBUNTU_RELEASES[code], code),
        "Ubuntu backports fixes into its own version. first_fix = earliest USN among the CVEs, "
        "all fixed = latest USN once every affected CVE has one")


def UBUNTU_URL(cve):
    return UBUNTU_CVE % cve


# --- Debian security tracker --------------------------------------------------

_ROW = re.compile(r"<tr>(.*?)</tr>", re.S)
_TD = re.compile(r"<td[^>]*>(.*?)</td>", re.S)


def _text(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def parse_debian_cve(page):
    """-> {suite: {"status": fixed|unfixed|not-affected, "version", "advisory"}}
    from the 'fixed versions' table (package, type, release, version, urgency, origin, bugs)."""
    out = {}
    start = page.find("Fixed Version")
    if start < 0:
        return out
    for row in _ROW.findall(page[start:]):
        tds = _TD.findall(row)
        if len(tds) < 6 or _text(tds[1]) != "source":
            continue
        suite, ver, origin = _text(tds[2]), _text(tds[3]), _text(tds[5])
        if suite not in DEBIAN_SUITES:
            continue
        if "not affected" in ver:
            out[suite] = {"status": "not-affected", "version": None, "advisory": None}
        elif "unfixed" in ver:
            out[suite] = {"status": "unfixed", "version": None, "advisory": None}
        else:
            m = re.search(r"D[SL]A-\d+-\d+", origin)
            out[suite] = {"status": "fixed", "version": ver, "advisory": m.group(0) if m else None}
    return out


def parse_debian_msg_date(page):
    """Date of a debian-security-announce / debian-lts-announce message page."""
    m = re.search(r"<li><em>Date</em>:\s*([^<]+)</li>", page) or re.search(r"<!--X-Date:\s*([^(]+?)\s*\(UTC\)", page)
    if not m:
        return None
    return iso(parsedate_to_datetime(m.group(1).strip()))


def debian_advisory_date(ctx, adv_id, year_hint):
    """Date for DSA-6574-1 / DLA-4848-1, cached in state['advisory_dates']."""
    cache = ctx.state.setdefault("advisory_dates", {})
    if adv_id in cache:
        return cache[adv_id]
    kind, num, _ = adv_id.split("-")
    when = None
    for y in (year_hint, year_hint + 1):
        url = ("https://www.debian.org/security/%d/dsa-%s" % (y, num)) if kind == "DSA" \
            else ("https://www.debian.org/lts/security/%d/dla-%s" % (y, num))
        try:
            when = parse_debian_msg_date(http.get_text(url))
        except RuntimeError:
            continue
        if when:
            break
    if when:
        cache[adv_id] = when
    return when


def collect_debian(ctx, release, suite):
    year = parse_ts(release["upstream_at"]).year
    per_cve = {}
    for cve in release["cves"]:
        key = ("debian", cve)
        if key not in ctx.cache:
            ctx.cache[key] = parse_debian_cve(http.get_text(DEBIAN_CVE % cve))
        info = ctx.cache[key].get(suite)
        if not info or info["status"] == "not-affected":
            continue
        u = {"at": None}
        if info["status"] == "fixed" and info["advisory"]:
            when = debian_advisory_date(ctx, info["advisory"], year)
            if when:
                u = {"at": when, "advisory": info["advisory"], "version": info["version"]}
        per_cve[cve] = u
    return _per_cve_entry(
        release, per_cve, 0,
        "security-tracker.debian.org CVE pages + DSA/DLA announcement dates (%s)" % suite,
        "first_fix = earliest DSA/DLA among the CVEs, all fixed = latest once every affected CVE has one; "
        "bookworm is covered by DLA (LTS) once it left regular security support")


# --- Docker official images ----------------------------------------------------

def docker_has_tag(manifest, version):
    return re.search(r"(?<![\d.])%s(?!\d|\.\d)" % re.escape(version), manifest) is not None


def docker_commits(ctx, since):
    key = ("docker", since)
    if key not in ctx.cache:
        commits, page = [], 1
        while True:
            batch = http.get_json(DOCKER_COMMITS % (since, page))
            commits += [{"sha": c["sha"], "at": iso(parse_ts(c["commit"]["committer"]["date"]))} for c in batch]
            if len(batch) < 100 or page >= 5:
                break
            page += 1
        commits.sort(key=lambda c: parse_ts(c["at"]))
        ctx.cache[key] = commits
    return ctx.cache[key]


def collect_docker(ctx, release):
    up = parse_ts(release["upstream_at"])
    since = iso(up.replace(hour=0, minute=0, second=0))
    commits = [c for c in docker_commits(ctx, since) if parse_ts(c["at"]) >= up]
    units = {}
    for branch, patched in release["branches"].items():
        for c in commits:
            key = ("dockerfile", c["sha"])
            if key not in ctx.cache:
                ctx.cache[key] = http.get_text(DOCKER_RAW % c["sha"])
            if docker_has_tag(ctx.cache[key], patched):
                units[branch] = {"version": patched, "at": c["at"], "commit": c["sha"][:10]}
                break
    return make_channel_entry(
        release, units, release["branches"], "exact",
        "docker-library/official-images commits touching library/php (first commit listing the tag)",
        notes="Time is the manifest merge; images build shortly after, so availability on Docker Hub may be later")


# --- Poll-based channels (no timestamps published) ----------------------------

def parse_packages(text, wanted):
    """Debian Packages index -> {package: [versions]} for package names in `wanted`."""
    out = {}
    for stanza in re.split(r"\n\s*\n", text):
        name = ver = None
        for line in stanza.splitlines():
            if line.startswith("Package: "):
                name = line[9:].strip()
            elif line.startswith("Version: "):
                ver = line[9:].strip()
        if name in wanted and ver:
            out.setdefault(name, []).append(ver)
    return out


POLL_CHANNELS = {
    "serverpilot-noble": {
        "url": "https://download.serverpilot.io/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
        "pkg": "sp-php%s", "source": "download.serverpilot.io Packages.gz (noble), first seen by collector"},
    "serverpilot-jammy": {
        "url": "https://download.serverpilot.io/ubuntu/dists/jammy/main/binary-amd64/Packages.gz",
        "pkg": "sp-php%s", "source": "download.serverpilot.io Packages.gz (jammy), first seen by collector"},
    "ondrej-debian-bookworm": {
        "url": "https://packages.sury.org/php/dists/bookworm/main/binary-amd64/Packages.gz",
        "pkg": "php%s-fpm", "source": "packages.sury.org Packages.gz (bookworm), first seen by collector"},
    "ondrej-debian-trixie": {
        "url": "https://packages.sury.org/php/dists/trixie/main/binary-amd64/Packages.gz",
        "pkg": "php%s-fpm", "source": "packages.sury.org Packages.gz (trixie), first seen by collector"},
}
POLL_BRANCHES = ("8.1", "8.2", "8.3", "8.4", "8.5", "8.6")


def poll_index(ctx, channel, now):
    """Fetch the index and record newly seen versions in ctx.state['poll']."""
    cfg = POLL_CHANNELS[channel]
    wanted = {cfg["pkg"] % b: b for b in POLL_BRANCHES}
    found = parse_packages(http.get_gz_text(cfg["url"]), wanted)
    st = ctx.state.setdefault("poll", {}).setdefault(channel, {})
    from .core import update_poll_state
    for pkg, versions in found.items():
        update_poll_state(st.setdefault(pkg, {}), versions, now)


def collect_poll(ctx, release, channel):
    cfg = POLL_CHANNELS[channel]
    st = ctx.state.get("poll", {}).get(channel, {})
    units = {}
    for branch, patched in release["branches"].items():
        pkg_state = st.get(cfg["pkg"] % branch, {})
        ver, ent = poll_first_seen(pkg_state, patched)
        if not ver:
            continue
        if ent.get("first_seen"):
            units[branch] = {"version": ver, "at": ent["first_seen"],
                             "precision": ent.get("precision", "hourly-poll"),
                             "source": ent.get("source", cfg["source"])}
        else:
            units[branch] = {"version": ver, "at": None, "seen_by": ent.get("baseline_at")}
    if not any(u.get("at") for u in units.values()):
        return None
    precisions = {u["precision"] for u in units.values() if u.get("at")}
    precision = precisions.pop() if len(precisions) == 1 else "mixed"
    sources = {u["source"] for u in units.values() if u.get("at")}
    source = sources.pop() if len(sources) == 1 else cfg["source"]
    return make_channel_entry(
        release, units, release["branches"], precision, source,
        notes="No published timestamps: at is when the collector (or a manual observation) first saw the "
              "version. A branch with at=null was already present at the collector's first poll (seen_by).")
