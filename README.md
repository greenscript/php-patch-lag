# php-patch-lag

How long PHP security fixes take to reach each distribution channel.

For every PHP security release (the set of patched versions per branch published together, for example 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), this collector records when each channel first made a fixed build available and the delay from the upstream disclosure. Results are stored as plain JSON in `data/` and refreshed hourly by GitHub Actions.

Write-up and charts: https://pressbot.io/php-patch-lag/ (placeholder)

## Data

- `data/releases.json`: releases, newest first. Each has `id` (date), `branches`, `cves`, `max_cvss`, `upstream_at`, `upstream_precision`, and `channels`.
- `data/state.json`: bookkeeping (first-seen versions for polled channels, cached advisory dates, recheck times).

A channel entry has `at` (ISO UTC), `delay_minutes` (from `upstream_at`; negative if the channel was ahead of the advisory), `complete`, `precision`, `source`, and a per-unit breakdown (`per_branch`, `per_release` or `per_suite`). `at` is the latest time among the units that have one, i.e. when all of them were fixed. `complete: false` means some branch/release/suite is not fixed yet (or was not observed), so `at` covers only the units that are.

## Upstream

Upstream time is the earliest `published_at` among the GitHub Security Advisories of `php/php-src` that belong to the release. Advisories published within 6 hours of each other are grouped into one release; per branch the highest patched version wins. Only advisories with a CVE id count. Versions are cross-checked against the php.net release JSON (`php_net_date`). If an advisory time were unavailable the php.net date would be used with `upstream_precision: "day"`. Backfill covers the last 365 days.

## Channels

| Channel | Source | Precision |
|---|---|---|
| `ondrej-ubuntu-noble`, `ondrej-ubuntu-jammy` | Launchpad API, ppa:ondrej/php. First amd64 `date_published` of `php<branch>-fpm` with upstream version >= patched, per branch; the channel time is the latest branch. | exact |
| `ondrej-debian-bookworm`, `ondrej-debian-trixie` | packages.sury.org `Packages.gz`, which has no timestamps. | hourly-poll |
| `docker-official` | Commits to `docker-library/official-images` touching `library/php`. First commit whose manifest lists the patched version tag. | exact (manifest merge time) |
| `ubuntu` | `ubuntu.com/security/cves/<CVE>.json`: package status for `php8.3` (noble) and `php8.1` (jammy) and the earliest USN publication date per CVE. | exact |
| `debian` | `security-tracker.debian.org` CVE pages for DSA/DLA ids, dated from the debian-security-announce / debian-lts-announce message. Per suite (bookworm, trixie). | exact |
| `serverpilot-noble`, `serverpilot-jammy` | `download.serverpilot.io` `Packages.gz`, packages `sp-php8.2` and up. | hourly-poll |

## Caveats

- **Polled channels** (ServerPilot, Ondrej Debian) publish no timestamps. The collector records the run time at which a fixed version first appears, so the true time is up to one polling interval earlier (the cron runs hourly and GitHub may delay scheduled runs). The first time a package is seen, its existing versions are stored as a baseline with no time; those cannot be dated and appear as `at: null` with `seen_by`. Releases before the collector started polling therefore have no polled-channel data, except manual observations recorded in `state.json` (for example the ServerPilot 2026-10-21 `sp-php8.2` observation, `precision: "5-min-poll"`, source "observed by GreenScript"; other branches for that release were not observed at the time).
- **Ubuntu and Debian backport** fixes into their own older PHP versions (8.1 on jammy, 8.3 on noble, 8.2 on bookworm, 8.4 on trixie), so version numbers cannot be compared with upstream. Fixes are tracked per CVE: a release or suite is dated when every affected CVE has an advisory (USN, DSA or DLA). CVEs Ubuntu marked `ignored`, or that a release is not affected by, do not block that. Their delays are measured to the advisory, not to the point where an update is installable on a given mirror.
- **Docker** time is the manifest merge into `official-images`; images are built and pushed shortly after, which this does not measure.
- **Ondrej Ubuntu PPA** time is when Launchpad published the amd64 binary, not when the build started.
- A negative delay means the channel's advisory precedes the upstream advisory timestamp (for example coordinated disclosure).
- Only security releases with at least one CVE are included. Releases without GitHub advisories are not detected.

## Running

Python 3.11+, standard library only.

```
python3 collect.py                 # set GITHUB_TOKEN to avoid unauthenticated API limits
python3 -m unittest discover -s tests
```

`collect.py` is idempotent and never deletes data. Errors in one channel are logged and skipped; it exits non-zero only if nothing could be fetched. Complete entries are not refetched; incomplete ones are rechecked every run for 30 days after release, then weekly.

## Adding a channel

1. Add `parse_*` (pure, testable against a trimmed fixture in `tests/fixtures/`) and `collect_<name>(ctx, release)` to `php_patch_lag/channels.py`. Return `make_channel_entry(...)` or `None`.
2. For a channel with no timestamps, add an entry to `POLL_CHANNELS` instead; polling and first-seen bookkeeping are shared.
3. Register it in `CHANNELS` in `collect.py`, add tests, and describe its source and precision in the table above.

## License

MIT, copyright GreenScript.
