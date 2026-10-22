"""Tiny urllib wrapper with retries. Standard library only."""
import gzip
import json
import os
import time
import urllib.error
import urllib.request

USER_AGENT = "php-patch-lag (+https://github.com/greenscript/php-patch-lag)"


def get(url, headers=None, retries=3, timeout=60):
    """Return response bytes. GITHUB_TOKEN (if set) is only sent to api.github.com."""
    hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        hdrs["Authorization"] = "Bearer " + token
        hdrs["Accept"] = "application/vnd.github+json"
    hdrs.update(headers or {})
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (404, 410):
                break  # not worth retrying
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise RuntimeError("GET %s failed: %s" % (url, last))


def get_text(url, **kw):
    return get(url, **kw).decode("utf-8", "replace")


def get_json(url, **kw):
    return json.loads(get(url, **kw))


def get_gz_text(url, **kw):
    return gzip.decompress(get(url, **kw)).decode("utf-8", "replace")
