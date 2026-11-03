#!/usr/bin/env python3
"""
Threat Wire - cybersecurity alerts for your stack, posted to a Telegram channel.

Posts only between POST_START and POST_END (05:30-21:00 by default); everything that arrives overnight goes into the morning
catch-up, and the evening digest closes the day.

Tiers
  RED     a card each, with sound        (stack/OT + exploited, zero-day, breach, critical;
                                          any big vendor when exploited or on KEV)
  YELLOW  a silent card each             (vendor advisories, ICS advisories, urgent general news)
          CVEs grouped at CVE_BATCH_AT
  DIGEST  the evening digest             (everything else)
Every post carries vendor hashtags (VENDOR_TAGS in threatwire_sources.py).

Usage
  python3 threatwire.py                 one pass (the systemd timer runs this)
  python3 threatwire.py --check-feeds   fetch every feed and report OK / FAIL, sends nothing
  python3 threatwire.py --test          send a test message to the channel
  python3 threatwire.py --dry-run       normal pass, print messages instead of sending
  python3 threatwire.py --digest-now    send the evening digest and the CVE post now
  python3 threatwire.py --morning-now   send the morning catch-up now
  python3 threatwire.py --loop          run forever, polling every POLL_MINUTES

Configuration is threatwire_sources.py, overridden by local_sources.py if
present. Credentials come from the environment (THREATWIRE_BOT_TOKEN /
THREATWIRE_CHAT_ID); running it by hand also reads ~/.config/threatwire.env
or a .env file next to this script.

Python standard library only - nothing to pip install.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone, time as dtime
from collections import Counter
from html import unescape
from pathlib import Path
from zoneinfo import ZoneInfo

import threatwire_sources as S

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
ENV_FILE = Path.home() / ".config" / "threatwire.env"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 ThreatWire/1.0")
TG_LIMIT = 4000  # Telegram's hard limit is 4096 characters

log = logging.getLogger("threatwire")


# ---------------------------------------------------------------- config ---

def load_env(path: Path) -> None:
    """KEY=VALUE lines. systemd already does this; this covers running by hand."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def compile_terms(terms):
    if not terms:
        return None
    parts = sorted({re.escape(t.lower()) for t in terms}, key=len, reverse=True)
    return re.compile(r"(?<![\w-])(" + "|".join(parts) + r")(?![\w])", re.I)


class Config:
    """The tuning in threatwire_sources.py, with the watchlists precompiled."""

    def __init__(self):
        self.tz = ZoneInfo(S.TIMEZONE)
        self.poll = int(S.POLL_MINUTES)
        self.headline_max = int(S.HEADLINE_MAX_PER_RUN)
        self.post_start = dtime.fromisoformat(S.POST_START)
        self.post_end = dtime.fromisoformat(S.POST_END)
        self.cve_batch_at = sorted(int(h) for h in S.CVE_BATCH_AT)
        self.cve_batch_max = int(S.CVE_BATCH_MAX)
        self.catchup_max = int(S.CATCHUP_MAX_HEADLINES)
        self.evening_max_red = int(S.EVENING_MAX_RED)
        self.evening_max_head = int(S.EVENING_MAX_HEADLINES)
        self.digest_max_cve = int(S.DIGEST_MAX_CVE)
        self.max_red = int(S.MAX_RED_PER_RUN)
        self.dedupe_hours = int(S.DEDUPE_WINDOW_HOURS)
        self.similarity = float(S.TITLE_SIMILARITY)
        self.re_stack = compile_terms(S.STACK)
        self.re_ot = compile_terms(S.OT_VENDORS)
        self.re_ot_pri = compile_terms(S.OT_PRIORITY)
        self.re_industry = compile_terms(S.INDUSTRY)
        self.re_urgent = compile_terms(S.URGENT_TERMS)
        self.re_big = compile_terms(S.BIG_VENDORS)
        amb = {t.lower() for t in S.AMBIGUOUS_IN_TEXT}
        self.re_wide = compile_terms(S.WATCH_EXPLOITED)                    # NVD product names
        self.re_wide_text = compile_terms([t for t in S.WATCH_EXPLOITED if t.lower() not in amb])
        self.re_vendor_text = compile_terms(
            [t for t in set(S.STACK) | set(S.OT_VENDORS) | set(S.BIG_VENDORS) if t.lower() not in amb])
        self.re_exploited = compile_terms(S.EXPLOITED_TERMS)
        # every vendor term, for hashtags
        self.re_vendor = compile_terms(set(S.STACK) | set(S.OT_VENDORS) | set(S.BIG_VENDORS))
        self.ot_terms = {t.lower() for t in S.OT_VENDORS}
        self.max_vendor_tags = int(S.MAX_VENDOR_TAGS)
        self.trend_hours = int(S.TRENDING_HOURS)
        self.trend_min = int(S.TRENDING_MIN_OUTLETS)
        self.drop = [re.compile(p, re.I) for p in S.DROP_PATTERNS]
        self.feeds = S.FEEDS


# ------------------------------------------------------------------ store ---

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  uid        TEXT PRIMARY KEY,
  feed       TEXT, category TEXT,
  title      TEXT, link TEXT, summary TEXT,
  tier       TEXT, reason TEXT,
  cves       TEXT,
  norm_title TEXT,
  first_seen TEXT,
  sent       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self.db.commit()

    def is_new_db(self) -> bool:
        return self.db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0

    def has_feed(self, name: str) -> bool:
        return self.db.execute("SELECT 1 FROM items WHERE feed=? LIMIT 1", (name,)).fetchone() is not None

    def cve_known(self, cve: str) -> bool:
        return self.db.execute("SELECT 1 FROM items WHERE ','||cves||',' LIKE ? LIMIT 1",
                               (f"%,{cve},%",)).fetchone() is not None

    def seen(self, uid: str) -> bool:
        return self.db.execute("SELECT 1 FROM items WHERE uid=?", (uid,)).fetchone() is not None

    def add(self, it: dict, tier: str, reason: str, sent: int) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (it["uid"], it["feed"], it["category"], it["title"], it["link"], it["summary"],
             tier, reason, ",".join(sorted(it["cves"])), it["norm"], now_utc().isoformat(), sent))

    def recent_titles(self, hours: int):
        since = (now_utc() - timedelta(hours=hours)).isoformat()
        return [r[0] for r in self.db.execute(
            "SELECT norm_title FROM items WHERE first_seen>=? AND tier IN ('red','yellow','digest')",
            (since,))]

    def recent_cves(self, days: int = 7):
        since = (now_utc() - timedelta(days=days)).isoformat()
        out = set()
        for (c,) in self.db.execute(
                "SELECT cves FROM items WHERE first_seen>=? AND tier IN ('red','yellow')", (since,)):
            out.update(x for x in (c or "").split(",") if x)
        return out

    def pending(self, tier: str, category: str = "", exclude_cve: bool = False,
                limit: int = 0):
        q = "SELECT * FROM items WHERE tier=? AND sent=0"
        args = [tier]
        if category:
            q += " AND category=?"
            args.append(category)
        if exclude_cve:
            q += " AND category!='cve'"
        q += " ORDER BY first_seen"
        if limit:
            q += " LIMIT ?"
            args.append(limit)
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(q, args).fetchall()
        self.db.row_factory = None
        return rows

    def since_rows(self, hours: int, tiers):
        """Everything that alerted in the window - the raw material of the recap."""
        since = (now_utc() - timedelta(hours=hours)).isoformat()
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            "SELECT * FROM items WHERE first_seen>=? AND tier IN (%s) ORDER BY first_seen"
            % ",".join("?" * len(tiers)), (since, *tiers)).fetchall()
        self.db.row_factory = None
        return rows

    def mark_sent(self, uids) -> None:
        self.db.executemany("UPDATE items SET sent=1 WHERE uid=?", [(u,) for u in uids])
        self.db.commit()

    def get(self, k: str, default: str = "") -> str:
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def set(self, k: str, v: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))
        self.db.commit()

    def commit(self) -> None:
        self.db.commit()


# ---------------------------------------------------------------- helpers ---

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVSS_RE = re.compile(r"CVSS(?:v\d(?:\.\d)?)?\s*(?:base\s*)?score:?\s*(\d{1,2}(?:\.\d)?)", re.I)
SEV_RE = re.compile(r"severity:?\s*(critical|high|medium|moderate|low)", re.I)


def strip(s: str) -> str:
    """Same shape as market_alerts_collect.strip - CDATA, tags, entities, space."""
    s = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", s or "", flags=re.S)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", unescape(s)).strip()


def tag(block: str, name: str) -> str:
    m = re.search(rf"<{name}[^>]*>(.*?)</{name}>", block, re.S)
    return strip(m.group(1)) if m else ""


def norm_title(t: str) -> str:
    t = re.sub(r"[^a-z0-9 ]", " ", t.lower())
    stop = {"the", "a", "an", "of", "to", "in", "on", "for", "and", "with",
            "by", "after", "as", "is", "at"}
    return " ".join(sorted({w for w in t.split() if w not in stop and len(w) > 2}))


def jaccard(a: str, b: str) -> float:
    sa, sb = set(a.split()), set(b.split())
    return len(sa & sb) / len(sa | sb) if sa and sb else 0.0


def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


# ---------------------------------------------------------------- fetching ---

def fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    if data[:2] == b"\x1f\x8b":            # some feeds serve a raw gzip body
        data = gzip.decompress(data)
    return data


def feed_url(feed: dict) -> str:
    """The NVD API wants a date window; every other feed is a fixed URL."""
    if feed.get("type") != "nvd":
        return feed["url"]
    end = now_utc()
    start = end - timedelta(hours=feed.get("window_hours", 6))
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return (f"{feed['url']}?pubStartDate={start.strftime(fmt)}"
            f"&pubEndDate={end.strftime(fmt)}&resultsPerPage=2000")


def nvd_score(metrics: dict):
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            d = metrics[k][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity") or metrics[k][0].get("baseSeverity")
    return None, None


def parse_feed(feed: dict, data: bytes):
    """RSS <item> and Atom <entry> alike, plus the CISA KEV JSON file and the NVD API."""
    items = []
    if feed.get("type") == "nvd":
        for v in json.loads(data).get("vulnerabilities", []):
            c = v.get("cve", {})
            if c.get("vulnStatus") == "Rejected":
                continue
            cve = c.get("id", "")
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            aff = [a for src in c.get("affected", []) for a in src.get("affectedData", [])]
            prod = f"{aff[0].get('vendor', '')} {aff[0].get('product', '')}".strip() if aff else ""
            # every vendor/product name, from the CNA's list and NVD's CPEs, for BIG_VENDORS
            names = [f"{a.get('vendor', '')} {a.get('product', '')}" for a in aff]
            names += [" ".join(m["criteria"].split(":")[3:5]).replace("_", " ")
                      for cfg_ in c.get("configurations", []) for n in cfg_.get("nodes", [])
                      for m in n.get("cpeMatch", []) if m.get("criteria")]
            score, sev = nvd_score(c.get("metrics", {}))
            rating = f"CVSS score: {score:g} ({sev}) · " if score is not None else "CVSS: not yet scored · "
            items.append(dict(uid=f"nvd:{cve}", title=f"{cve} — {prod}" if prod else cve,
                              summary=(rating + desc)[:600],
                              link=f"https://nvd.nist.gov/vuln/detail/{cve}", kev=False,
                              products=" | ".join(names)))
        return items

    if feed.get("type") == "kev":
        kev = json.loads(data)
        for v in kev.get("vulnerabilities", []):
            cve = v.get("cveID", "")
            title = f"{v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}"
            summary = (f"{v.get('shortDescription','')} Added to KEV {v.get('dateAdded','')}; "
                       f"federal due date {v.get('dueDate','')}. "
                       f"Ransomware use: {v.get('knownRansomwareCampaignUse','Unknown')}.")
            items.append(dict(uid=f"kev:{cve}", title=f"{cve} — {title}", summary=summary,
                              link=f"https://nvd.nist.gov/vuln/detail/{cve}", kev=True))
        return items

    body = data.decode("utf-8", errors="ignore")

    for block in re.findall(r"<item[^>]*>(.*?)</item>", body, re.S):
        title = tag(block, "title")
        link = tag(block, "link")
        guid = tag(block, "guid") or link or title
        summary = tag(block, "description") or tag(block, "content:encoded")
        if not title:
            continue
        items.append(dict(uid=_uid(feed["name"], guid), title=title,
                          summary=summary[:600], link=link, kev=False))

    for block in re.findall(r"<entry[^>]*>(.*?)</entry>", body, re.S):
        m = re.search(r'<link[^>]*href="([^"]+)"', block)
        link = unescape(m.group(1)) if m else ""
        title = tag(block, "title")
        guid = tag(block, "id") or link or title
        summary = tag(block, "summary") or tag(block, "content")
        if not title:
            continue
        items.append(dict(uid=_uid(feed["name"], guid), title=title,
                          summary=summary[:600], link=link, kev=False))

    return items


def _uid(feed_name: str, guid: str) -> str:
    return feed_name + ":" + hashlib.sha1(guid.encode("utf-8", "ignore")).hexdigest()[:16]


# ----------------------------------------------------------------- scoring ---

def severity(text: str):
    cvss = None
    m = CVSS_RE.search(text)
    if m:
        try:
            cvss = float(m.group(1))
        except ValueError:
            pass
    s = SEV_RE.search(text)
    return cvss, (s.group(1).lower() if s else None)


def classify(it: dict, cat: str, cfg: Config):
    """Return (tier, reason). The base rules, then the WATCH_EXPLOITED rule:
    a big vendor outside the stack is red when exploited, never on score alone."""
    tier, reason = _classify(it, cat, cfg)
    if tier in ("red", "drop") or not cfg.re_wide or not cfg.re_exploited:
        return tier, reason
    if cat == "cve":
        wide = cfg.re_wide.search(it.get("products", ""))
    else:
        wide = cfg.re_wide_text.search(f"{it['title']} {it['summary']}")
    if wide and (it.get("kev") or cfg.re_exploited.search(f"{it['title']} {it['summary']}")):
        name = wide.group(1).lower()
        if name not in reason.lower():
            reason = f"{name} · {reason}" if reason else name
        if "exploit" not in reason.lower():
            reason += " · exploited"
        return "red", reason
    return tier, reason


def _classify(it: dict, cat: str, cfg: Config):
    """Return (tier, reason). tier in red|yellow|digest|drop."""
    title, text = it["title"], f"{it['title']} {it['summary']}"
    if any(p.search(title) for p in cfg.drop):
        return "drop", "noise filter"

    def hits(rx):
        return sorted({m.group(1).lower() for m in rx.finditer(text)}) if rx else []

    stack, ot, ind, urg = hits(cfg.re_stack), hits(cfg.re_ot), hits(cfg.re_industry), hits(cfg.re_urgent)
    ot_pri = hits(cfg.re_ot_pri)
    cvss, sev = severity(text)
    critical = (cvss is not None and cvss >= 9.0) or sev == "critical"
    low = (cvss is not None and cvss < 4.0) or sev == "low"
    exploited = it.get("kev") or any(u for u in urg if "exploit" in u or "zero" in u or "0-day" in u)

    tags = []
    if cvss is not None:
        tags.append(f"CVSS {cvss:g}")
    elif sev:
        tags.append(sev.upper())
    if it.get("kev"):
        tags.append("CISA KEV — exploited")
    elif urg:
        tags.append(urg[0])
    who = (stack + ot)[:2]
    reason = " · ".join(who + tags) or cat

    if cat == "gov" and it.get("kev"):
        return ("red" if (stack or ot) else "yellow"), reason

    if cat == "cve":  # NVD: ~500 a day, so only your stack, big names and criticals are sent
        # big-name vendors are matched on the product names only: descriptions mention
        # "Docker image" or "Kubernetes-based" for projects that are neither
        prods = it.get("products", "")

        def phits(rx):
            return sorted({m.group(1).lower() for m in rx.finditer(prods)}) if rx else []

        # stack and OT are matched on product names too, for the same reason
        stack, ot, ot_pri, big = phits(cfg.re_stack), phits(cfg.re_ot), phits(cfg.re_ot_pri), phits(cfg.re_big)
        tags = [t for t in reason.split(" · ") if t.startswith("CVSS") or t.isupper()]
        reason = " · ".join(list(dict.fromkeys(stack + ot + big))[:2] + tags) or "cve"
        # OT pages only for OT_PRIORITY, matching the ICS advisory rule
        if (stack and critical) or exploited and (stack or ot) or (ot_pri and critical):
            return "red", reason
        if big and critical and exploited:
            return "red", reason
        if stack or ot or (big and critical):
            return "yellow", reason
        if critical:
            return "digest", reason
        return "drop", "not stack, big name or critical"

    if cat == "psirt":
        if exploited or critical:
            return "red", reason
        return ("digest" if low else "yellow"), reason

    if cat == "ics":
        if exploited or (critical and ot_pri):
            return "red", reason
        if ot or critical:
            return "yellow", reason
        return "digest", reason

    if cat == "status":
        if urg or re.search(r"\b(investigating|identified|incident|security|degraded|outage)\b", text, re.I):
            return ("red" if not re.search(r"\bresolved\b", title, re.I) else "yellow"), reason
        return "yellow", reason

    if cat == "gov":
        if (stack or ot) or exploited:
            return ("red" if (stack or ot) and (exploited or urg) else "yellow"), reason
        return "yellow", reason

    # news / industry
    relevant = bool(stack or ot or ind)
    if relevant and urg:
        return "red", reason
    if relevant or urg or cat == "industry":
        return "yellow", reason
    return "digest", reason


# ---------------------------------------------------------------- telegram ---

class Telegram:
    """Telegram Bot API sender, urllib only."""

    def __init__(self, token: str, chat_id: str, dry_run: bool = False):
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.dry_run = dry_run

    def send(self, text: str, silent: bool = False) -> bool:
        for chunk in split_message(text):
            if self.dry_run:
                print(("[silent] " if silent else "[ALERT] ") + chunk + "\n" + "-" * 60)
                continue
            payload = json.dumps({
                "chat_id": self.chat_id, "text": chunk, "parse_mode": "HTML",
                "disable_web_page_preview": True, "disable_notification": silent,
            }).encode()
            for _ in range(4):
                req = urllib.request.Request(
                    self.url, data=payload,
                    headers={"Content-Type": "application/json", "User-Agent": UA})
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        r.read()
                    break
                except urllib.error.HTTPError as e:
                    body = e.read().decode("utf-8", errors="ignore")
                    if e.code == 429:
                        try:
                            wait = json.loads(body).get("parameters", {}).get("retry_after", 5)
                        except ValueError:
                            wait = 5
                        time.sleep(wait + 1)
                        continue
                    log.error("telegram %s: %s", e.code, body[:300])
                    return False
                except urllib.error.URLError as e:
                    log.warning("telegram error: %s", e)
                    time.sleep(5)
                    continue
            else:
                return False
            time.sleep(1.2)  # stay under channel rate limits
        return True


def split_message(text: str):
    if len(text) <= TG_LIMIT:
        return [text]
    out, cur = [], ""
    for line in text.split("\n"):
        if len(cur) + len(line) + 1 > TG_LIMIT:
            out.append(cur)
            cur = ""
        cur += line + "\n"
    if cur.strip():
        out.append(cur)
    return out


def clean_summary(s: str) -> str:
    # some feeds (CISA) escape their HTML twice, so strip() leaves real tags behind
    s = strip(strip(s))
    s = re.sub(r"^View CSAF\s*(Summary\s*)?", "", s)
    return re.sub(r"\s*The post .*? appeared first on .*$", "", s).strip()


def feed_emoji(feed: str) -> str:
    return S.FEED_EMOJI.get(feed, S.DEFAULT_EMOJI)


ZERO_DAY_RE = re.compile(r"\b(zero[- ]day|0-day)\b", re.I)
URL_RE = re.compile(r"(https?://|www\.)\S+|\b[\w.-]+\.(com|org|gov|net|io)(/\S*)?", re.I)
TOPIC_RES = [(re.compile(rx, re.I), tag) for rx, tag in S.TOPIC_TAGS.items()]


def tag_name(term: str) -> str:
    t = S.VENDOR_TAGS.get(term.lower())
    if not t:
        t = "".join(w[:1].upper() + w[1:] for w in re.split(r"[^A-Za-z0-9]+", term) if w)
    return re.sub(r"[^A-Za-z0-9_]", "", t)


def vendor_tags(r, cfg: Config):
    """The vendors an item names, as tag names, in order of first mention.
    NVD titles are "CVE-x — Vendor Product", so the title is the product field."""
    cat = r["category"]
    if cat == "cve":
        text, rx = r["title"], cfg.re_vendor
    else:
        # URLs out first: CISA bodies link github.com/cisagov on every advisory
        text = URL_RE.sub(" ", f"{r['title']} {r['summary'] or ''}")
        rx = cfg.re_vendor_text
    out, ot = [], cat in ("ics", "industry")
    for m in rx.finditer(text) if rx else []:
        term = m.group(1).lower()
        ot = ot or term in cfg.ot_terms
        t = tag_name(term)
        if t and t not in out:
            out.append(t)
    return out[:cfg.max_vendor_tags], ot


def hashtags(r, cfg: Config) -> str:
    """#Vendor ... #OT #KEV #Exploited #ZeroDay #Critical - tappable in Telegram."""
    vendors, ot = vendor_tags(r, cfg)
    text = f"{r['title']} {r['summary'] or ''}"
    kev = r["feed"] == "CISA KEV"
    tags = vendors + (["OT"] if ot else [])
    if kev:
        tags.append("KEV")
    if kev or (cfg.re_exploited and cfg.re_exploited.search(text)):
        tags.append("Exploited")
    if ZERO_DAY_RE.search(text):
        tags.append("ZeroDay")
    sc, sev = severity(text)
    if (sc is not None and sc >= 9.0) or sev == "critical":
        tags.append("Critical")
    tags += [tag for rx, tag in TOPIC_RES if rx.search(text)]
    return " ".join("#" + t for t in tags)


def fmt_red(it: dict, reason: str, tags: str = "") -> str:
    # one story per card, with the red marker and the reason it is red
    e = feed_emoji(it["feed"])
    body = trunc(clean_summary(it["summary"]), 350)
    lines = [f"\U0001F534 {e} <b>{esc(it['title'])}</b> {e}", ""]
    if body:
        lines += [f"<code>{esc(body)}</code>", ""]
    lines += [f"⚠️ <i>{esc(reason)}</i>", "",
              f"\U0001F4D6 <a href=\"{esc(it['link'])}\">Read more.</a>", "",
              f"\U0001F517 Via \"<i>{esc(it['feed'])}</i>\""]
    if tags:
        lines += ["", tags]
    return "\n".join(lines)


def fmt_headline(it, reason: str, tags: str = "") -> str:
    """One yellow story, its own silent post: the red card without the alarm."""
    e = feed_emoji(it["feed"])
    body = trunc(clean_summary(it["summary"]), 300)
    lines = [f"{e} <b>{esc(it['title'])}</b> {e}", ""]
    if body:
        lines += [f"<code>{esc(body)}</code>", ""]
    if reason:
        lines += [f"ℹ️ <i>{esc(reason)}</i>", ""]
    lines += [f"📖 <a href=\"{esc(it['link'])}\">Read more.</a>", "",
              f"🔗 Via \"<i>{esc(it['feed'])}</i>\""]
    if tags:
        lines += ["", tags]
    return "\n".join(lines)


def cvss(r) -> float:
    m = CVSS_RE.search(r["summary"] or "")
    return float(m.group(1)) if m else 0.0


def fmt_cve_batch(rows, when: str, cfg: Config, held: int = 0) -> str:
    """Yellow CVEs grouped. NVD titles already carry the vendor, so one line does;
    the vendor's hashtag goes on the end so #Vendor finds these too."""
    lines = [f"🧩 <b>Threat Wire · {len(rows)} new CVEs</b> ({when})", ""]
    for r in rows:
        sc = cvss(r)
        tail = f" · <b>{sc:g}</b>" if sc else ""
        v, _ = vendor_tags(r, cfg)
        tag = f" #{v[0]}" if v else ""
        lines.append(f"• <a href=\"{esc(r['link'])}\">{esc(trunc(r['title'], 110))}</a>{tail}{tag}")
    if held:
        lines += ["", f"<i>+{held} more, in the next CVE post.</i>"]
    return "\n".join(lines)


def fmt_one_line(r) -> str:
    return (f"{feed_emoji(r['feed'])} <a href=\"{esc(r['link'])}\">"
            f"{esc(trunc(r['title'], 120))}</a> · <i>{esc(r['feed'])}</i>")


def trending(store: "Store", cfg: Config):
    """CVEs named by several news outlets inside the window, not yet announced."""
    since = (now_utc() - timedelta(hours=cfg.trend_hours)).isoformat()
    seen = {}
    for feed, title, link, cves in store.db.execute(
            "SELECT feed, title, link, cves FROM items WHERE first_seen>=? AND cves!='' "
            "AND category IN ('news','industry') AND tier!='seed' ORDER BY first_seen", (since,)):
        for c in cves.split(","):
            seen.setdefault(c, {"feeds": [], "title": title, "link": link})
            if feed not in seen[c]["feeds"]:
                seen[c]["feeds"].append(feed)
    return [(c, v) for c, v in seen.items()
            if len(v["feeds"]) >= cfg.trend_min and not store.get(f"trend:{c}")]


def fmt_trend(cve: str, v: dict) -> str:
    outlets = ", ".join(v["feeds"])
    return "\n".join([
        f"\U0001F4C8 <b>Trending: {esc(cve)}</b> \U0001F4C8", "",
        f"{esc(v['title'])}", "",
        f"⚠️ <i>named by {len(v['feeds'])} outlets: {esc(outlets)}</i>", "",
        f"\U0001F4D6 <a href=\"{esc(v['link'])}\">Read more.</a> · "
        f"<a href=\"https://nvd.nist.gov/vuln/detail/{esc(cve)}\">NVD</a>"])


def fmt_cve_lines(rows, limit: int = 0) -> str:
    # obscure criticals in the digest: one line each, or 30 of them fill three messages
    lines = ["", f"‼️ <b>Critical CVEs, other vendors</b> · {len(rows)}"]
    rest = 0
    if limit and len(rows) > limit:
        rows, rest = sorted(rows, key=cvss, reverse=True)[:limit], len(rows) - limit
    for r in rows:
        sc = cvss(r)
        tail = f" · {sc:g}" if sc else ""
        lines.append(f"• <a href=\"{esc(r['link'])}\">{esc(trunc(r['title'], 110))}</a>{tail}")
    if rest:
        lines.append(f"<i>+{rest} more, all in the weekly report.</i>")
    return "\n".join(lines)


def fmt_tagged_line(r, cfg: Config, reason: bool = False) -> str:
    v, ot = vendor_tags(r, cfg)
    tags = " ".join("#" + t for t in v + (["OT"] if ot else []))
    why = f" · ⚠️ <i>{esc(r['reason'])}</i>" if reason and r["reason"] else ""
    return fmt_one_line(r) + why + (f" {tags}" if tags else "")


def in_window(local: datetime, cfg: Config) -> bool:
    """The channel posts only between POST_START and POST_END."""
    return cfg.post_start <= local.time() < cfg.post_end


def send_morning(cfg: Config, store: Store, tg: Telegram, local: datetime) -> None:
    """05:30: everything held overnight in one post - reds first, then headlines.
    The overnight CVEs wait for the 08:00 CVE post."""
    reds = store.pending("red")
    heads = store.pending("yellow", exclude_cve=True)
    lines = ["🌅 <b>Threat Wire · overnight</b>",
             f"<i>{local.strftime('%A %-d %B')} · since {cfg.post_end.strftime('%-I:%M %p')} last night</i>", ""]
    if not reds and not heads:
        lines.append("A quiet night: nothing newsworthy came in.")
    else:
        lines.append(f"🔴 {len(reds)} critical · 🟡 {len(heads)} headlines")
    if reds:
        lines += ["", "🔴 <b>Critical</b>"] + [fmt_tagged_line(r, cfg, reason=True) for r in reds]
    if heads:
        shown = heads[-cfg.catchup_max:]  # newest, if a big night overflows
        lines += ["", "🟡 <b>Headlines</b>"] + [fmt_tagged_line(r, cfg) for r in shown]
        if len(heads) > len(shown):
            lines.append(f"<i>+{len(heads) - len(shown)} older, in tonight's digest.</i>")
    if tg.send("\n".join(lines), silent=not reds):
        store.mark_sent([r["uid"] for r in reds] + [r["uid"] for r in heads])


def send_evening(cfg: Config, store: Store, tg: Telegram, local: datetime) -> None:
    """21:00: the day's newsworthy alerts, summarised. The last post of the day.
    'The day' runs from last night's POST_END, so the overnight items count."""
    since = local.replace(hour=cfg.post_end.hour, minute=cfg.post_end.minute,
                          second=0, microsecond=0) - timedelta(days=1)
    hours = (local - since).total_seconds() / 3600
    day = store.since_rows(hours, ("red", "yellow"))
    reds = [r for r in day if r["tier"] == "red"]
    heads = [r for r in day if r["tier"] == "yellow" and r["category"] != "cve"]
    n_cve = sum(1 for r in day if r["tier"] == "yellow" and r["category"] == "cve")
    low_cves = [r for r in store.pending("digest") if r["category"] == "cve"]

    tally = Counter()
    for r in day:
        tally.update(vendor_tags(r, cfg)[0])

    lines = ["🌙 <b>Threat Wire · today</b>",
             f"<i>{local.strftime('%A %-d %B')}</i>", "",
             f"🔴 {len(reds)} critical · 🟡 {len(heads)} headlines · 🧩 {n_cve} CVEs"]
    if tally:
        lines += ["", "<b>Most mentioned:</b> " +
                  " · ".join(f"#{v} {n}" for v, n in tally.most_common(6))]
    if reds:
        lines += ["", "🔴 <b>Critical</b>"] + \
                 [fmt_tagged_line(r, cfg, reason=True) for r in reds[-cfg.evening_max_red:]]
        if len(reds) > cfg.evening_max_red:
            lines.append(f"<i>+{len(reds) - cfg.evening_max_red} more earlier today.</i>")
    if heads:
        lines += ["", "🟡 <b>Headlines</b>"] + \
                 [fmt_tagged_line(r, cfg) for r in heads[-cfg.evening_max_head:]]
        if len(heads) > cfg.evening_max_head:
            lines.append(f"<i>+{len(heads) - cfg.evening_max_head} more earlier today.</i>")
    if low_cves:
        lines.append(fmt_cve_lines(low_cves, limit=cfg.digest_max_cve))
    lines += ["", f"<i>Back at {cfg.post_start.strftime('%-I:%M %p')} with the overnight catch-up.</i>"]

    if tg.send("\n".join(lines), silent=True):
        # anything still queued from the day is in this digest, so it does not
        # reappear in the morning catch-up. Yellow CVEs wait for 08:00.
        done = store.pending("digest") + store.pending("red") + \
            store.pending("yellow", exclude_cve=True)
        store.mark_sent([r["uid"] for r in done])


# -------------------------------------------------------------------- run ---

def run_once(cfg: Config, store: Store, tg: Telegram, force_flush: bool = False,
             force_morning: bool = False) -> None:
    seeding = store.is_new_db()
    recent = store.recent_titles(cfg.dedupe_hours)
    recent_cves = store.recent_cves()
    reds, counts, failures = [], {"red": 0, "yellow": 0, "digest": 0, "drop": 0, "dup": 0}, []

    for feed in cfg.feeds:
        # a feed added after go-live seeds silently too, or its back catalogue floods the channel
        new_feed = not seeding and not store.has_feed(feed["name"])
        try:
            items = parse_feed(feed, fetch(feed_url(feed)))
        except Exception as e:  # one bad feed never stops the run
            failures.append(f"{feed['name']}: {e}")
            log.warning("feed failed %s: %s", feed["name"], e)
            continue

        for it in items:
            if store.seen(it["uid"]):
                continue
            it["feed"], it["category"] = feed["name"], feed["category"]
            it["norm"] = norm_title(it["title"])
            it["cves"] = {c.upper() for c in CVE_RE.findall(f"{it['title']} {it['summary']}")}

            if seeding or new_feed:  # first run: remember everything, alert on nothing
                store.add(it, "seed", "", 1)
                continue

            tier, reason = classify(it, feed["category"], cfg)

            # NVD repeats CVEs already carried by KEV or a vendor PSIRT
            if feed["category"] == "cve" and tier != "drop" and \
                    any(store.cve_known(c) for c in it["cves"]):
                tier, reason = "dup", "CVE already carried"

            # same story from another outlet -> don't send twice
            if tier != "drop" and feed["category"] in ("news", "industry") and \
                    any(jaccard(it["norm"], t) >= cfg.similarity for t in recent):
                tier, reason = "dup", "duplicate story"
            # CVE already alerted on this week -> demote one level
            elif tier in ("red", "yellow") and it["cves"] and it["cves"] <= recent_cves:
                tier = "yellow" if tier == "red" else "digest"
                reason += " · already reported"

            counts[tier] = counts.get(tier, 0) + 1
            if tier == "red":
                if len(reds) >= cfg.max_red:
                    tier = "yellow"
                else:
                    reds.append(it["uid"])
            store.add(it, tier, reason, 1 if tier in ("drop", "dup") else 0)
            if tier in ("red", "yellow", "digest"):
                recent.append(it["norm"])
                if tier != "digest":
                    recent_cves |= it["cves"]
    store.commit()

    if seeding:
        n = store.db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        tg.send("\U0001F6E1️ <b>Threat Wire is online</b>\n"
                f"Watching {len(cfg.feeds) - len(failures)} feeds. "
                f"Indexed {n} existing items as a baseline, so only new items alert from here.")
        today = datetime.now(cfg.tz).date().isoformat()
        store.set("last_morning", today)
        store.set("last_evening", today)
        if failures:
            tg.send("⚠️ <b>Feeds that failed on first run</b>\n" + esc("\n".join(failures)), silent=True)
        return

    local = datetime.now(cfg.tz)
    today = local.date().isoformat()
    window = in_window(local, cfg) or force_flush or force_morning

    # 21:00 onwards: the evening digest once, then nothing until morning.
    # Whatever is still queued from the day is listed in it and marked sent.
    if force_flush or (local.time() >= cfg.post_end and store.get("last_evening") != today):
        send_evening(cfg, store, tg, local)
        store.set("last_evening", today)

    if not window:
        log.info("run (outside posting window, held): %s, failures=%d", counts, len(failures))
        return

    # 05:30: the morning catch-up, once - everything that came in overnight
    if force_morning or store.get("last_morning") != today:
        send_morning(cfg, store, tg, local)
        store.set("last_morning", today)

    # red: a card each, with sound. Stored unsent, so a failed send is retried.
    posted = []
    for r in store.pending("red", limit=cfg.max_red):
        if tg.send(fmt_red(r, r["reason"], hashtags(r, cfg))):
            posted.append(r["uid"])
    store.mark_sent(posted)

    # trending: a CVE several outlets are writing about, announced once
    for cve, v in trending(store, cfg)[:5]:
        if tg.send(fmt_trend(cve, v), silent=True):
            store.set(f"trend:{cve}", now_utc().isoformat())

    # yellow headlines: one silent card each, a few per pass
    posted = []
    for r in store.pending("yellow", exclude_cve=True, limit=cfg.headline_max):
        if tg.send(fmt_headline(r, r["reason"], hashtags(r, cfg)), silent=True):
            posted.append(r["uid"])
    store.mark_sent(posted)

    # yellow CVEs stay grouped, at the CVE_BATCH_AT hours
    slots = [h for h in cfg.cve_batch_at if h <= local.hour]
    slot = f"{today} {slots[-1]:02d}" if slots else ""
    if force_flush or (slot and store.get("last_cve_slot") != slot):
        rows = store.pending("yellow", category="cve")
        if rows:
            # an Oracle CPU day lands 70+ at once: highest CVSS first, rest wait
            held = max(0, len(rows) - cfg.cve_batch_max)
            if held:
                rows = sorted(rows, key=cvss, reverse=True)[:cfg.cve_batch_max]
            when = local.strftime("%-I:%M %p")
            if tg.send(fmt_cve_batch(rows, when, cfg, held), silent=True):
                store.mark_sent([r["uid"] for r in rows])
        if slot:
            store.set("last_cve_slot", slot)

    # a failing feed is logged, never posted - this is a public channel now.
    # A dead feed shows in the weekly's "feeds that went quiet" section.
    if failures:
        log.warning("feeds failing: %s", "; ".join(failures))

    log.info("run: %s, failures=%d", counts, len(failures))


def check_feeds(cfg: Config) -> int:
    bad = 0
    for feed in cfg.feeds:
        try:
            items = parse_feed(feed, fetch(feed_url(feed)))
            status = f"OK   {len(items):4d} items" if items else "WARN    0 items (check URL)"
            if not items:
                bad += 1
        except Exception as e:
            status, bad = f"FAIL {e}", bad + 1
        print(f"{feed['name']:<22} {status}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Threat Wire cyber alerts -> Telegram")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--check-feeds", action="store_true")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--digest-now", action="store_true")
    ap.add_argument("--morning-now", action="store_true")
    ap.add_argument("--db", default=str(DATA / "threatwire.db"))
    a = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(),
                                  logging.FileHandler(DATA / "threatwire.log", encoding="utf-8")])
    load_env(BASE / ".env")
    load_env(ENV_FILE)
    cfg = Config()

    if a.check_feeds:
        return check_feeds(cfg)

    token = os.environ.get("THREATWIRE_BOT_TOKEN", "").strip()
    chat = os.environ.get("THREATWIRE_CHAT_ID", "").strip()
    if not a.dry_run and (not token or not chat):
        log.error("Set THREATWIRE_BOT_TOKEN and THREATWIRE_CHAT_ID in %s or %s",
                  BASE / ".env", ENV_FILE)
        return 2
    tg = Telegram(token, chat, dry_run=a.dry_run)

    if a.test:
        ok = tg.send("✅ <b>Threat Wire test</b>\nThe bot can post to this channel.")
        return 0 if ok else 1

    store = Store(Path(a.db))
    if a.loop:
        while True:
            try:
                run_once(cfg, store, tg)
            except Exception:
                log.exception("run failed")
            time.sleep(cfg.poll * 60)
    run_once(cfg, store, tg, force_flush=a.digest_now, force_morning=a.morning_now)
    return 0


if __name__ == "__main__":
    sys.exit(main())
