#!/usr/bin/env python3
"""
Threat Wire weekly report - optional. Run it from a weekly timer.

  1. Pulls the week's items out of data/threatwire.db: every red that fired,
     the yellows and digest items, the CVEs seen, counts by feed and by vendor,
     and which feeds went quiet. The numbers are computed here, exactly.
  2. Writes a bundle at data/weekly/bundle-<date>.md. That alone is useful:
     --bundle-only stops here and needs nothing else installed.
  3. Optionally runs Claude Code (`claude -p`) on the bundle. Claude writes a
     Markdown report into THREATWIRE_WEEKLY_OUTDIR and a short Telegram post,
     and reports the numbers rather than recomputing them. It gets no shell
     and no network, because the bundle is strangers' advisory and news text;
     file writes are fenced to the output folders - see allowed_tools().
  4. Posts the Telegram summary to the channel.

Settings (environment, or the .env file):
    THREATWIRE_WEEKLY_OUTDIR   where the report is written (default data/reports)
    THREATWIRE_WEEKLY_PROMPT   prompt file (default threatwire_weekly_prompt.md;
                               local_weekly_prompt.md is used if it exists)
    THREATWIRE_WEEKLY_CWD      folder Claude runs in (default: the output folder)
    THREATWIRE_WEEKLY_MODEL    model alias (default sonnet)
    CLAUDE_BIN                 path to the claude CLI (default: claude on PATH)

Usage:
    python3 threatwire_weekly.py --bundle-only  # just build the bundle
    python3 threatwire_weekly.py --no-post      # write the report, send nothing
    python3 threatwire_weekly.py                # full run, posts
    python3 threatwire_weekly.py --db other.db  # read a database copied from elsewhere
"""
import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
import threatwire as T  # noqa: E402
import threatwire_sources as S  # noqa: E402

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
WEEKLY = DATA / "weekly"
OUT = DATA / "out"

T.load_env(BASE / ".env")
T.load_env(T.ENV_FILE)
_local_prompt = BASE / "local_weekly_prompt.md"
PROMPT = Path(os.environ.get("THREATWIRE_WEEKLY_PROMPT") or
              (_local_prompt if _local_prompt.exists() else BASE / "threatwire_weekly_prompt.md"))
OUTDIR = Path(os.environ.get("THREATWIRE_WEEKLY_OUTDIR") or DATA / "reports").expanduser()
WORKDIR = Path(os.environ.get("THREATWIRE_WEEKLY_CWD") or OUTDIR).expanduser()
CLAUDE = os.environ.get("CLAUDE_BIN") or shutil.which("claude") or "claude"
MODEL = os.environ.get("THREATWIRE_WEEKLY_MODEL", "sonnet")
TIMEOUT = 50 * 60
CT = ZoneInfo(S.TIMEZONE)


def log(msg):
    print(f"{datetime.now(CT):%H:%M:%S} {msg}", flush=True)


# ------------------------------------------------------------------ data ---

def week_rows(db_path: Path, days: int = 7):
    """Everything first seen in the last `days`, excluding the seed baseline."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT * FROM items WHERE first_seen>=? AND tier IN ('red','yellow','digest') "
        "ORDER BY tier, first_seen", (since,)).fetchall()
    db.close()
    return rows


def vendor_hits(rows, cfg):
    """Vendors named across the week, by the same tags the channel posts."""
    c = Counter()
    for r in rows:
        c.update(T.vendor_tags(r, cfg)[0])
    return c


def build_bundle(rows, cfg, date, days=7):
    WEEKLY.mkdir(parents=True, exist_ok=True)
    by_tier = Counter(r["tier"] for r in rows)
    by_feed = Counter(r["feed"] for r in rows)
    cves = Counter()
    for r in rows:
        for c in (r["cves"] or "").split(","):
            if c:
                cves[c] += 1
    vendors = vendor_hits(rows, cfg)
    quiet = [f["name"] for f in cfg.feeds if f["name"] not in by_feed]

    L = [f"# Threat Wire bundle - {date}", "",
         f"Window: last {days} days. Counts are exact; report them, never recompute.", "",
         "## Totals", "",
         f"- Red (sent immediately): **{by_tier.get('red', 0)}**",
         f"- Yellow (batched): **{by_tier.get('yellow', 0)}**",
         f"- Digest: **{by_tier.get('digest', 0)}**",
         f"- Total items: **{len(rows)}**", "",
         "## By feed", ""]
    L += [f"- {f}: {n}" for f, n in by_feed.most_common()] or ["- none"]

    L += ["", "## Vendors mentioned (hashtag counts)", ""]
    L += [f"- {v}: {n}" for v, n in vendors.most_common(25)] or ["- none"]

    L += ["", "## CVEs seen", ""]
    L += [f"- {c} (x{n})" for c, n in cves.most_common(40)] or ["- none"]

    L += ["", "## Feeds with nothing this week", ""]
    L += [f"- {f}" for f in quiet] or ["- none - every feed produced something"]

    for tier, label in (("red", "RED - fired immediately"),
                        ("yellow", "YELLOW - batched"),
                        ("digest", "DIGEST")):
        sel = [r for r in rows if r["tier"] == tier]
        L += ["", f"## {label} ({len(sel)})", ""]
        if not sel:
            L.append("- none")
            continue
        for r in sel:
            L.append(f"### {r['title']}")
            L.append(f"- feed: {r['feed']} ({r['category']}) | reason: {r['reason']}"
                     f" | first seen: {r['first_seen'][:16]}Z")
            if r["cves"]:
                L.append(f"- CVEs: {r['cves']}")
            L.append(f"- link: {r['link']}")
            if r["summary"]:
                L.append(f"- summary: {r['summary'][:500]}")
            L.append("")

    p = WEEKLY / f"bundle-{date}.md"
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------- claude ---

def allowed_tools():
    # Only Edit(path) rules are matched by the file-permission check, and an
    # Edit rule covers every file-writing tool including Write - a Write(path)
    # rule is silently ignored and claude exits 0 having written nothing.
    # The doubled leading slash ("//home/...") is how an absolute path is
    # written in a permission rule; with a single slash it is read as relative
    # to the project and never matches.
    return ["Read", "Glob", "Grep",
            f"Edit(/{OUTDIR}/**)",
            f"Edit(/{OUT}/**)"]


def run_claude(bundle: Path, date: str, tg_out: Path) -> bool:
    now = datetime.now(CT)
    prompt = PROMPT.read_text(encoding="utf-8").format(
        date=date,
        date_long=now.strftime("%A %-d %B %Y"),
        week=f"{(now - timedelta(days=6)):%-d} – {now:%-d %B %Y}",
        bundle=bundle, telegram_out=tg_out, outdir=OUTDIR)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    tg_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [CLAUDE, "-p", "--no-session-persistence", "--model", MODEL,
           "--permission-mode", "dontAsk", "--add-dir", str(DATA), "--add-dir", str(OUTDIR),
           "--allowedTools", *allowed_tools(),
           # Deny beats allow. This run reads strangers' advisory and news text,
           # so it gets no shell and no network, whatever the project's own
           # settings allow.
           "--disallowedTools", "Bash", "WebFetch", "WebSearch", "Agent",
           "--", prompt]
    log(f"claude -p ({MODEL}) starting")
    r = subprocess.run(cmd, cwd=WORKDIR, capture_output=True, text=True, timeout=TIMEOUT)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"claude-weekly-{date}.log").write_text(r.stdout + r.stderr, encoding="utf-8")
    log(f"claude -p exit {r.returncode}")
    return r.returncode == 0


# ------------------------------------------------------------------- run ---

def main() -> int:
    ap = argparse.ArgumentParser(description="Threat Wire weekly report")
    ap.add_argument("--no-post", action="store_true")
    ap.add_argument("--bundle-only", action="store_true")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--db", default=str(DATA / "threatwire.db"))
    a = ap.parse_args()

    cfg = T.Config()
    date = datetime.now(CT).strftime("%Y-%m-%d")

    rows = week_rows(Path(a.db), a.days)
    bundle = build_bundle(rows, cfg, date, a.days)
    log(f"bundle written: {bundle} ({len(rows)} items)")
    if a.bundle_only:
        return 0

    if not rows:
        log("nothing to report this week - no note written")
        return 0

    tg_out = OUT / f"telegram-weekly-{date}.txt"
    if not run_claude(bundle, date, tg_out):
        log("claude failed - see the log in data/out/")
        return 1

    if a.no_post:
        log("--no-post: note written, nothing sent")
        return 0

    if not tg_out.exists():
        log(f"no Telegram text at {tg_out} - note written, nothing sent")
        return 1

    token = os.environ.get("THREATWIRE_BOT_TOKEN", "").strip()
    chat = os.environ.get("THREATWIRE_CHAT_ID", "").strip()
    if not token or not chat:
        log("THREATWIRE_BOT_TOKEN / THREATWIRE_CHAT_ID not set - nothing sent")
        return 2
    tg = T.Telegram(token, chat)
    ok = tg.send(tg_out.read_text(encoding="utf-8").strip(), silent=True)
    log(f"telegram sent: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
