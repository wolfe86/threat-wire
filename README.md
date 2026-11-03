# Threat Wire

**A cybersecurity alert feed that knows which vendors you run.** It reads CISA KEV, vendor PSIRTs, the NVD API, CISA ICS advisories and a dozen security news sites, scores every item against your stack, and posts what matters to a Telegram channel — tagged by vendor, so `#Fortinet` pulls up every Fortinet alert.

Built for the solo IT/security lead and the SOC engineer who can't read everything but can't miss the one that hits their environment.

- **Quiet by design.** Tested against one Patch Tuesday week (1,984 new CVEs), it raised 2 red alerts.
- **Python standard library only.** No `pip install`. SQLite remembers what's been sent; a systemd timer runs it every 10 minutes. It's happy on a 1 GB VM.
- **Live example:** [t.me/WolfeLabsThreatWire](https://t.me/WolfeLabsThreatWire) — free to join, but the point of this repo is to build one around *your* stack.

## What it posts

| When | Post |
|---|---|
| Start of the day (05:30) | 🌅 **Catch-up** — everything that came in overnight, red first |
| During the day | 🔴 **Red card** — your vendor plus exploited / KEV / zero-day / critical, or any big vendor actively exploited |
| During the day | 🟡 **Headline card** — vendor advisories, ICS advisories, notable news |
| During the day | 📈 **Trending CVE** — two or more outlets naming the same CVE within 48 hours |
| 08:00 · 12:00 · 16:00 · 20:00 | 🧩 **CVEs, grouped** — your vendors and big-name criticals from NVD |
| End of the day (21:00) | 🌙 **Evening digest** — the day summarised, most-mentioned vendors, other-vendor criticals |
| Weekly (optional) | 📄 **Weekly report** — written by Claude Code from exact counts, see below |

Nothing posts outside the window; it's all in the next morning's catch-up. Red posts make a sound, everything else is sent silently, and subscribers can override either.

A red card looks like this:

```
🔴 🖋️ Attackers Exploit Critical Siemens IoT2050 Flaw to Plant Remote Command Backdoors 🖋️

A maximum-severity security flaw impacting Siemens SIMATIC IoT2050 Advanced devices
has come under active exploitation… (CVE-2026-58115, CVSS 10.0)

⚠️ siemens · simatic · CVSS 10 · under active exploitation
📖 Read more.
🔗 Via "The Hacker News"

#Siemens #OT #Exploited #Critical
```

## Quick start

You need Python 3.9+, a Telegram account and somewhere to run a timer.

**1. Make a bot and a channel.**
- In Telegram, message [@BotFather](https://t.me/BotFather), send `/newbot` and keep the token it gives you.
- Create a channel, open its settings → *Administrators* → add your bot with permission to post.

**2. Get the code and set your credentials.**
```
git clone https://github.com/wolfe86/threat-wire.git ~/threat-wire
cd ~/threat-wire
cp .env.example .env && chmod 600 .env
nano .env        # paste the token; chat ID is @yourchannel, or the -100… number for a private channel
```

**3. Tell it what you run.**
```
cp local_sources.example.py local_sources.py
nano local_sources.py   # your vendors, time zone, posting window
```

**4. Check it.**
```
python3 threatwire.py --check-feeds   # every feed should say OK (Azure Status shows 0 items when there is no incident)
python3 threatwire.py --test          # a test message should appear in the channel
python3 threatwire.py                 # first run: records everything already out there as a baseline, posts one "online" message
```
The first run is silent on purpose, so you aren't flooded with last month's news. From then on, only new items alert.

**5. Schedule it.**
```
cp examples/systemd/threatwire.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now threatwire.timer
```
On a headless server, run `loginctl enable-linger $USER` once so user timers run without a login, or install the units as system units with `User=` set.

## Make it yours

Everything is in `threatwire_sources.py`, and anything you set in `local_sources.py` overrides it. `local_sources.py` is git-ignored, so your watchlist never ends up in a commit. Lists are replaced whole: copy a list, then edit it.

| Setting | What it does |
|---|---|
| `STACK` | **Your vendors and products.** A hit plus exploited / zero-day / breach / critical is red |
| `OT_VENDORS` · `OT_PRIORITY` | OT/ICS vendors; `OT_PRIORITY` are the ones whose criticals go red (default: all) |
| `BIG_VENDORS` | Widely deployed vendors. Outside your stack they go red **only when exploited**, never on CVSS alone |
| `INDUSTRY` | Sector words (oil & gas, SCADA, named ICS threat groups) that make general news relevant |
| `URGENT_TERMS` · `EXPLOITED_TERMS` | What counts as urgent, and the stricter list that counts as "exploited" |
| `DROP_PATTERNS` | Titles to throw away outright |
| `FEEDS` | The sources. Add your vendors' PSIRT RSS feeds here; keep NVD last |
| `POST_START` · `POST_END` · `TIMEZONE` | The posting window |
| `CVE_BATCH_AT` | Hours of the grouped CVE posts |
| `VENDOR_TAGS` · `TOPIC_TAGS` | How matched terms become hashtags (`fortigate` → `#Fortinet`) |

After changing feeds, run `--check-feeds`. To see what a pass *would* send, copy the database and run against the copy — `--dry-run` prints instead of posting but still records what it saw:
```
cp data/threatwire.db /tmp/copy.db && python3 threatwire.py --dry-run --db /tmp/copy.db
```

## How it decides

1. **Fetch** every feed. One failing feed never stops a run; failures are logged.
2. **Drop** titles matching `DROP_PATTERNS`.
3. **Classify** by source type (KEV, PSIRT, ICS, status page, news, NVD) against your watchlists. NVD entries are matched on their **product names, not the description** — descriptions name products a CVE isn't about.
4. **De-duplicate.** The same story from a second outlet within 36 hours is suppressed (word-overlap similarity ≥ 0.6). A CVE NVD repeats from KEV or a PSIRT is marked duplicate. A CVE already alerted this week drops one tier.
5. **Cap.** More than 8 reds in one pass fall to yellow — a safety valve for patch days.
6. **Post** inside the window, oldest first, at most 3 headlines per pass so a spike drains instead of landing as a wall.

Everything is stored in `data/threatwire.db`, sent or not, so the weekly report can count what was filtered out.

## The weekly report (optional)

`threatwire_weekly.py` pulls the week out of SQLite and computes every count exactly, then hands that bundle to [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) to write a Markdown report and a short Telegram summary.

- **The model reports the numbers; it never computes them.**
- **It runs with no shell and no network, and can write only to the report folder.** Its input is strangers' advisory and news text, which is a prompt-injection surface; the report has an *Oddities* section for anything that looks like an instruction.
- Without Claude Code, `--bundle-only` still gives you the week's data as Markdown.

Settings go in `.env`: `THREATWIRE_WEEKLY_OUTDIR` (where reports go), `CLAUDE_BIN`, `THREATWIRE_WEEKLY_MODEL`. A `local_weekly_prompt.md`, if present, replaces the shipped prompt. Example units are in `examples/systemd/`. If the feed runs on one machine and Claude Code on another, `examples/pull_db.sh` copies the database across safely first.

## Commands

| Command | Does |
|---|---|
| `python3 threatwire.py` | One pass (what the timer runs) |
| `--check-feeds` | Fetch every feed, report OK / WARN / FAIL, send nothing |
| `--test` | Send a test message |
| `--dry-run` | Print instead of send (still writes the database) |
| `--digest-now` | Send the evening digest and the CVE post now |
| `--morning-now` | Send the morning catch-up now |
| `--db PATH` | Use another database file |
| `--loop` | Run forever instead of using a timer |

## License

MIT — see [LICENSE](LICENSE).
