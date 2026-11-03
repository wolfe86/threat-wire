"""Threat Wire sources, watchlists and tuning.

Everything here is a default. To make it yours without editing this file,
copy local_sources.example.py to local_sources.py and set only what you want
to change - usually STACK, TIMEZONE and the posting window. local_sources.py
is git-ignored, so your watchlist never ends up in a commit.

Nothing here is secret. Credentials live in the environment
(THREATWIRE_BOT_TOKEN, THREATWIRE_CHAT_ID) - see .env.example.

After changing FEEDS, run:  python3 threatwire.py --check-feeds
"""

TIMEZONE = "America/Chicago"

POLL_MINUTES = 10        # how often the timer runs a pass

# The channel posts only inside this window (local time, "HH:MM"). Nothing is
# sent outside it - red included. The first pass at POST_START sends the
# morning catch-up (everything that came in overnight, in one post); the first
# pass at POST_END sends the evening digest (the day's newsworthy alerts
# summarised), and then the channel is quiet.
POST_START = "05:30"
POST_END = "21:00"

# Yellow headlines post one at a time. A pass releases at most HEADLINE_MAX_PER_RUN of them, so a spike drains over a
# few passes instead of landing as a wall. 3 per pass x 6 passes/h = 18/h of
# capacity against an arrival rate nearer 3/h, so the queue is normally empty.
HEADLINE_MAX_PER_RUN = 3

# Yellow CVEs stay grouped: one post at each of these local hours. The cap is
# for Oracle CPU and Patch Tuesday days - highest CVSS first, the rest wait for
# the next post. An exploited or KEV CVE never waits for this: it is red.
CVE_BATCH_AT = [8, 12, 16, 20]
CVE_BATCH_MAX = 30

# The morning catch-up and evening digest are summaries: past these counts
# they say "+N more" instead of listing.
CATCHUP_MAX_HEADLINES = 25
EVENING_MAX_RED = 20
EVENING_MAX_HEADLINES = 20
DIGEST_MAX_CVE = 10
MAX_RED_PER_RUN = 8      # safety valve: extra reds in one run drop to yellow
DEDUPE_WINDOW_HOURS = 36  # stories this similar within this window are duplicates
TITLE_SIMILARITY = 0.6   # 0-1, how close two headlines must be to count as one

# ---------------------------------------------------------------------------
# WATCHLISTS - case-insensitive, matched on whole words/phrases
# ---------------------------------------------------------------------------

# YOUR stack - the vendors and products you run. This is the list to change.
# A hit here plus exploited / zero-day / breach / critical = RED.
# The example below is a common small-business mix; replace it with yours.
STACK = [
    "microsoft", "m365", "microsoft 365", "office 365", "exchange online",
    "exchange server", "entra", "azure", "intune", "microsoft teams",
    "sharepoint", "onedrive", "windows server", "active directory",
    "fortinet", "fortigate", "fortios", "forticlient",
    "cisco", "ios xe", "cisco asa", "meraki", "anyconnect",
    "vmware", "esxi", "vcenter",
    "veeam",
]

# OT / ICS vendors and products.
OT_VENDORS = [
    "rockwell", "allen-bradley", "factorytalk", "controllogix", "compactlogix",
    "studio 5000", "rslogix",
    "siemens", "simatic", "wincc",
    "schneider electric", "modicon", "ecostruxure", "triconex",
    "emerson", "deltav", "ovation", "roc800",
    "honeywell", "experion",
    "abb", "ge vernova", "cimplicity",
    "yokogawa", "centum",
    "aveva", "wonderware", "osisoft", "pi system",
    "inductive automation", "ignition", "kepware",
    "moxa", "phoenix contact", "hirschmann", "red lion", "codesys", "wago",
    "mitsubishi electric", "omron", "schweitzer engineering", "sel-",
    "iconics", "opto 22",
]

# OT vendors whose critical advisories are RED. Defaults to every OT vendor
# (computed at the bottom of this file); set it in local_sources.py to narrow
# it to the ones you run.

# Industry / sector terms - makes general news relevant to oil & gas.
INDUSTRY = [
    "oil and gas", "oil & gas", "pipeline", "pipelines", "refinery",
    "refineries", "upstream", "midstream", "downstream", "lng", "petroleum",
    "drilling", "energy sector", "energy company", "utility", "utilities",
    "critical infrastructure",
    "scada", "plc", "plcs", "ics", "ot security", "operational technology",
    "hmi", "dcs", "modbus", "dnp3", "historian", "tsa security directive",
    "volt typhoon", "frostygoop", "pipedream", "industroyer", "triton",
    "trisis", "chernovite", "electrum", "kamacite", "bauxite",
]

# Vendors with an install base big enough that their critical CVEs make the news.
# NVD only: matched on the CVE's vendor/product names, never its description.
# Critical (CVSS 9+) = yellow; critical and exploited = red.
BIG_VENDORS = [
    "microsoft", "windows", "apple", "macos", "google", "chrome", "android",
    "cisco", "oracle", "vmware", "broadcom", "citrix", "netscaler", "ivanti",
    "sap", "adobe", "atlassian", "confluence", "jira", "linux kernel", "linux",
    "openssl", "openssh", "juniper", "sonicwall", "f5", "big-ip", "zoom",
    "samsung", "qualcomm", "intel", "nvidia", "ibm", "apache", "mozilla",
    "firefox", "check point", "zyxel", "kubernetes", "github", "gitlab", "okta",
    "salesforce", "servicenow", "veeam", "progress", "moveit", "solarwinds",
    "openai", "anthropic", "fortinet", "palo alto networks",
]

# Vendors outside STACK go RED only when exploited: a CISA KEV entry, or an
# item whose text says exploited / zero-day. A high CVSS score alone is not
# enough. Measured on two weeks of real data, full STACK rules for every big
# vendor sent ~14 reds a day (Oracle's quarterly patch day alone ~70); this
# rule ~5. WATCH_EXPLOITED defaults to BIG_VENDORS minus STACK (computed at the
# bottom of this file).

# Vendor terms that are also ordinary words. They still match NVD product names,
# but never news or advisory text - "threat intel", "work in progress".
AMBIGUOUS_IN_TEXT = ["progress", "intel", "ignition", "ovation", "zoom", "centum"]

# What counts as "exploited" for WATCH_EXPLOITED. Stricter than URGENT_TERMS on
# purpose: "breach", "compromised" and "hacked" turned up in too many stories
# that only mention a vendor in passing.
EXPLOITED_TERMS = [
    "actively exploited", "exploited in the wild", "under active exploitation",
    "known exploited", "exploitation detected", "zero-day", "zero day", "0-day",
]

# ---------------------------------------------------------------------------
# HASHTAGS - every post carries the vendors it names, so a reader can tap
# #Fortinet in Telegram and see every Fortinet post in the channel. Each
# watchlist term maps to one vendor tag; a term not listed here becomes its own
# name with spaces and punctuation removed ("check point" -> #CheckPoint).
# ---------------------------------------------------------------------------

MAX_VENDOR_TAGS = 4

# Topic tags, so a story that names no vendor is still findable. Regex -> tag,
# matched on the title and summary.
TOPIC_TAGS = {
    r"\bransomware\b": "Ransomware",
    r"\b(data breach|breached|data leak|leaked data)\b": "DataBreach",
    r"\bsupply[- ]chain\b": "SupplyChain",
    r"\bphishing\b": "Phishing",
}

VENDOR_TAGS = {
    # Microsoft
    "microsoft": "Microsoft", "m365": "Microsoft", "microsoft 365": "Microsoft",
    "office 365": "Microsoft", "exchange online": "Microsoft",
    "exchange server": "Microsoft", "entra": "Microsoft", "azure": "Microsoft",
    "intune": "Microsoft", "microsoft teams": "Microsoft", "sharepoint": "Microsoft",
    "onedrive": "Microsoft", "windows server": "Microsoft", "windows": "Microsoft",
    "active directory": "Microsoft",
    # Fortinet
    **{t: "Fortinet" for t in (
        "fortinet", "fortigate", "fortios", "forticlient", "fortianalyzer",
        "fortimanager", "fortiweb", "fortisiem", "fortisandbox", "fortiproxy",
        "fortimail", "fortiswitch", "fortiap")},
    "connectwise": "ConnectWise", "screenconnect": "ConnectWise", "skykick": "SkyKick",
    **{t: "Cisco" for t in ("cisco", "ios xe", "cisco asa", "firepower", "meraki",
                            "anyconnect", "secure client")},
    **{t: "PaloAlto" for t in ("palo alto", "palo alto networks", "pan-os",
                               "globalprotect", "prisma access", "cortex xdr")},
    # OT
    **{t: "Rockwell" for t in ("rockwell", "allen-bradley", "factorytalk",
                               "controllogix", "compactlogix", "studio 5000", "rslogix")},
    "siemens": "Siemens", "simatic": "Siemens", "wincc": "Siemens",
    **{t: "Schneider" for t in ("schneider electric", "modicon", "ecostruxure", "triconex")},
    **{t: "Emerson" for t in ("emerson", "deltav", "ovation", "roc800")},
    "honeywell": "Honeywell", "experion": "Honeywell", "abb": "ABB",
    "ge vernova": "GEVernova", "cimplicity": "GEVernova",
    "yokogawa": "Yokogawa", "centum": "Yokogawa",
    **{t: "AVEVA" for t in ("aveva", "wonderware", "osisoft", "pi system")},
    "inductive automation": "Ignition", "ignition": "Ignition", "kepware": "Kepware",
    "phoenix contact": "PhoenixContact", "red lion": "RedLion", "codesys": "CODESYS",
    "wago": "WAGO", "mitsubishi electric": "Mitsubishi",
    "schweitzer engineering": "SEL", "sel-": "SEL", "iconics": "ICONICS", "opto 22": "Opto22",
    # big vendors
    "apple": "Apple", "macos": "Apple", "google": "Google", "chrome": "Google",
    "android": "Google", "vmware": "VMware", "broadcom": "VMware",
    "citrix": "Citrix", "netscaler": "Citrix", "sap": "SAP",
    "atlassian": "Atlassian", "confluence": "Atlassian", "jira": "Atlassian",
    "linux kernel": "Linux", "openssl": "OpenSSL", "openssh": "OpenSSH",
    "f5": "F5", "big-ip": "F5", "ibm": "IBM", "mozilla": "Mozilla", "firefox": "Mozilla",
    "github": "GitHub", "gitlab": "GitLab", "servicenow": "ServiceNow",
    "sonicwall": "SonicWall", "progress": "Progress", "moveit": "Progress",
    "solarwinds": "SolarWinds", "openai": "OpenAI", "nvidia": "NVIDIA",
}

# A CVE named by this many news/industry outlets inside this window gets one
# "Trending" post, whatever the vendor.
TRENDING_HOURS = 48
TRENDING_MIN_OUTLETS = 2

# Words that make something urgent.
URGENT_TERMS = [
    "actively exploited", "exploited in the wild", "exploitation detected",
    "under active exploitation", "known exploited",
    "zero-day", "zero day", "0-day",
    "breach", "breached", "compromised", "compromise", "hacked", "hijacked",
    "unauthorized access",
    "ransomware", "out-of-band", "emergency patch", "emergency directive",
    "supply chain attack", "wiper", "data leak", "suspended", "outage",
]

# Titles matching any of these regexes are dropped entirely (noise).
DROP_PATTERNS = [
    r"^Chromium CVE-",            # MSRC republishes every Chrome CVE; Edge auto-updates
    r"Updated an acknowledgement",
    r"informational change only",
]

# ---------------------------------------------------------------------------
# FEEDS
#   type:     rss | kev | nvd
#   category: gov | psirt | ics | status | news | industry | cve
#   psirt and status feeds are assumed to be "in the stack" already.
# ---------------------------------------------------------------------------

FEEDS = [
    # Government
    {"name": "CISA KEV",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "type": "kev", "category": "gov"},
    {"name": "CISA Advisories",
     "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
     "type": "rss", "category": "gov"},
    {"name": "CISA ICS Advisories",
     "url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
     "type": "rss", "category": "ics"},

    # Vendor PSIRTs - add or remove to match your stack
    {"name": "Microsoft MSRC",
     "url": "https://api.msrc.microsoft.com/update-guide/rss",
     "type": "rss", "category": "psirt"},
    {"name": "Fortinet PSIRT",
     "url": "https://www.fortiguard.com/rss/ir.xml",
     "type": "rss", "category": "psirt"},
    {"name": "Palo Alto PSIRT",
     "url": "https://security.paloaltonetworks.com/rss.xml",
     "type": "rss", "category": "psirt"},
    {"name": "Cisco PSIRT",
     "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
     "type": "rss", "category": "psirt"},

    # OT vendor PSIRTs (Rockwell, Schneider, Emerson, Honeywell are covered by CISA ICS)
    {"name": "Siemens ProductCERT",
     "url": "https://cert-portal.siemens.com/productcert/rss/advisories.atom",
     "type": "rss", "category": "ics"},

    # Vendor status pages
    # --check-feeds reports "0 items" for this one whenever Azure has no open
    # incident, which is most of the time. That is healthy, not a broken feed.
    {"name": "Azure Status",
     "url": "https://azure.status.microsoft/en-us/status/feed/",
     "type": "rss", "category": "status"},

    # Breaking news
    {"name": "BleepingComputer",
     "url": "https://www.bleepingcomputer.com/feed/",
     "type": "rss", "category": "news"},
    {"name": "The Hacker News",
     "url": "https://feeds.feedburner.com/TheHackersNews",
     "type": "rss", "category": "news"},
    {"name": "SecurityWeek",
     "url": "https://www.securityweek.com/feed/",
     "type": "rss", "category": "news"},
    {"name": "The Record",
     "url": "https://therecord.media/feed",
     "type": "rss", "category": "news"},
    {"name": "Krebs on Security",
     "url": "https://krebsonsecurity.com/feed/",
     "type": "rss", "category": "news"},
    {"name": "Dark Reading",
     "url": "https://www.darkreading.com/rss.xml",
     "type": "rss", "category": "news"},
    # Infosecurity Magazine carries stories the others miss (found in a gap
    # check against a large public channel).
    {"name": "Infosecurity Magazine",
     "url": "https://www.infosecurity-magazine.com/rss/news/",
     "type": "rss", "category": "news"},
    {"name": "ESET WeLiveSecurity",
     "url": "https://www.welivesecurity.com/en/rss/feed/",
     "type": "rss", "category": "news"},
    # "news", not "gov": the gov rules make every item at least yellow.
    {"name": "UK NCSC",
     "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
     "type": "rss", "category": "news"},
    {"name": "ITPro",
     "url": "https://www.itpro.com/feeds/tag/security",
     "type": "rss", "category": "news"},
    {"name": "TechRepublic",
     "url": "https://www.techrepublic.com/rssfeeds/topic/security/",
     "type": "rss", "category": "news"},

    # Industry / OT news
    {"name": "Industrial Cyber",
     "url": "https://industrialcyber.co/feed/",
     "type": "rss", "category": "industry"},
    {"name": "SecurityWeek ICS/OT",
     "url": "https://www.securityweek.com/category/ics-ot/feed/",
     "type": "rss", "category": "industry"},
    # Dragos has no working feed (checked 2026-10-18), in order:
    #   /feed/           -> 404
    #   /blog/feed/      -> 404
    #   /rss.xml         -> 404
    #   /blog/rss.xml    -> 200 but serves the HTML blog page, not XML
    #   /blog.rss        -> 200, application/xml, zero-byte body
    # The last is the URL the site declares in its own
    # <link rel="alternate" type="application/rss+xml"> tag, so this is broken
    # on their side. Industrial Cyber and SecurityWeek ICS/OT cover the same
    # category meanwhile. Re-test /blog.rss occasionally and uncomment.
    # {"name": "Dragos Blog",
    #  "url": "https://www.dragos.com/blog.rss",
    #  "type": "rss", "category": "industry"},
    # Every new CVE (~500 a day), filtered hard by the cve rules.
    # The API takes a date window, so the URL is built per run from window_hours.
    # Keep it LAST: a CVE already in the database from KEV or a PSIRT is marked
    # dup, which only works if those feeds ran first. No API key: 5 requests/30 s.
    {"name": "NVD",
     "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
     "type": "nvd", "category": "cve", "window_hours": 6},
]


# ---------------------------------------------------------------------------
# POST STYLE - one emoji per source, shown either side of red titles and before
# each story in batches.
# ---------------------------------------------------------------------------

DEFAULT_EMOJI = "\U0001F4F0"  # newspaper

FEED_EMOJI = {
    "CISA KEV": "\U0001F3AF",            # direct hit
    "NVD": "‼️",                          # double exclamation (cib CVE channel)
    "CISA Advisories": "\U0001F3DB️",     # classical building
    "CISA ICS Advisories": "\U0001F3ED", # factory
    "Microsoft MSRC": "\U0001FA9F",      # window
    "Fortinet PSIRT": "\U0001F9F1",      # brick
    "Palo Alto PSIRT": "\U0001F525",     # fire
    "Cisco PSIRT": "\U0001F309",         # bridge
    "Siemens ProductCERT": "⚡",
    "ConnectWise Status": "\U0001F4E1",  # satellite dish
    "Azure Status": "☁️",
    "BleepingComputer": "\U0001F4BB",    # laptop
    "The Hacker News": "\U0001F58B️",     # pen (cib)
    "SecurityWeek": "\U0001F4C5",        # calendar
    "The Record": "\U0001F399️",          # microphone
    "Krebs on Security": "♟️",            # chess pawn (cib)
    "Dark Reading": "\U0001F575️‍♂️",       # detective (cib)
    "Infosecurity Magazine": "\U0001F4D4",  # notebook (cib)
    "ESET WeLiveSecurity": "\U0001F680",    # rocket (cib)
    "UK NCSC": "\U0001F6A8",                # siren (cib)
    "ITPro": "\U0001F4E2",                  # loudspeaker (cib)
    "TechRepublic": "\U0001F9BF",           # leg (cib)
    "Industrial Cyber": "⚙️",
    "SecurityWeek ICS/OT": "\U0001F527",    # wrench
}


# ---------------------------------------------------------------------------
# LOCAL OVERRIDES - local_sources.py (git-ignored) replaces any setting above.
# Then the derived lists are computed, unless local_sources.py set them itself.
# ---------------------------------------------------------------------------

try:
    import local_sources as _local
except ImportError:
    _local = None
if _local is not None:
    globals().update({k: v for k, v in vars(_local).items() if k.isupper()})

if _local is None or not hasattr(_local, "OT_PRIORITY"):
    OT_PRIORITY = list(OT_VENDORS)
if _local is None or not hasattr(_local, "WATCH_EXPLOITED"):
    WATCH_EXPLOITED = [v for v in BIG_VENDORS if v not in STACK]
