"""Copy this file to local_sources.py and edit it. local_sources.py is
git-ignored, so your watchlist stays out of any commit.

Anything you set here replaces the same setting in threatwire_sources.py.
Lists are replaced whole, so copy the default list and edit it rather than
listing only the additions.
"""

TIMEZONE = "America/New_York"

# The channel posts only inside this window, local time.
POST_START = "06:00"
POST_END = "20:00"

# The vendors and products you run. A hit here plus exploited / zero-day /
# breach / critical is a red alert. Whole words, case-insensitive.
STACK = [
    "microsoft", "m365", "entra", "azure", "intune", "exchange server",
    "palo alto", "pan-os", "globalprotect",
    "citrix", "netscaler",
    "okta",
]

# Only the OT vendors you actually run should page you. Default: all of them.
# OT_PRIORITY = ["rockwell", "allen-bradley", "factorytalk"]
