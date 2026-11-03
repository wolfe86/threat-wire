#!/bin/bash
# Copy the Threat Wire database from the machine that runs the feed, for a
# weekly report written somewhere else (e.g. where Claude Code is installed).
#
#   examples/pull_db.sh HOST [REMOTE_DB] [LOCAL_DB]
#   examples/pull_db.sh feedbox ~/threat-wire/data/threatwire.db data/threatwire-remote.db
#
# Then: python3 threatwire_weekly.py --db data/threatwire-remote.db
# sqlite's backup API makes the copy on the remote side, so a pass writing at
# the same moment can't hand you a torn file.
set -euo pipefail
HOST=${1:?usage: pull_db.sh HOST [REMOTE_DB] [LOCAL_DB]}
REMOTE_DB=${2:-threat-wire/data/threatwire.db}
LOCAL_DB=${3:-data/threatwire-remote.db}
mkdir -p "$(dirname "$LOCAL_DB")"
ssh -o BatchMode=yes "$HOST" \
  "python3 -c 'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(\"/tmp/threatwire-pull.db\"); s.backup(d); d.close()' $REMOTE_DB"
scp -q -o BatchMode=yes "$HOST:/tmp/threatwire-pull.db" "$LOCAL_DB"
echo "pulled $(du -h "$LOCAL_DB" | cut -f1) to $LOCAL_DB"
