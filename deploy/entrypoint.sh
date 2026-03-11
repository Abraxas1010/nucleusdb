#!/usr/bin/env bash
set -euo pipefail

DB="${NUCLEUSDB_DISCORD_DB_PATH:-/data/discord_records.ndb}"

# Initialize database on first run
if [ ! -f "$DB" ]; then
  nucleusdb create --db "$DB" --backend merkle
  printf 'SET MODE APPEND_ONLY;\n' | nucleusdb sql --db "$DB"
fi

# Track background PIDs so we can kill everything if any process dies
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait
}
trap cleanup EXIT INT TERM

nucleusdb-server "${NUCLEUSDB_API_ADDR:-0.0.0.0:8088}" production &
PIDS+=($!)

nucleusdb mcp --transport http \
  --host "${NUCLEUSDB_MCP_HOST:-0.0.0.0}" \
  --port "${NUCLEUSDB_MCP_PORT:-3000}" \
  --db "$DB" &
PIDS+=($!)

nucleusdb dashboard --port "${NUCLEUSDB_DASHBOARD_PORT:-3100}" --no-open &
PIDS+=($!)

nucleusdb-discord &
PIDS+=($!)

# Wait for ANY process to exit — if one dies, kill all and let Docker restart us
wait -n
echo "nucleusdb: a subprocess exited, shutting down for restart" >&2
exit 1
