#!/bin/sh
# Start the demo lab (compose project "demolab" only). Seeds the demo estate on a cold start.
set -eu
cd "$(dirname "$0")"
python3 seed_state.py
docker compose -p demolab up -d --build
docker compose -p demolab ps
