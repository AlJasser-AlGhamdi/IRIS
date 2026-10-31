#!/bin/sh
# Stop and remove the demo lab: its two containers and its own bridge network, nothing else.
# ./state is kept, so the next ./up.sh resumes the same estate.
set -eu
cd "$(dirname "$0")"
docker compose -p demolab down
