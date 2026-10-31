#!/usr/bin/env python3
"""Write an estate into ./state so the lab can start before the worker ever runs.

    python3 seed_state.py            # the demo estate, only if ./state holds none yet
    python3 seed_state.py seed-7 --force

Stdlib only (Python 3.10+). The worker owns ./state once it runs; this is for a cold start.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from estates import estate, read_state, write_state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("estate", nargs="?", default="demo")
    parser.add_argument("--state", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "state"))
    parser.add_argument("--force", action="store_true", help="overwrite an existing state")
    args = parser.parse_args()
    os.makedirs(args.state, exist_ok=True)
    current = read_state(args.state)
    if current is not None and not args.force:
        print(f"state already holds estate {current[0].name!r} (version {current[1]}); left as is")
        return
    version = current[1] + 1 if current else 1
    serial = max((current[0].serial + 1) if current else 1, int(time.time()))
    from dataclasses import replace  # noqa: PLC0415

    write_state(args.state, replace(estate(args.estate), serial=serial), version)
    print(f"wrote estate {args.estate!r} into {args.state} (version {version}, serial {serial})")


if __name__ == "__main__":
    main()
