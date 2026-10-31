"""Deploy dist/ (the static replay site) to Vercel through its REST API; no CLI needed.

    VERCEL_TOKEN_FILE=<path to token file> uv run python scripts/deploy_vercel.py [--name NAME]

The token is read from the file and sent only to api.vercel.com; it is never printed.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
API = "https://api.vercel.com"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="compliance-officer-replay")
    args = parser.parse_args(argv)
    token = Path(os.environ["VERCEL_TOKEN_FILE"]).read_text(encoding="utf-8").strip()
    headers = {"Authorization": f"Bearer {token}"}
    teams = httpx.get(f"{API}/v2/teams", headers=headers, timeout=30).json().get("teams", [])
    params = {"teamId": teams[0]["id"]} if teams else {}
    files = [
        {
            "file": p.relative_to(DIST).as_posix(),
            "data": base64.b64encode(p.read_bytes()).decode(),
            "encoding": "base64",
        }
        for p in sorted(DIST.rglob("*"))
        if p.is_file()
    ]
    body = {
        "name": args.name,
        "files": files,
        "target": "production",
        "projectSettings": {"framework": None, "buildCommand": None, "outputDirectory": None},
    }
    response = httpx.post(f"{API}/v13/deployments", headers=headers, params=params, json=body, timeout=120)
    data = response.json()
    if response.status_code >= 400:  # noqa: PLR2004
        print("deploy failed:", data.get("error", {}).get("code"), data.get("error", {}).get("message"))
        return 1
    print("deployment:", data.get("url"), "| ready state:", data.get("readyState"))
    print("aliases:", data.get("alias", []))
    return 0


if __name__ == "__main__":
    sys.exit(main())
