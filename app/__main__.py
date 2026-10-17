"""python -m app [--env .env] — uvicorn entry."""
import argparse
import os

import uvicorn

parser = argparse.ArgumentParser()
parser.add_argument("--env", default=".env", help="env file path")
args = parser.parse_args()
os.environ["PROXY_ENV_FILE"] = args.env

from .config import Config  # noqa: E402

cfg = Config.load(args.env)
addr = cfg.addr.lstrip(":") if cfg.addr.startswith(":") else cfg.addr
host, _, port = addr.rpartition(":")
uvicorn.run("app.web:app", host=host or "0.0.0.0", port=int(port or 8081), log_level="info")
