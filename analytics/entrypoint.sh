#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# TechDetechtives analytics workbench entrypoint.
# Part of the TechDetechtives analytics layer (derived from HELK, GPL-3.0).
set -euo pipefail

if [[ -z "${TD_JUPYTER_TOKEN:-}" ]]; then
  echo "TD_JUPYTER_TOKEN is empty. Set it in config/techdetechtives.env (openssl rand -hex 32)." >&2
  echo "Refusing to start Jupyter without an access token." >&2
  exit 1
fi
if [[ ${#TD_JUPYTER_TOKEN} -lt 24 ]]; then
  echo "TD_JUPYTER_TOKEN is shorter than 24 characters. Use: openssl rand -hex 32" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  exec "$@"
fi

exec jupyter lab \
  --ip=0.0.0.0 \
  --port=8888 \
  --no-browser \
  --ServerApp.root_dir=/home/hunter/work \
  --IdentityProvider.token="$TD_JUPYTER_TOKEN"
