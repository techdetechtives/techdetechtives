# TechDetechtives network inventory image.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
# Build context is the repository root (see network/docker-compose.yml).
# Standard library only: nothing is installed from the Python package index.
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="TechDetechtives network inventory" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/techdetechtives

COPY ticketing/forwarder/td_forwarder.py /opt/techdetechtives/td_forwarder.py
COPY network/app/td_net /opt/techdetechtives/td_net

# Runs as the account that first installed it (see docker-compose.yml), so it can
# read that account's TLS key and nothing else. The state folder accepts any account.
RUN mkdir -p /state && chmod 1777 /state
USER 65534:65534
VOLUME ["/state"]
ENTRYPOINT ["python", "-m", "td_net.main"]
