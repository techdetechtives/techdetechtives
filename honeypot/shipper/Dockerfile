# TechDetechtives honeypot shipper image.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
# Build context is the repository root (see honeypot/docker-compose.yml).
# Standard library only: nothing is installed from the Python package index.
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="TechDetechtives honeypot shipper" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/techdetechtives

RUN useradd --create-home --uid 1000 shipper \
    && mkdir -p /state /opt/techdetechtives \
    && chown shipper:shipper /state

COPY ticketing/forwarder/td_forwarder.py /opt/techdetechtives/td_forwarder.py
COPY honeypot/shipper/td_honeypot.py /opt/techdetechtives/td_honeypot.py

USER shipper
VOLUME ["/state"]
ENTRYPOINT ["python", "/opt/techdetechtives/td_honeypot.py"]
