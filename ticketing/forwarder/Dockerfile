# TechDetechtives alert-to-ticket forwarder image.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
# Standard library only: nothing is installed from the Python package index.
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="TechDetechtives ticket forwarder" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 1000 forwarder \
    && mkdir -p /state /opt/techdetechtives \
    && chown forwarder:forwarder /state

COPY td_forwarder.py /opt/techdetechtives/td_forwarder.py

USER forwarder
VOLUME ["/state"]
ENTRYPOINT ["python", "/opt/techdetechtives/td_forwarder.py"]
