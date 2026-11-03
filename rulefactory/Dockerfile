# TechDetechtives rule factory: the exposure check that runs on your network.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
# Build context is the repository root (see rulefactory/docker-compose.yml).
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="TechDetechtives rule factory (exposure check)" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TD_RF_CACHE=/state/cache TD_RF_STATE=/state/rulefactory-exposure.json
WORKDIR /opt/techdetechtives

RUN pip install --no-cache-dir PyYAML==6.0.2 \
    && useradd --create-home --uid 1000 rulefactory \
    && mkdir -p /state && chown rulefactory:rulefactory /state

# Only what the exposure check reads: its own code, the forwarder's helpers
# and the rule files, to say which CVEs already have TechDetechtives rules.
COPY rulefactory /opt/techdetechtives/rulefactory
COPY ticketing/forwarder/td_forwarder.py /opt/techdetechtives/ticketing/forwarder/td_forwarder.py
COPY platform/detections /opt/techdetechtives/platform/detections

USER rulefactory
VOLUME ["/state"]
ENTRYPOINT ["python", "-m", "rulefactory"]
CMD ["exposure", "--days", "60", "--every", "6"]
