# SPDX-License-Identifier: GPL-3.0-only
#
# TechDetechtives analytics workbench image.
# Modified work derived from the HELK Jupyter image
# (https://github.com/Cyb3rWard0g/HELK, docker/helk-jupyter/Dockerfile),
# Copyright Roberto Rodriguez (@Cyb3rWard0g), GPL-3.0.
# Modified by TechDetechtives, 2026: rebuilt on a current Python base image,
# PostgreSQL/Hive metastore removed, Spark runs in local mode, and the image
# connects to the platform's Elasticsearch instead of a bundled one.

FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="TechDetechtives analytics workbench" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.description="Jupyter and Spark hunting workbench. Derived from HELK."

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/techdetechtives \
    MPLCONFIGDIR=/tmp/matplotlib

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless tini procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN useradd --create-home --uid 1000 --shell /bin/bash hunter \
    && mkdir -p /home/hunter/work/notebooks /home/hunter/work/data /opt/techdetechtives \
    && chown -R hunter:hunter /home/hunter/work

COPY td_hunt /opt/techdetechtives/td_hunt
COPY entrypoint.sh /usr/local/bin/td-entrypoint
RUN chmod 0755 /usr/local/bin/td-entrypoint

USER hunter
WORKDIR /home/hunter/work
EXPOSE 8888

ENTRYPOINT ["tini", "--", "td-entrypoint"]
