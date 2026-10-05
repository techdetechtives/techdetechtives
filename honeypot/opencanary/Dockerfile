# TechDetechtives honeypot image: OpenCanary, unmodified, at a pinned commit.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# OpenCanary is a separate project by Thinkst Applied Research (BSD 3-Clause):
# https://github.com/thinkst/opencanary. This file only installs it. The commit
# comes from upstream.lock and is passed in by honeypot/setup-honeypot.sh.
#
# The full Python image is used on purpose: it carries the compiler and headers
# that some of OpenCanary's pinned dependencies need to install.
FROM python:3.12-bookworm

ARG OPENCANARY_COMMIT
RUN test -n "$OPENCANARY_COMMIT" || (echo "build with --build-arg OPENCANARY_COMMIT=<commit>" >&2; exit 1)

LABEL org.opencontainers.image.title="OpenCanary for TechDetechtives" \
      org.opencontainers.image.source="https://github.com/thinkst/opencanary" \
      org.opencontainers.image.licenses="BSD-3-Clause"

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install "https://github.com/thinkst/opencanary/archive/${OPENCANARY_COMMIT}.tar.gz" \
    && mkdir -p /var/log/opencanary /etc/opencanaryd \
    && opencanaryd --version

# OpenCanary starts as root to open the decoy ports, then gives up root for the
# unprivileged "nobody" account. This is the start command its own project documents.
ENTRYPOINT ["opencanaryd"]
CMD ["--dev", "--uid=nobody", "--gid=nogroup"]
