# TechDetechtives network inventory and traffic map.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Builds an asset inventory, a traffic map and a baseline of normal
conversations from the connection and protocol records the platform's sensor
writes, and matches published security advisories against it. It only reads
from the platform; it never touches the monitored network itself."""

VERSION = "0.2.0"
