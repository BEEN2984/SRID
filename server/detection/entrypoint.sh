#!/usr/bin/env bash
set -e
mkdir -p /var/log/remote
rsyslogd
exec python3 /app/main.py
