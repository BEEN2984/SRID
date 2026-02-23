#!/usr/bin/env bash
set -e
rm -f /var/run/rsyslogd.pid
mkdir -p /var/log/remote
rsyslogd
tail -f /dev/null