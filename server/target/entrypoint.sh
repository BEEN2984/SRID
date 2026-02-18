#!/usr/bin/env bash
set -e
rsyslogd
ssh-keygen -A
exec /usr/sbin/sshd -D
