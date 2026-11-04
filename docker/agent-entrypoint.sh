#!/bin/sh
# Creates the signed baseline on the very first start (UC-01), then runs the given command.
set -eu
if [ "${1:-watch}" = "watch" ] && [ ! -f /var/lib/fimagent/baseline.json ]; then
  echo "no baseline yet, creating the initial baseline"
  fimagent init -by "container-bootstrap"
fi
exec fimagent "$@"
