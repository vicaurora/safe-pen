#!/bin/sh
# Entry point of the container started by "safepen.py bench --sandbox": the model's local ports
# answer on this container's loopback, then the agent command runs.
if [ -n "${GT_FORWARD:-}" ]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 /gt-sandbox/forward_local.py "$GT_FORWARD" &
    i=0; while [ ! -f /tmp/.gt-forward-ready ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
  else
    echo "safepen: python3 is missing in this image, the local model ports are not forwarded" >&2
  fi
fi
unset GT_FORWARD
exec sh -c "$1"
