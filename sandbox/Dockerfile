# Default image of "safepen.py bench --sandbox": Python and common network tools. A
# requirements.txt in the current directory is installed on top of it automatically.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap curl wget dnsutils netcat-openbsd iputils-ping ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests httpx pyyaml
