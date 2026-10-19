FROM node:24.22.0-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY assets/agent/package.json assets/agent/package-lock.json /opt/clients/
RUN cd /opt/clients && npm ci --ignore-scripts --no-audit --no-fund \
    && npm cache clean --force

COPY assets/agent/link_clients.py /opt/link_clients.py
RUN python3 /opt/link_clients.py \
    && /opt/agent-bin/codex --version \
    && /opt/agent-bin/claude --version

COPY scripts/agent_worker.py scripts/agent_session.py scripts/tunnel.py /opt/rea-sandbox/
ENV PATH="/opt/agent-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
USER node
WORKDIR /tmp
ENTRYPOINT ["python3", "/opt/rea-sandbox/agent_worker.py"]
