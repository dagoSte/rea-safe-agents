FROM node:24.22.0-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS base

# Ghidra 12.1.4 is REA 6.7.0's verified native provider; it needs a full JDK 21.
# jadx-headless-mcp 0.7.1 is its audited Android provider (JADX_RELEASE in the
# REA package: tag v0.7.1, commit 5844800a, Apache-2.0); it runs on that JDK.
# Every download is pinned by SHA-256 and fetched only during this reviewed build.
FROM base AS ghidra
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip g++=4:12.2.0-3 make=4.3-4.1 \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip \
    && echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_12.1.4_PUBLIC /opt/ghidra \
    && rm -rf /tmp/ghidra.zip /opt/ghidra/docs
RUN case "$TARGETARCH" in \
        amd64) jdk=x64; sum=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94 ;; \
        arm64) jdk=aarch64; sum=23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223 ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSLo /tmp/jdk.tar.gz "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_${jdk}_linux_hotspot_21.0.12.1_1.tar.gz" \
    && echo "$sum  /tmp/jdk.tar.gz" | sha256sum -c - \
    && mkdir /opt/jdk \
    && tar -xzf /tmp/jdk.tar.gz -C /opt/jdk --strip-components=1 \
    && rm /tmp/jdk.tar.gz
RUN mkdir /opt/jadx \
    && curl -fsSLo /opt/jadx/jadx-headless-mcp-0.7.1-all.jar https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar \
    && echo "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  /opt/jadx/jadx-headless-mcp-0.7.1-all.jar" | sha256sum -c - \
    && chmod 0444 /opt/jadx/jadx-headless-mcp-0.7.1-all.jar
# The release ships x86_64 natives only. On arm64, build the decompiler and the
# GNU demangler from the sources inside the same verified release archive.
RUN if [ "$TARGETARCH" = arm64 ]; then \
        cp -r /opt/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp /tmp/decompile \
        && cd /tmp/decompile && touch *.cc *.hh \
        && make -j"$(nproc)" ghidra_opt ARCH_TYPE= OSDIR=linux_arm_64 \
        && install -D -m 0755 ghidra_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile \
        && demangler=/opt/ghidra/GPL/DemanglerGnu/src/demangler_gnu_v2_41 \
        && gcc -O2 -std=gnu17 -DHAVE_STDLIB_H -DHAVE_STRING_H -I"$demangler/headers" "$demangler"/c/*.c -o /tmp/demangler_gnu_v2_41 \
        && install -D -m 0755 /tmp/demangler_gnu_v2_41 /opt/ghidra/GPL/DemanglerGnu/os/linux_arm_64/demangler_gnu_v2_41 \
        && rm -rf /tmp/decompile /tmp/demangler_gnu_v2_41; \
    fi

FROM base
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghidra /opt/jdk /opt/jdk
COPY --from=ghidra /opt/ghidra /opt/ghidra
COPY --from=ghidra /opt/jadx /opt/jadx
# The launcher refuses runtime environment injection, so the provider settings
# are part of the pinned image. The heaps leave room inside the 2 GiB limit.
ENV JAVA_HOME=/opt/jdk \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRA_HEADLESS_MAXMEM=1G \
    REA_JADX_MCP_JAR=/opt/jadx/jadx-headless-mcp-0.7.1-all.jar \
    REA_JADX_HEAP_MIB=512 \
    REA_JADX_ACTIVE_PROCESSOR_COUNT=2

COPY package.json package-lock.json /opt/rea/
RUN cd /opt/rea \
    && npm ci --ignore-scripts --omit=optional --no-audit --no-fund \
    && ln -s /opt/rea/node_modules/.bin/rea /usr/local/bin/rea \
    && npm cache clean --force

USER node
WORKDIR /input
ENTRYPOINT ["/usr/local/bin/rea"]
CMD ["mcp"]
