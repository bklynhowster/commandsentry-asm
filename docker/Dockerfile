# syntax=docker/dockerfile:1.7
#
# COMMANDsentry scanner image — bakes the full Phase 4a toolchain
# (Light + Medium tier) plus wireguard-go for VPN egress into a single
# reproducible image. Built + published to GHCR by
# .github/workflows/build-scanner-image.yml.
#
# Why: scans #43-65 (2026-05-30 marathon) walked us through every way
# Ubuntu hosted runners can hang on apt/dpkg/systemd/modprobe. Burning
# 5+ min of install time every scan, with no reproducibility, on a
# platform actively hostile to runtime package work, was the wrong
# architecture. This image freezes the stack we've proven works.
#
# Required runtime options when used via GH Actions `container:` block:
#   options: --cap-add=NET_ADMIN --device=/dev/net/tun
# (wireguard-go needs both to create + own a TUN device)
#
# Tag scheme:
#   ghcr.io/bklynhowster/commandsentry-scanner:latest
#   ghcr.io/bklynhowster/commandsentry-scanner:YYYYMMDD-<sha>
# Pin to a SHA tag in production; use :latest for dev.

# ════════════════════════════════════════════════════════════════════
# Stage 1 — Builder: compile Go-based scanners + wireguard-go
# ════════════════════════════════════════════════════════════════════
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      golang-go git ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV PATH=/root/go/bin:/usr/local/go/bin:$PATH
ENV CGO_ENABLED=0

# ─── wireguard-go (userspace WG impl — the M7 keystone) ────────────
# This is what makes the whole VPN egress work on hosted runners
# without the kernel-module-load → systemd-modules-load.service hang.
RUN go install golang.zx2c4.com/wireguard@latest \
 && mv /root/go/bin/wireguard /usr/local/bin/wireguard-go

# ─── ProjectDiscovery toolkit + ffuf ───────────────────────────────
# These are the active scanners run by run_light.py + run_medium.py.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest \
 && go install github.com/ffuf/ffuf/v2@latest

# ─── Extract `wg` userspace tool from wireguard-tools .deb ─────────
# We need the `wg` CLI (for setconf/show/set fwmark) but NOT wg-quick
# (we've replaced it with scripts/scanner/wg_up_userspace.sh).
# dpkg-deb -x avoids the maintainer scripts that hang on hosted runners.
RUN wget -q -O /tmp/wg-tools.deb \
      "http://archive.ubuntu.com/ubuntu/pool/main/w/wireguard/wireguard-tools_1.0.20210914-1ubuntu4_amd64.deb" \
 && dpkg-deb -x /tmp/wg-tools.deb /tmp/wg-tools \
 && cp /tmp/wg-tools/usr/bin/wg /usr/local/bin/wg \
 && rm -rf /tmp/wg-tools.deb /tmp/wg-tools

# ════════════════════════════════════════════════════════════════════
# Stage 2 — Runtime: minimal base + scan tooling + Python deps
# ════════════════════════════════════════════════════════════════════
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Runtime system packages — everything the scan steps need at runtime,
# but no Go toolchain (binaries are pre-built in the builder stage).
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      # Network + routing — required for wireguard-go tunnel setup
      iproute2 iptables iputils-ping \
      # Privilege management
      sudo \
      # Scanner runtime deps
      python3 python3-pip python3-venv \
      # `python` → `python3` symlink; scanner.yml + scripts call `python`
      # (hosted runners install this by default; container images don't)
      python-is-python3 \
      # Active scan utilities (system pkgs).
      # NOTE: nikto is NOT installed via apt — Ubuntu 24.04 ships nikto
      # 2.1.5 from 2014 which (a) rejects modern flags like -useragent
      # (verified scan_run e1825c68, 2026-06-08), making UA spoofing
      # impossible and producing instant "Nikto/2.x" WAF bans on owned
      # WAF-fronted assets, and (b) has Getopt::Long prefix-matching
      # quirks. Upstream sullo/nikto is installed in a dedicated step
      # below — pure Perl, no compile needed. Per Task #6 (REQUIRED
      # Stage-3 guardrail). Keep `perl` because nikto IS Perl.
      whois jq dnsutils perl libnet-ssleay-perl \
      # PostgreSQL client — scanner.yml uses psql in queue/poll/cleanup
      # steps (8 invocations total) to talk to Supabase
      postgresql-client \
      # Misc system
      ca-certificates curl wget gawk \
      # testssl.sh needs git for clone (at image build) and bsdmainutils
      git bsdmainutils \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean

# ─── Python tools ──────────────────────────────────────────────────
# wafw00f for WAF fingerprinting, psycopg for Supabase writes,
# requests for everything HTTP. --break-system-packages because
# Ubuntu 24.04 PEP 668-protects /usr/lib/python3.
RUN pip3 install --break-system-packages --no-cache-dir \
       wafw00f \
       "psycopg[binary]" \
       requests

# ─── yq binary (the apt version is too old for our usage) ──────────
RUN wget -q -O /usr/local/bin/yq \
       https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
 && chmod +x /usr/local/bin/yq

# ─── GitHub CLI (`gh`) — used by scanner.yml `gh release download` ─
# Static binary from cli/cli releases. Not in noble's default apt repo.
RUN wget -q -O /tmp/gh.tar.gz \
       https://github.com/cli/cli/releases/download/v2.62.0/gh_2.62.0_linux_amd64.tar.gz \
 && tar -xzf /tmp/gh.tar.gz -C /tmp \
 && install -m 0755 /tmp/gh_2.62.0_linux_amd64/bin/gh /usr/local/bin/gh \
 && rm -rf /tmp/gh.tar.gz /tmp/gh_2.62.0_linux_amd64

# ─── testssl.sh (cloned at build time, pinned to current HEAD) ─────
RUN git clone --depth 1 --quiet \
       https://github.com/drwetter/testssl.sh.git \
       /opt/testssl.sh \
 && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ─── nikto (UPSTREAM — sullo/nikto from GitHub) ────────────────────
# Replaces apt's nikto 2.1.5 (frozen 2014). Per Task #6 (REQUIRED
# Stage-3 guardrail). Upstream provides:
#   - Modern argument semantics — no Getopt::Long prefix-matching
#     ambiguity ('-h' resolves cleanly to '-host')
#   - -useragent flag works (Ubuntu apt 2.1.5 rejected it with
#     "Unknown option: useragent" — verified scan_run e1825c68)
#   - Modern check database (apt's plugins are 10+ years stale)
#
# Pure Perl, no compile. nikto.pl + program/ + plugins/ + databases/.
# Symlink + wrapper so /usr/local/bin/nikto invokes the real script.
RUN git clone --depth 1 --quiet \
       https://github.com/sullo/nikto.git \
       /opt/nikto \
 && printf '#!/bin/sh\nexec /usr/bin/perl /opt/nikto/program/nikto.pl "$@"\n' \
       > /usr/local/bin/nikto \
 && chmod +x /usr/local/bin/nikto \
 && /usr/local/bin/nikto -Version 2>&1 | head -3

# ─── Copy built binaries from the builder stage ────────────────────
COPY --from=builder /usr/local/bin/wireguard-go  /usr/local/bin/
COPY --from=builder /usr/local/bin/wg            /usr/local/bin/
COPY --from=builder /root/go/bin/subfinder       /usr/local/bin/
COPY --from=builder /root/go/bin/dnsx            /usr/local/bin/
COPY --from=builder /root/go/bin/httpx           /usr/local/bin/
COPY --from=builder /root/go/bin/naabu           /usr/local/bin/
COPY --from=builder /root/go/bin/nuclei          /usr/local/bin/
COPY --from=builder /root/go/bin/katana          /usr/local/bin/
COPY --from=builder /root/go/bin/fingerprintx    /usr/local/bin/
COPY --from=builder /root/go/bin/ffuf            /usr/local/bin/

# ─── Pre-pull nuclei templates so first scan doesn't pay the cost ──
RUN nuclei -update-templates -silent 2>/dev/null || true

# ─── Sanity check — fail the build if any expected tool is missing ─
RUN set -eux; \
    for t in wireguard-go wg \
             subfinder dnsx httpx naabu nuclei katana fingerprintx \
             ffuf nikto wafw00f testssl.sh \
             whois jq yq python python3 sudo ip iptables \
             psql gh; do \
      command -v "$t" >/dev/null 2>&1 \
        || { echo "MISSING: $t"; exit 1; }; \
    done; \
    echo "all tools present"

# ─── Image metadata ────────────────────────────────────────────────
LABEL org.opencontainers.image.source="https://github.com/bklynhowster/commandsentry-asm"
LABEL org.opencontainers.image.description="COMMANDsentry scanner — wireguard-go + Phase 4a toolchain baked in"
LABEL org.opencontainers.image.licenses="Proprietary"

WORKDIR /work
