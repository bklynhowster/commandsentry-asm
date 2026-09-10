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

# ════════════════════════════════════════════════════════════════════
# TOOLCHAIN PIN — every version below is GROUND TRUTH, not a guess
# ════════════════════════════════════════════════════════════════════
# Captured 2026-09-07 by `.github/workflows/toolchain-inventory.yml`
# (run #4) from the Go build-info record embedded in each binary in the
# then-running :latest image. Guarded by scripts/scanner/test_toolchain_pinned.py.
#
# WHY PINNED. These were all `@latest`. The sharpest consequence is not
# "builds aren't reproducible" — it is that a finding can DISAPPEAR
# because a tool or template changed upstream, and the finding lifecycle
# records that as REMEDIATION. No gate catches it, because the scan ran
# perfectly and every phase reported ok. Secondary: every coverage number
# in specs 227-231 assumes stable tool behaviour, so a baseline built on a
# floating toolchain is not a baseline.
#
# ⚠ PIN TO WHAT IS INSTALLED, NOT TO NEWEST. Every measurement in specs
# 227-231 came from this exact build. Bumping forward while pinning
# silently invalidates the baseline those specs rest on. Two tools had
# ALREADY drifted when this pin was written (httpx v1.10.0 installed vs
# v1.11.0 released 2026-08-31; dnsx v1.3.0 vs v1.3.1 same day) — they are
# pinned to the INSTALLED version deliberately. Bump on purpose, re-run
# the inventory, and re-measure. Never bump as a side effect.
#
# ⚠ DO NOT TRUST `<tool> -version` WHEN BUMPING. dnsx's CLI reports
# "1.2.3" while its own build record says v1.3.0 — the CLI string is a
# source constant upstream forgot to bump, stale by two releases. Read
# the embedded record (the inventory workflow does this for you).
# wireguard is worse: the binary prints "v0.0.20250522" but the module has
# no tags at all and pins as a v0.0.0-<date>-<hash> pseudo-version.
# Neither number is derivable from the other.

# ─── wireguard-go (userspace WG impl — the M7 keystone) ────────────
# This is what makes the whole VPN egress work on hosted runners
# without the kernel-module-load → systemd-modules-load.service hang.
RUN go install golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446 \
 && mv /root/go/bin/wireguard /usr/local/bin/wireguard-go

# ─── ProjectDiscovery toolkit + ffuf ───────────────────────────────
# These are the active scanners run by run_light.py + run_medium.py.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0 \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 \
 && go install github.com/projectdiscovery/katana/cmd/katana@v1.7.0 \
 && go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1.1.19 \
 && go install github.com/ffuf/ffuf/v2@v2.2.1 \
 && go install github.com/lc/gau/v2/cmd/gau@v2.2.4

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
      #
      # 2026-06-10: libjson-perl + libxml-writer-perl added after scan_run
      # 47bbdbff proved upstream nikto dies at startup without them
      # ("ERROR: Required module not found: JSON / XML::Writer"). apt's
      # nikto package pulled these as dependencies automatically; the
      # git-clone install does not. The -Version smoke check below passes
      # WITHOUT them (it doesn't load reporting plugins), which is how
      # image #5 shipped broken — hence the module-load smoke check now
      # baked into the nikto install step.
      whois jq dnsutils perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
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
 && /usr/local/bin/nikto -Version 2>&1 | head -3 \
 # Module-load smoke check (2026-06-10, scan_run 47bbdbff): -Version alone
 # passes even when nikto's required Perl modules are missing, because it
 # doesn't load the reporting plugins. Image #5 shipped with nikto unable
 # to start ("Required module not found: JSON / XML::Writer") and the
 # build was green. Fail the BUILD if the modules nikto needs at startup
 # can't load.
 && perl -MJSON -MXML::Writer -MNet::SSLeay -e 'print "nikto perl deps OK\n"' \
 # Belt-and-suspenders: a real (host-less) nikto invocation must NOT emit
 # the module-not-found startup error.
 && ! (/usr/local/bin/nikto -list-plugins 2>&1 | grep -q "Required module not found")

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
COPY --from=builder /root/go/bin/gau             /usr/local/bin/

# ─── Pre-pull nuclei templates so first scan doesn't pay the cost ──
#
# TEMPLATE_DRIFT — DELIBERATE, ACCEPTED, AND INSTRUMENTED (2026-09-07)
#
# Pinning the nuclei BINARY above does not pin what it scans FOR. This
# line pulls the newest template set at build time, so templates float
# even with the binary frozen — and this is the layer that actually
# produces the false-remediation path: a template renamed or dropped
# upstream makes a finding vanish, and the lifecycle records that as
# REMEDIATION. It directly undermines spec 227's premise that a finding's
# absence means it was fixed.
#
# THE DECISION: keep the drift, make it detectable. Template freshness is
# how new CVEs get caught at all — freezing the set would trade a real,
# ongoing coverage loss for reproducibility, which is a bad bargain for an
# external ASM scanner whose whole job is finding what's new. So the set
# stays live and the hole is closed from the other side: record the
# template set per scan run so a vanished finding can be DIFFED against a
# template change instead of silently reading as a fix.
#
# ⛔⛔ THIS PRE-PULL IS DEAD WEIGHT — CORRECTED 2026-09-10, DO NOT DELETE THE
# LINE WITHOUT READING THIS.
#
# HOME is /root at BUILD time and /github/home at RUN time. nuclei resolves its
# template directory from $HOME, so this line writes /root/nuclei-templates and
# NOTHING EVER READS IT. Measured in the production image
# (toolchain-inventory run #4):
#
#     -tl against /root/nuclei-templates  : 13212
#     -tl against $HOME/nuclei-templates  : 13203
#     -tl DEFAULT, no -t                  : 13203   <- matches $HOME
#     /root  mtime 2026-09-07 (this build) | $HOME mtime = ~21s into the RUN
#
# ⛔ EVERY SCAN DOWNLOADS ITS OWN CORPUS AT RUNTIME. Consequences:
#   * Image rebuild dates, tags and this file's history say NOTHING about what
#     a scan scans with. Do not reason about template coverage from them.
#   * The `|| true` below cannot cause a silent scan-time coverage loss,
#     because scans do not use what it fetches. The fail-silent risk MOVED to
#     the runtime fetch and is UNPROBED there.
#   * The template-drift decision recorded below still stands, but its
#     mechanism is the runtime fetch, not this line.
#
# ⚠ CORRECTION: an earlier version of this comment said "there is nothing to
# pin by version — `nuclei -templates-version` prints an EMPTY version string."
# That was an artifact of CALL ORDER, not a missing feature. The flag was
# invoked before any nuclei run had created the runtime directory. After a
# single `nuclei -tl`, $HOME/.config/nuclei/.templates-config.json reports
# "nuclei-templates-version":"v10.4.8". A real corpus version DOES exist — it
# is simply unreadable until nuclei has run once. #31 stamps it from there.
#
# ⚠ Also corrected: "13,619 templates in /root/nuclei-templates" is a count of
# a directory no scan reads.
#
# KEEPING THE LINE ANYWAY: it is cheap, and removing it would be a behaviour
# change in a build whose relationship to scan-time behaviour is now understood
# but not yet re-verified end to end. Fixing HOME, or pointing the fetch at the
# runtime path, is a deliberate change to make on its own — not a side effect
# of a comment correction.
RUN nuclei -update-templates -silent 2>/dev/null || true

# ─── Sanity check — fail the build if any expected tool is missing ─
RUN set -eux; \
    for t in wireguard-go wg \
             subfinder dnsx httpx naabu nuclei katana fingerprintx \
             ffuf gau nikto wafw00f testssl.sh \
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
