#!/usr/bin/env bash
# COMMANDsentry — install ASM tool stack
# ──────────────────────────────────────
# Installs all 9 tools needed by asm-discover.sh.
# Idempotent — safe to re-run.
#
# Usage:
#   ./install-tools.sh                    # auto-detect platform
#   ./install-tools.sh --platform ubuntu  # force Ubuntu (GH Actions runner)
#   ./install-tools.sh --platform mac     # force macOS (local dev)
#
# Tools installed:
#   subfinder, dnsx, httpx, naabu, fingerprintx (Go)
#   wafw00f                                      (pip)
#   testssl.sh                                   (git clone)
#   nuclei + exposure templates                  (Go + nuclei -ut)
#   whois                                        (system pkg)
#   jq, yq                                       (system pkg + binary)

set -uo pipefail   # NOT -e — we want to continue past failed installs

PLATFORM="${PLATFORM:-auto}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.commandsentry/tools}"
GO_BIN="$(go env GOPATH 2>/dev/null)/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ "$PLATFORM" == "auto" ]]; then
  if [[ "$(uname)" == "Darwin" ]]; then PLATFORM=mac; else PLATFORM=ubuntu; fi
fi

echo "═══ COMMANDsentry tool installer ═══"
echo "Platform: $PLATFORM"
echo "Install dir: $INSTALL_DIR"
echo ""

mkdir -p "$INSTALL_DIR"

# ─── System packages ─────────────────────────────────────────────
echo "[1/5] System packages..."
if [[ "$PLATFORM" == "ubuntu" ]]; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq whois jq python3-pip git ca-certificates curl dnsutils
  # dnsutils gives us `dig` for DNS-derived subdomain enumeration
  # yq via binary (apt version is too old)
  if ! command -v yq &>/dev/null; then
    sudo curl -sLo /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
    sudo chmod +x /usr/local/bin/yq
  fi
elif [[ "$PLATFORM" == "mac" ]]; then
  command -v brew &>/dev/null || { echo "Install Homebrew first"; exit 1; }
  brew install whois jq yq python git --quiet 2>/dev/null || true
  # macOS ships with dig in BIND utilities (built-in) — no install needed
fi

# ─── Go (required for ProjectDiscovery tools) ────────────────────
echo "[2/5] Go runtime..."
if ! command -v go &>/dev/null; then
  if [[ "$PLATFORM" == "ubuntu" ]]; then
    sudo apt-get install -y -qq golang-go
  else
    brew install go --quiet 2>/dev/null || true
  fi
fi

# ensure GOPATH/bin on PATH for this script
export PATH="$GO_BIN:$PATH"

# ─── Go-based scanners ───────────────────────────────────────────
echo "[3/5] ProjectDiscovery tools (subfinder, dnsx, httpx, naabu, nuclei, fingerprintx)..."

go_install() {
  local tool="$1" pkg="$2"
  if command -v "$tool" &>/dev/null; then
    echo "  ✓ $tool already installed"
  else
    echo "  installing $tool..."
    go install -v "$pkg" 2>&1 | tail -1
  fi
}

go_install subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
go_install nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install fingerprintx "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest"

# Symlink to /usr/local/bin so non-interactive workflows can find them
if [[ "$PLATFORM" == "ubuntu" ]]; then
  for tool in subfinder dnsx httpx naabu nuclei fingerprintx; do
    [[ -f "$GO_BIN/$tool" ]] && sudo ln -sf "$GO_BIN/$tool" "/usr/local/bin/$tool"
  done
fi

# Update nuclei templates (exposure-only set will be filtered at runtime)
echo "  updating nuclei templates..."
nuclei -update-templates -silent 2>&1 | tail -1 || true

# ─── Python tools ────────────────────────────────────────────────
echo "[4/6] Python tools (wafw00f)..."
if ! command -v wafw00f &>/dev/null; then
  if [[ "$PLATFORM" == "ubuntu" ]]; then
    pip3 install --quiet --break-system-packages wafw00f 2>/dev/null || pip3 install --quiet wafw00f
  else
    pip3 install --quiet --break-system-packages wafw00f
  fi
fi

# ─── Medium-tier active scan tools (nikto + ffuf) ────────────────
# Added 2026-05-30 after scan #35 surfaced 'command not found' for
# both. Required by run_medium.py.
echo "[5/6] Medium-tier active scan tools (nikto, ffuf)..."

# ffuf — Go-installable
go_install ffuf "github.com/ffuf/ffuf/v2@latest"
if [[ "$PLATFORM" == "ubuntu" ]] && [[ -f "$GO_BIN/ffuf" ]]; then
  sudo ln -sf "$GO_BIN/ffuf" /usr/local/bin/ffuf
fi

# nikto — system package on Ubuntu, brew on Mac
if ! command -v nikto &>/dev/null; then
  if [[ "$PLATFORM" == "ubuntu" ]]; then
    sudo apt-get install -y -qq nikto
  elif [[ "$PLATFORM" == "mac" ]]; then
    brew install nikto --quiet 2>/dev/null || true
  fi
fi

# ─── testssl.sh ──────────────────────────────────────────────────
echo "[6/6] testssl.sh..."
TESTSSL_DIR="$INSTALL_DIR/testssl.sh"
if [[ ! -d "$TESTSSL_DIR" ]]; then
  git clone --quiet --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR"
fi
# Symlink for convenience
if [[ "$PLATFORM" == "ubuntu" ]]; then
  sudo ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh
fi

# ─── Verification ────────────────────────────────────────────────
echo ""
echo "═══ Verification ═══"
for tool in subfinder dnsx httpx naabu fingerprintx nuclei wafw00f nikto ffuf whois jq yq; do
  if command -v "$tool" &>/dev/null; then
    printf "  ✓ %-15s %s\n" "$tool" "$(command -v $tool)"
  else
    printf "  ✗ %-15s NOT FOUND\n" "$tool"
  fi
done
[[ -x "$TESTSSL_DIR/testssl.sh" ]] && echo "  ✓ testssl.sh     $TESTSSL_DIR/testssl.sh" || echo "  ✗ testssl.sh     NOT FOUND"

echo ""
echo "Install complete. Run scanner/asm-discover.sh to start."
