#!/usr/bin/env bash
# install_tools.sh — Install all required recon tools
set -e

echo "🔧 Installing Bug Bounty Recon Tools"
echo "======================================"

# Check Go
if ! command -v go &>/dev/null; then
  echo "❌ Go not found. Please install Go first: https://go.dev/dl/"
  exit 1
fi

GO_BIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GO_BIN"

install_go_tool() {
  local name="$1"; local pkg="$2"
  if command -v "$name" &>/dev/null; then
    echo "✓ $name already installed"
  else
    echo "📦 Installing $name..."
    go install "$pkg" 2>/dev/null && echo "✓ $name installed" || echo "⚠ Failed: $name"
  fi
}

install_go_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool gau          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool waybackurls  "github.com/tomnomnom/waybackurls@latest"

# Amass (separate due to size)
if ! command -v amass &>/dev/null; then
  echo "📦 Installing amass..."
  go install "github.com/owasp-amass/amass/v4/...@master" 2>/dev/null \
    && echo "✓ amass installed" || echo "⚠ amass failed — install manually from https://github.com/owasp-amass/amass"
else
  echo "✓ amass already installed"
fi

echo ""
echo "✅ Done! Make sure $GO_BIN is in your PATH:"
echo "   export PATH=\$PATH:\$(go env GOPATH)/bin"
echo ""
echo "Add this to your ~/.bashrc or ~/.zshrc to persist it."
