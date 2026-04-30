#!/usr/bin/env bash
# run.sh — Start the Bug Bounty Recon Assistant
set -e

cd "$(dirname "$0")"

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python3 not found"; exit 1
fi

# Create venv if missing
if [ ! -d ".venv" ]; then
  echo "📦 Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

# Install deps
echo "📦 Installing dependencies..."
pip install -q -r requirements.txt

# Check .env
if [ ! -f ".env" ]; then
  echo "⚠️  .env not found — copying from .env.example"
  cp .env.example .env 2>/dev/null || true
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Bug Bounty Recon Assistant                ║"
echo "║   http://localhost:8000                     ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

python3 main.py
