#!/usr/bin/env bash
# ============================================================
# run.sh — Start Malicious URL Detection (Backend + Frontend)
# ============================================================
# Backend  → http://localhost:8002  (FastAPI / DistilBERT)
# Frontend → http://localhost:5173  (Vite / React)
#
# Usage:
#   chmod +x run.sh
#   ./run.sh
#
# Stop: Ctrl+C (kills both processes cleanly)
# ============================================================

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT/daa_model"
FRONTEND_DIR="$ROOT/frontend_updated"

# ── Colours ──────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${CYAN}[run.sh]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; }

# ── Cleanup on exit ──────────────────────────────────────────
BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    log "Shutting down..."
    [ -n "$BACKEND_PID"  ] && kill "$BACKEND_PID"  2>/dev/null && ok "Backend stopped."
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && ok "Frontend stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Kill any stale processes on our ports ────────────────────
log "Freeing ports 8002 and 5173/5174..."
lsof -ti:8002 | xargs kill -9 2>/dev/null && warn "Killed stale process on :8002" || true
lsof -ti:5173 | xargs kill -9 2>/dev/null && warn "Killed stale process on :5173" || true
lsof -ti:5174 | xargs kill -9 2>/dev/null && warn "Killed stale process on :5174" || true
sleep 1

# ── Checks ───────────────────────────────────────────────────
if [ ! -d "$BACKEND_DIR" ]; then
    err "daa_model/ not found at $BACKEND_DIR"; exit 1
fi
if [ ! -d "$FRONTEND_DIR" ]; then
    err "frontend_updated/ not found at $FRONTEND_DIR"; exit 1
fi

echo ""
echo -e "${GREEN}=================================================${RESET}"
echo -e "${GREEN}   Malicious URL Detection — Dev Server${RESET}"
echo -e "${GREEN}=================================================${RESET}"
echo ""

# ── Backend ──────────────────────────────────────────────────
log "Starting backend (FastAPI on :8002)..."

# ── Resolve Python / uvicorn from conda env ──────────────────
CONDA_ENV_PATH="/opt/homebrew/Caskroom/miniforge/base/envs/tf-metal"
if [ -f "$CONDA_ENV_PATH/bin/uvicorn" ]; then
    UVICORN="$CONDA_ENV_PATH/bin/uvicorn"
    ok "Using tf-metal conda env: $CONDA_ENV_PATH"
else
    UVICORN="uvicorn"
    warn "tf-metal conda env not found, falling back to system uvicorn."
fi

export KMP_DUPLICATE_LIB_OK=TRUE

cd "$BACKEND_DIR"
$UVICORN app_nn:app --host 0.0.0.0 --port 8002 --log-level warning &
BACKEND_PID=$!
ok "Backend started (PID $BACKEND_PID)"

# Wait for backend to be ready
log "Waiting for backend to be ready..."
for i in $(seq 1 20); do
    if curl -sf http://localhost:8002/health > /dev/null 2>&1; then
        ok "Backend is up → http://localhost:8002"
        break
    fi
    sleep 1
    if [ "$i" -eq 20 ]; then
        err "Backend did not start in 20s. Check logs above."
        cleanup
    fi
done

# ── Frontend ─────────────────────────────────────────────────
log "Starting frontend (Vite on :5173)..."
cd "$FRONTEND_DIR"

# Install node_modules if missing
if [ ! -d "node_modules" ]; then
    warn "node_modules not found — running npm install..."
    npm install --silent
    ok "npm install complete."
fi

npm run dev &
FRONTEND_PID=$!
ok "Frontend started (PID $FRONTEND_PID)"

# ── Ready ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}=================================================${RESET}"
echo -e "${GREEN}   Both servers are running!${RESET}"
echo -e "${GREEN}=================================================${RESET}"
echo -e "  ${CYAN}Frontend${RESET}  → http://localhost:5173"
echo -e "  ${CYAN}Backend${RESET}   → http://localhost:8002"
echo -e "  ${CYAN}API Docs${RESET}  → http://localhost:8002/docs"
echo ""
echo -e "  Press ${YELLOW}Ctrl+C${RESET} to stop both servers."
echo ""

# Keep alive — wait for either process to die unexpectedly
wait $BACKEND_PID  2>/dev/null
wait $FRONTEND_PID 2>/dev/null
