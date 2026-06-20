#!/bin/bash
# =============================================================================
# SecuriVillage - Ollama AI Container Startup Script
# =============================================================================
# PURPOSE: This script solves the "chicken-and-egg" problem of starting Ollama.
#
# The problem: `ollama serve` starts the HTTP server, but we ALSO need to run
# `ollama pull <model>` to download our AI model. However, `ollama pull` only
# works AFTER the server is running. So we need to:
#   1. Start the server in the BACKGROUND (the & at the end of `ollama serve`)
#   2. WAIT in a loop until the server is actually accepting connections
#   3. THEN run the pull command to download the model
#   4. Wait forever so the container doesn't exit (wait $SERVER_PID keeps it alive)
# =============================================================================

set -e  # Exit immediately if any command fails (safety net)

# Which model to download. This is read from an environment variable so you can
# override it in docker-compose without editing this script.
# Default: llama3.2:1b (ultra-lightweight, ~1.3GB, perfect for hackathons)
MODEL="${OLLAMA_MODEL:-llama3.2:1b}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║       SecuriVillage Local AI Engine Startup          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "[OLLAMA] Step 1/3: Starting Ollama server process in background..."

# Start the Ollama HTTP server in the background.
# This is the process that will listen on port 11434 for requests from our router.
# The `&` sends it to the background so this script can continue to the next steps.
/bin/ollama serve &

# Save the Process ID (PID) of the server so we can `wait` for it later.
# If we don't `wait` on it, the script exits and Docker kills the whole container.
SERVER_PID=$!

echo "[OLLAMA] Server process started with PID: $SERVER_PID"
echo "[OLLAMA] Step 2/3: Waiting for server to become ready..."

# Health-check loop: keep trying until the Ollama server responds.
#
# WHY NOT curl?
# The ollama/ollama Docker image is a minimal distro — curl is not installed.
# Additionally, `ollama serve` binds to the IPv6 any-address [::]  which means
# it listens on both IPv6 (::1) and IPv4 (127.0.0.1), but on some kernel
# configurations `localhost` resolves only to 127.0.0.1 while the listener is
# on ::1, causing curl to connect to the wrong address and time out silently.
#
# WHY /bin/ollama list?
# `ollama list` is a native CLI command that is always present in the image.
# Internally it connects to the same ollama serve socket using the same
# resolution logic the server itself uses — so if the server is up, this
# command succeeds (exit code 0). If the server isn't ready yet, it exits
# with a non-zero code, which is exactly what the `until` loop needs.
# No network stack assumptions, no missing binaries.
MAX_WAIT=120  # Maximum seconds to wait before giving up
ELAPSED=0
INTERVAL=3    # Check every 3 seconds

until /bin/ollama list > /dev/null 2>&1; do
    echo "[OLLAMA] Server not ready yet... (${ELAPSED}s elapsed, max ${MAX_WAIT}s)"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))

    if [ $ELAPSED -ge $MAX_WAIT ]; then
        echo "[ERROR] Ollama server failed to start within ${MAX_WAIT} seconds. Exiting."
        exit 1
    fi
done

echo "[OLLAMA] ✓ Server is ready and accepting connections!"
echo "[OLLAMA] Step 3/3: Pulling AI model '${MODEL}'..."
echo "[OLLAMA] This may take several minutes on first run (downloads ~1.3GB)."
echo "[OLLAMA] On subsequent runs, the model is cached in the Docker volume (instant)."

# Pull the model. This command downloads the quantized model weights from the
# Ollama model registry (like Docker Hub but for AI models).
# On subsequent container restarts, the volume cache makes this nearly instant.
/bin/ollama pull "${MODEL}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✓ SecuriVillage AI Engine FULLY OPERATIONAL!       ║"
echo "║  Model: ${MODEL}"
echo "║  Endpoint: http://ollama:11434 (internal network)    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Block here, keeping the server process alive.
# `wait $SERVER_PID` pauses this script until the ollama serve process exits.
# Since `ollama serve` runs forever, this keeps our container alive indefinitely.
# If ollama crashes, this script exits, and Docker's `restart: unless-stopped`
# policy will automatically restart the entire container.
wait $SERVER_PID
