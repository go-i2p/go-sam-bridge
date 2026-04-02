#!/bin/bash
# run-integration-test.sh
#
# Builds and runs the container-isolated integration test for go-sam-bridge.
# Uses the embedded go-i2p router (no external I2P installation required).
#
# Usage:
#   ./run-integration-test.sh              # Build and run
#   ./run-integration-test.sh --no-cache   # Force fresh build
#   ./run-integration-test.sh --shell      # Drop into container shell for debugging

set -euo pipefail

IMAGE_NAME="sam-bridge-integration"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BUILD_ARGS=""
RUN_SHELL=false

for arg in "$@"; do
    case "$arg" in
        --no-cache)
            BUILD_ARGS="--no-cache"
            ;;
        --shell)
            RUN_SHELL=true
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--no-cache] [--shell]"
            exit 1
            ;;
    esac
done

echo "=== Building integration test container ==="
docker build $BUILD_ARGS -f "$SCRIPT_DIR/Dockerfile.integration" -t "$IMAGE_NAME" "$SCRIPT_DIR"

if [ "$RUN_SHELL" = true ]; then
    echo "=== Dropping into container shell ==="
    echo "Run: /integration-test -test.v -test.timeout 20m"
    docker run --rm -it "$IMAGE_NAME" /bin/bash
else
    echo "=== Running integration tests ==="
    echo "This may take several minutes while the embedded I2P router bootstraps..."
    echo ""
    docker run --rm "$IMAGE_NAME"
fi
