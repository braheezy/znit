#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="init-test"
INIT_TYPE="${INIT_TYPE:-tini}"  # Can be 'tini' or 'znit'

# Set paths based on init type
case "$INIT_TYPE" in
    tini)
        INIT_BINARY="/sbin/tini"
        INIT_NAME="tini"
        DOCKERFILE="Dockerfile"
        ;;
    znit)
        INIT_BINARY="/usr/local/bin/znit"
        INIT_NAME="znit"
        DOCKERFILE="Dockerfile.znit"
        ;;
    *)
        echo "Unknown INIT_TYPE: $INIT_TYPE. Use 'tini' or 'znit'"
        exit 1
        ;;
esac

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_command() {
    echo -e "${BLUE}[COMMAND]${NC} $1"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --init)
                INIT_TYPE="$2"
                case "$INIT_TYPE" in
                    tini)
                        INIT_BINARY="/sbin/tini"
                        INIT_NAME="tini"
                        DOCKERFILE="Dockerfile"
                        ;;
                    znit)
                        INIT_BINARY="/usr/local/bin/znit"
                        INIT_NAME="znit"
                        DOCKERFILE="Dockerfile.znit"
                        ;;
                    *)
                        echo "Unknown init type: $INIT_TYPE. Use 'tini' or 'znit'"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                # Not our argument, break and let main handle it
                break
                ;;
        esac
    done

    # Update image name to include init type
    IMAGE_NAME="init-test-$INIT_TYPE"
}

# Build the Docker image
build_image() {
    log_info "Building Docker image for $INIT_NAME..."

    if [[ "$INIT_TYPE" == "znit" ]]; then
        # Check if znit binary exists
        if [[ ! -f "zig-out/bin/znit" ]]; then
            log_info "znit binary not found. Please build znit first with 'zig build'"
            return 1
        fi
    fi

    log_command "docker build -f $DOCKERFILE -t $IMAGE_NAME ."
    docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" .
    log_success "Image built successfully for $INIT_NAME"
    echo
}

# Run the comprehensive test suite
run_test_suite() {
    log_info "Running comprehensive $INIT_NAME test suite..."
    log_command "docker run --rm -e INIT_BINARY=$INIT_BINARY -e INIT_NAME=$INIT_NAME $IMAGE_NAME /test-init.sh"
    docker run --rm -e INIT_BINARY="$INIT_BINARY" -e INIT_NAME="$INIT_NAME" "$IMAGE_NAME" /test-init.sh
    echo
}

# Test basic functionality
test_basic() {
    log_info "Testing basic $INIT_NAME functionality..."

    echo "1. Version check:"
    log_command "docker run --rm $IMAGE_NAME $INIT_BINARY --version"
    docker run --rm "$IMAGE_NAME" "$INIT_BINARY" --version || true
    echo

    echo "2. Help output:"
    log_command "docker run --rm $IMAGE_NAME $INIT_BINARY -h"
    docker run --rm "$IMAGE_NAME" "$INIT_BINARY" -h || true
    echo

    echo "3. Basic command execution:"
    log_command "docker run --rm $IMAGE_NAME echo 'Hello from $INIT_NAME container'"
    docker run --rm "$IMAGE_NAME" echo "Hello from $INIT_NAME container"
    echo
}

# Test signal handling
test_signals() {
    log_info "Testing signal handling with $INIT_NAME..."

    echo "1. Testing SIGTERM handling:"
    log_command "docker run --rm $IMAGE_NAME timeout 5s sleep 10"
    docker run --rm "$IMAGE_NAME" timeout 5s sleep 10 || echo "Process terminated as expected"
    echo

    echo "2. Testing graceful shutdown:"
    log_command "docker run --rm $IMAGE_NAME sh -c 'sleep 30 &' # (will be interrupted)"
    docker run --rm "$IMAGE_NAME" sh -c 'echo "Starting background sleep..."; sleep 30 & wait' &
    CONTAINER_PID=$!
    sleep 2
    echo "Sending SIGTERM to container..."
    kill -TERM $CONTAINER_PID || true
    wait $CONTAINER_PID || echo "Container terminated gracefully"
    echo
}

# Test zombie reaping behavior
test_zombie_reaping() {
    log_info "Testing zombie reaping behavior with $INIT_NAME..."

    # Create a script that generates zombies
    cat > zombie_test.sh << 'EOF'
#!/bin/bash
echo "Creating zombie processes..."
# Create multiple child processes that exit quickly
for i in {1..5}; do
    # Each child will exit immediately, becoming a zombie until reaped
    (sleep 0.1; exit $i) &
    echo "Started child process $! (will exit with code $i)"
done

echo "Background processes started, parent will sleep..."
echo "Before sleep - checking for zombies:"
ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies yet"

sleep 3

echo "After sleep - checking for zombies:"
ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies found (init cleaned them up!)"
echo "Parent exiting..."
EOF

    # Make the script executable
    chmod +x zombie_test.sh

    log_command "docker run --rm -v \$(pwd)/zombie_test.sh:/zombie_test.sh $IMAGE_NAME /zombie_test.sh"
    docker run --rm -v $(pwd)/zombie_test.sh:/zombie_test.sh "$IMAGE_NAME" /zombie_test.sh

    # Clean up
    rm -f zombie_test.sh
    echo
}

# Test with different init systems
test_different_inits() {
    log_info "Comparing different init approaches..."

    echo "1. With explicit $INIT_NAME (current setup):"
    log_command "docker run --rm $IMAGE_NAME ps aux"
    docker run --rm "$IMAGE_NAME" ps aux | head -5
    echo

    echo "2. With Docker's built-in --init:"
    log_command "docker run --init --rm alpine:latest ps aux"
    docker run --init --rm alpine:latest ps aux | head -5
    echo

    echo "3. Without any init (notice PID 1 is the command itself):"
    log_command "docker run --rm alpine:latest ps aux"
    docker run --rm alpine:latest ps aux | head -5
    echo
}

# Test different verbosity levels
test_verbosity() {
    log_info "Testing different verbosity levels with $INIT_NAME..."

    echo "1. Default verbosity:"
    log_command "docker run --rm $IMAGE_NAME echo 'Default verbosity'"
    docker run --rm "$IMAGE_NAME" echo "Default verbosity"
    echo

    echo "2. Verbose mode (-v):"
    log_command "docker run --rm --entrypoint=$INIT_BINARY $IMAGE_NAME -v echo 'Verbose mode'"
    docker run --rm --entrypoint="$INIT_BINARY" "$IMAGE_NAME" -v echo "Verbose mode"
    echo

    echo "3. Very verbose mode (-vv):"
    log_command "docker run --rm --entrypoint=$INIT_BINARY $IMAGE_NAME -vv echo 'Very verbose mode'"
    docker run --rm --entrypoint="$INIT_BINARY" "$IMAGE_NAME" -vv echo "Very verbose mode"
    echo

    if [[ "$INIT_TYPE" == "tini" ]]; then
        echo "4. Environment variable verbosity:"
        log_command "docker run --rm -e TINI_VERBOSITY=2 $IMAGE_NAME echo 'Env verbosity'"
        docker run --rm -e TINI_VERBOSITY=2 "$IMAGE_NAME" echo "Env verbosity"
    else
        echo "4. Skipping tini-specific environment variables for $INIT_NAME"
    fi
    echo
}

# Test in non-PID1 mode (useful for comparison)
test_non_pid1_mode() {
    log_info "Testing $INIT_NAME behavior when NOT running as PID 1..."

    echo "Running test suite in a container where $INIT_NAME is NOT PID 1:"
    log_command "docker run --rm --entrypoint=/bin/bash $IMAGE_NAME /test-init.sh --binary $INIT_BINARY --name $INIT_NAME"
    docker run --rm --entrypoint=/bin/bash "$IMAGE_NAME" /test-init.sh --binary "$INIT_BINARY" --name "$INIT_NAME"
    echo
}

# Compare tini vs znit behavior
compare_inits() {
    log_info "Comparing tini vs znit behavior..."

    echo "=== Building both images ==="
    INIT_TYPE=tini parse_args
    build_image

    INIT_TYPE=znit parse_args
    build_image

    echo "=== Running basic tests for both ==="
    echo "--- TINI Results ---"
    INIT_TYPE=tini parse_args
    test_basic

    echo "--- ZNIT Results ---"
    INIT_TYPE=znit parse_args
    test_basic

    echo "=== Running comprehensive tests for both ==="
    echo "--- TINI Results ---"
    INIT_TYPE=tini parse_args
    run_test_suite

    echo "--- ZNIT Results ---"
    INIT_TYPE=znit parse_args
    run_test_suite

    log_success "Comparison complete! Review the outputs above to compare behaviors."
}

# Interactive mode for manual testing
interactive_mode() {
    log_info "Starting interactive container for manual testing with $INIT_NAME..."
    log_info "Inside the container, you can:"
    echo "  - Run '/test-init.sh' for the full test suite"
    echo "  - Run '$INIT_BINARY --help' for help"
    echo "  - Run 'ps aux' to see the process tree"
    echo "  - Test signal handling manually"
    echo "  - Exit with 'exit'"
    echo
    log_command "docker run --rm -it -e INIT_BINARY=$INIT_BINARY -e INIT_NAME=$INIT_NAME $IMAGE_NAME"
    docker run --rm -it -e INIT_BINARY="$INIT_BINARY" -e INIT_NAME="$INIT_NAME" "$IMAGE_NAME"
}

# Show usage
usage() {
    echo "Init System Test Runner"
    echo "======================"
    echo
    echo "Usage: $0 [--init tini|znit] [command]"
    echo
    echo "Global Options:"
    echo "  --init TYPE       Which init system to test (tini or znit, default: tini)"
    echo "  --help            Show this help message"
    echo
    echo "Commands:"
    echo "  build             - Build the Docker image"
    echo "  test              - Run the comprehensive test suite"
    echo "  basic             - Test basic functionality"
    echo "  signals           - Test signal handling"
    echo "  zombies           - Test zombie reaping"
    echo "  inits             - Compare different init approaches"
    echo "  verbosity         - Test different verbosity levels"
    echo "  non-pid1          - Test when NOT running as PID 1"
    echo "  compare           - Compare tini vs znit behavior"
    echo "  interactive       - Start interactive container"
    echo "  all               - Run all tests (default)"
    echo "  help              - Show this help message"
    echo
    echo "Environment Variables:"
    echo "  INIT_TYPE         - Which init system to test (tini or znit)"
    echo
    echo "Example workflows:"
    echo "  $0 --init tini build test      # Build and test tini"
    echo "  $0 --init znit build test      # Build and test znit"
    echo "  $0 compare                     # Compare both side by side"
    echo "  $0 --init znit interactive     # Manual znit testing"
}

# Main function
main() {
    # Parse global arguments first
    parse_args "$@"

    # Get remaining arguments after parsing
    local remaining_args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --init|--help)
                # These were handled by parse_args, skip them and their values
                shift 2 2>/dev/null || shift 1
                ;;
            *)
                remaining_args+=("$1")
                shift
                ;;
        esac
    done

    # Use first remaining argument as command, default to 'all'
    local command="${remaining_args[0]:-all}"

    case "$command" in
        build)
            build_image
            ;;
        test)
            run_test_suite
            ;;
        basic)
            test_basic
            ;;
        signals)
            test_signals
            ;;
        zombies)
            test_zombie_reaping
            ;;
        inits)
            test_different_inits
            ;;
        verbosity)
            test_verbosity
            ;;
        non-pid1)
            test_non_pid1_mode
            ;;
        compare)
            compare_inits
            ;;
        interactive)
            interactive_mode
            ;;
        all)
            build_image
            test_basic
            test_verbosity
            test_zombie_reaping
            test_signals
            run_test_suite
            ;;
        help)
            usage
            ;;
        *)
            echo "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
