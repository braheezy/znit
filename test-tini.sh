#!/bin/bash

set -e

# Configuration - can be overridden via environment variables or command line
INIT_BINARY="${INIT_BINARY:-/sbin/tini}"
INIT_NAME="${INIT_NAME:-tini}"
VERBOSE="${VERBOSE:-false}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --binary)
            INIT_BINARY="$2"
            INIT_NAME=$(basename "$2")
            shift 2
            ;;
        --name)
            INIT_NAME="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --binary PATH    Path to init binary (default: /sbin/tini)"
            echo "  --name NAME      Name of init system for display (default: tini)"
            echo "  --verbose        Enable verbose output"
            echo "  --help           Show this help"
            echo ""
            echo "Environment variables:"
            echo "  INIT_BINARY      Path to init binary"
            echo "  INIT_NAME        Name of init system"
            echo "  VERBOSE          Enable verbose output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== $INIT_NAME Behavior Test Suite ==="
echo "Testing binary: $INIT_BINARY"
echo "This script exercises various init behaviors for comparison"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test 1: Basic version check
test_version() {
    log_test "Testing version output"
    echo "--- $INIT_NAME --version ---"
    $INIT_BINARY --version || true
    echo
}

# Test 2: Help output
test_help() {
    log_test "Testing help output"
    echo "--- $INIT_NAME -h ---"
    $INIT_BINARY -h || true
    echo
}

# Test 3: Basic command execution
test_basic_exec() {
    log_test "Testing basic command execution"
    echo "--- $INIT_NAME echo 'Hello World' ---"
    $INIT_BINARY echo "Hello World"
    log_success "Basic execution works"
    echo
}

# Test 4: Process substitution and PID 1 behavior
test_pid1_behavior() {
    log_test "Testing PID 1 behavior in container"

    echo "--- Current environment analysis ---"
    echo "Current process PID: $$"
    echo "PID 1 process: $(ps -p 1 -o comm=)"
    echo "Are we running under $INIT_NAME as PID 1? $(ps -p 1 -o comm= | grep -q $INIT_NAME && echo 'YES' || echo 'NO')"
    echo

    echo "--- Process tree when $INIT_NAME runs as PID 1 ---"
    ps aux
    echo
    echo "--- $INIT_NAME process details ---"
    ps -p 1 -o pid,ppid,pgid,sid,tty,stat,time,command
    echo

    # Additional context about our testing environment
    if ps -p 1 -o comm= | grep -q $INIT_NAME; then
        log_info "Running in optimal test environment - $INIT_NAME is PID 1"
        echo "This allows us to test real init behavior including:"
        echo "  - Automatic zombie reaping"
        echo "  - Signal handling as PID 1"
        echo "  - Process group management"
    else
        log_info "Running nested $INIT_NAME tests"
        echo "We'll use subreaper mode (-s) for zombie reaping tests"
    fi
    echo
}

# Test 5: Signal handling
test_signal_handling() {
    log_test "Testing signal handling"

    # Check if we're already running under $INIT_NAME as PID 1
    if ps -p 1 -o comm= | grep -q $INIT_NAME; then
        echo "--- Testing signal handling with $INIT_NAME as PID 1 ---"
        echo "Creating a background process that $INIT_NAME will manage..."

        # Create a background process
        sleep 30 &
        SLEEP_PID=$!
        echo "Started sleep process with PID: $SLEEP_PID"
        sleep 1

        # Send SIGTERM to the sleep process
        echo "Sending SIGTERM to sleep process..."
        kill -TERM $SLEEP_PID || true

        # Wait a bit and check if it's still running
        sleep 2
        if kill -0 $SLEEP_PID 2>/dev/null; then
            log_error "Process still running after SIGTERM"
            kill -KILL $SLEEP_PID || true
        else
            log_success "Process terminated gracefully"
        fi

    else
        echo "--- Running sleep with $INIT_NAME and sending SIGTERM ---"

        # Start a long-running process in background
        $INIT_BINARY sleep 30 &
        INIT_PID=$!
        sleep 1

        echo "$INIT_NAME process started with PID: $INIT_PID"
        ps -p $INIT_PID -o pid,ppid,pgid,command

        # Send SIGTERM
        echo "Sending SIGTERM to $INIT_NAME process..."
        kill -TERM $INIT_PID || true

        # Wait a bit and check if it's still running
        sleep 2
        if kill -0 $INIT_PID 2>/dev/null; then
            log_error "Process still running after SIGTERM"
            kill -KILL $INIT_PID || true
        else
            log_success "Process terminated gracefully"
        fi
    fi
    echo
}

# Test 6: Zombie reaping
test_zombie_reaping() {
    log_test "Testing zombie reaping"
    echo "--- Creating zombie processes ---"

    # Check if we're already running under $INIT_NAME as PID 1
    if ps -p 1 -o comm= | grep -q $INIT_NAME; then
        echo "Already running under $INIT_NAME as PID 1 - testing direct zombie creation"

        # Create zombies directly since $INIT_NAME (PID 1) will reap them
        echo "Creating zombie processes..."
        echo "Before creating children - checking for existing zombies:"
        ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies found"

        for i in {1..3}; do
            # Create child processes that exit quickly, becoming zombies
            (sleep 0.1; exit $i) &
            CHILD_PID=$!
            echo "Started child process $CHILD_PID (will exit with code $i)"
        done

        echo "Background processes started, sleeping to let them exit and potentially become zombies..."
        sleep 2

        echo "After sleep - checking for zombies:"
        ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies found ($INIT_NAME as PID 1 cleaned them up!)"

    else
        echo "Not running under $INIT_NAME as PID 1 - testing with subreaper option"

        # This script creates zombies that $INIT_NAME should reap
        cat > /tmp/zombie_maker.sh << 'EOF'
#!/bin/bash
echo "Creating zombie processes..."
# Create child processes that exit quickly, making them zombies
for i in {1..3}; do
    # Start a background process that exits immediately
    (exit $i) &
    echo "Started child process $! that will exit with code $i"
done

echo "Parent process sleeping to allow children to become zombies..."
sleep 3

echo "Checking for zombie processes:"
ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies visible (may have been reaped)"

echo "Parent process exiting..."
# When parent exits, children should be adopted by init ($INIT_NAME)
EOF
        chmod +x /tmp/zombie_maker.sh

        echo "Before running zombie maker:"
        ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies found"

        # Use -s option to register as subreaper
        $INIT_BINARY -s /tmp/zombie_maker.sh

        echo "After running zombie maker:"
        ps aux | grep -E "(zombie|<defunct>)" || echo "No zombies found (good!)"
    fi

    log_success "Zombie reaping test completed"
    echo
}

# Test 7: Environment variable handling
test_env_vars() {
    log_test "Testing environment variable handling"
    echo "--- Testing TINI_VERBOSITY ---"
    TINI_VERBOSITY=2 $INIT_BINARY echo "Testing with verbose output"
    echo

    echo "--- Testing TINI_KILL_PROCESS_GROUP ---"
    TINI_KILL_PROCESS_GROUP=1 $INIT_BINARY echo "Testing with kill process group"
    echo
}

# Test 8: Exit code handling
test_exit_codes() {
    log_test "Testing exit code propagation"

    echo "--- Testing exit code 0 ---"
    $INIT_BINARY sh -c "exit 0"
    echo "Exit code: $?"

    echo "--- Testing exit code 42 ---"
    $INIT_BINARY sh -c "exit 42" || echo "Exit code: $?"

    echo "--- Testing command not found (should be 127) ---"
    $INIT_BINARY /nonexistent/command || echo "Exit code: $?"
    echo
}

# Test 9: Process group handling
test_process_groups() {
    log_test "Testing process group handling"
    echo "--- Process group information ---"

    # Run a command that spawns subprocesses
    $INIT_BINARY bash -c 'echo "Main process PID: $$, PGID: $(ps -o pgid= -p $$)"; sleep 1 & echo "Background process PID: $!, PGID: $(ps -o pgid= -p $!)"; wait'
    echo
}

# Test 10: Verbose output
test_verbose_output() {
    log_test "Testing verbose output levels"

    echo "--- Default verbosity ---"
    $INIT_BINARY echo "Default verbosity test"

    echo "--- Verbosity level 1 ---"
    $INIT_BINARY -v echo "Verbosity level 1 test"

    echo "--- Verbosity level 2 ---"
    $INIT_BINARY -vv echo "Verbosity level 2 test"

    echo "--- Verbosity level 3 ---"
    $INIT_BINARY -vvv echo "Verbosity level 3 test"
    echo
}

# Main test runner
main() {
    echo "Starting $INIT_NAME behavior tests..."
    echo "Container environment: $(uname -a)"
    echo "Current PID: $$"
    echo

    test_version
    test_help
    test_basic_exec
    test_pid1_behavior
    test_env_vars
    test_exit_codes
    test_process_groups
    test_verbose_output
    test_signal_handling
    test_zombie_reaping

    echo
    log_success "All tests completed!"
    echo "Use these behaviors as reference when testing znit compatibility"
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
