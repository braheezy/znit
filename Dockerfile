FROM alpine:latest

# Install basic tools for testing
RUN apk add --no-cache \
    bash \
    coreutils \
    procps \
    strace \
    curl \
    tini

# Copy test script
COPY test-tini.sh /test-init.sh
RUN chmod +x /test-init.sh

# Set tini as the entrypoint (can also use --init flag when running docker)
ENTRYPOINT ["/sbin/tini", "--"]

# Default command for interactive testing
CMD ["/bin/bash"]
