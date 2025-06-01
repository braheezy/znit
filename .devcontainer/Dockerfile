FROM mcr.microsoft.com/devcontainers/base:debian

ARG ZIG_VERSION

RUN apt-get update && apt-get install -y \
    clangd

USER vscode
WORKDIR /home/vscode
ENV PATH="$PATH:/home/vscode/"

RUN curl -LO https://github.com/marler8997/zigup/releases/download/v2025_05_24/zigup-aarch64-linux.tar.gz \
    && tar -xzf zigup-aarch64-linux.tar.gz \
    && chmod +x zigup \
    && ./zigup ${ZIG_VERSION} \
    && rm zigup-aarch64-linux.tar.gz zigup

RUN zig version
