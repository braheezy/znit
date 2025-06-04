# znit

This is a minimal `init` system based of [`tini`](https://github.com/krallin/tini).

Just like Tini, `znit` spawns a single child and waits for it to exit, reaping zombies and performing signal forwarding. It's meant to run in a container.

`znit` tries to match `tini` in behavior but none of the extra features and options are implemented yet so just use `tini` if you need an init system.

## Usage
Until pre-built releases are provided, you have to build from source. This is a Zig project so you need thata installed.

```bash
git clone https://github.com/braheezy/znit.git
cd znit
zig build
```

Make `znit` the `ENTRYPOINT` in your Containerfile. Here's an example snippet:

```dockerfile
# Copy znit binary from host build
COPY zig-out/bin/znit /usr/local/bin/znit
RUN chmod +x /usr/local/bin/znit

# Set znit as the entrypoint
ENTRYPOINT ["/usr/local/bin/znit", "--"]
```
