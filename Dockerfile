# NKOSI Agent Dockerfile
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# Build release
RUN cargo build --release --bin nkosi-agent && \
    cargo build --release --bin nkosi-cli && \
    cargo build --release --bin nkosi-api

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create nkosi user
RUN useradd -r -s /bin/false nkosi

# Copy binaries
COPY --from=builder /app/target/release/nkosi-agent /usr/local/bin/
COPY --from=builder /app/target/release/nkosi-cli /usr/local/bin/
COPY --from=builder /app/target/release/nkosi-api /usr/local/bin/

# Copy config and service files
COPY config/nkosi.toml /etc/nkosi/nkosi.toml
COPY man/nkosi.1 /usr/share/man/man1/

# Create required directories
RUN mkdir -p /var/lib/nkosi /var/log/nkosi /var/backup/nkosi && \
    chown -R nkosi:nkosi /var/lib/nkosi /var/log/nkosi /var/backup/nkosi

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/status || exit 1

# Run as nkosi user
USER nkosi

# Default to agent mode
ENTRYPOINT ["nkosi-agent"]
