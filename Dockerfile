# syntax=docker/dockerfile:1
#
# h2h -- the HushSpec reference CLI.
#
#   docker build -t h2h .
#   docker run --rm h2h version
#   docker run --rm -v "$PWD:/workspace" h2h validate policy.yaml
#
# Multi-stage: compile with the full Rust toolchain, ship only the binary.

FROM rust:1.88-slim AS builder
WORKDIR /src

# Only the workspace manifest and the three crates are needed to build
# hushspec-cli: every schema, ruleset and library file it embeds is vendored
# into checked-in generated_*.rs source, not read at build time (see
# crates/hushspec/src/generated_builtins.rs and generated_schemas.rs), so
# schemas/, rulesets/, library/, fixtures/, and the language SDKs under
# packages/ are never copied into the build context.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build -p hushspec-cli --release --locked && \
    strip target/release/h2h

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="h2h" \
      org.opencontainers.image.description="HushSpec reference CLI: validate, lint, test, diff, sign and audit AI agent security policies" \
      org.opencontainers.image.source="https://github.com/backbay-labs/hush" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.documentation="https://github.com/backbay-labs/hush/blob/main/docs/src/reference/cli.md" \
      org.opencontainers.image.vendor="backbay-labs"

COPY --from=builder /src/target/release/h2h /usr/local/bin/h2h

# Unprivileged, no shell needed for policy files mounted read-only, but
# bookworm-slim (rather than a fully distroless base) keeps one available
# for interactive debugging (`docker run --rm -it --entrypoint bash h2h`).
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 hushspec
USER hushspec
WORKDIR /workspace

ENTRYPOINT ["h2h"]
CMD ["--help"]
