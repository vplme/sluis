# Build stage — musl-free static-ish build is unnecessary: distroless/cc
# provides the glibc the default target needs, and rustls means no OpenSSL.
FROM rust:1.96-slim AS build
WORKDIR /src

# Cache dependencies separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true
COPY . .
RUN touch src/main.rs src/lib.rs && cargo build --release --locked --bin sluis

# Runtime stage — no shell, no package manager, non-root.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/sluis /usr/local/bin/sluis
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sluis"]
CMD ["serve"]
