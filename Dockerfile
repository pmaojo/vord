# Release Dockerfile for vord-cli
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev gcc g++ make git curl

WORKDIR /app
COPY . .

RUN cargo build --release --locked -p vord-cli

# CLI container
FROM alpine:3.20 AS cli
# git: `vord scan --blame-output` shells out to it for line attribution.
RUN apk add --no-cache ca-certificates git
COPY --from=builder /app/target/release/vord-cli /usr/local/bin/vord
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/vord"]
CMD ["scan", "."]
