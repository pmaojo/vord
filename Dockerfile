# Release Dockerfile for yunq-cli
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev gcc g++ make git curl

WORKDIR /app
COPY . .

RUN cargo build --release --bins

# CLI container
FROM alpine:3.20 AS cli
RUN apk add --no-cache ca-certificates git
COPY --from=builder /app/target/release/yunq-cli /usr/local/bin/yunq
ENTRYPOINT ["/usr/local/bin/yunq"]
