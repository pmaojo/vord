# Multi-stage release Dockerfile for yunq-server, yunq-worker, and yunq-cli
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev gcc g++ make git

WORKDIR /app
COPY . .

RUN cargo build --release --bins

# Server container
FROM alpine:3.20 AS server
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/yunq-server /usr/local/bin/yunq-server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/yunq-server"]

# Worker container
FROM alpine:3.20 AS worker
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/yunq-worker /usr/local/bin/yunq-worker
ENTRYPOINT ["/usr/local/bin/yunq-worker"]

# CLI container
FROM alpine:3.20 AS cli
RUN apk add --no-cache ca-certificates git
COPY --from=builder /app/target/release/yunq-cli /usr/local/bin/yunq
ENTRYPOINT ["/usr/local/bin/yunq"]
