# Multi-stage release Dockerfile for yunq-server and yunq-worker
FROM rust:1.85-alpine as builder

RUN apk add --no-cache musl-dev gcc

WORKDIR /app
COPY . .

RUN cargo build --release --bins

# Server container
FROM alpine:3.20 as server
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/yunq-server /usr/local/bin/yunq-server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/yunq-server"]

# Worker container
FROM alpine:3.20 as worker
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/yunq-worker /usr/local/bin/yunq-worker
ENTRYPOINT ["/usr/local/bin/yunq-worker"]

# CLI container
FROM alpine:3.20 as cli
RUN apk add --no-cache ca-certificates git
COPY --from=builder /app/target/release/yunq-cli /usr/local/bin/yunq
ENTRYPOINT ["/usr/local/bin/yunq"]
