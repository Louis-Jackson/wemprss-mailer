# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------------
FROM golang:1.22 AS builder

WORKDIR /src

# Avoid CGO for a static-ish binary; allow toolchain auto-download if needed
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/wemprss-mailer ./cmd/wemprss-mailer

# --- Runtime stage -----------------------------------------------------------
FROM alpine:3.20

RUN adduser -D -u 10001 app \
    && apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /out/wemprss-mailer /app/wemprss-mailer

EXPOSE 8080
USER app

# Default to web mode; override with `send` to run one-shot
ENTRYPOINT ["/app/wemprss-mailer"]
CMD ["serve"]


