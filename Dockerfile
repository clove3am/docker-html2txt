# syntax=docker/dockerfile:1

# ---- Stage 1: Build ----
# Use the official Go image as a build environment.
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Copy the module files first so dependency download is cached separately
# from the source code. The wildcard keeps this working without a go.sum.
COPY go.* ./
RUN go mod download

# Copy the source code.
COPY . .

# Build a static binary that runs on the minimal runtime image.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/html2txt .


# ---- Stage 2: Final Image ----
FROM alpine:3.24.4

# lynx is a runtime dependency: it does the actual HTML to text rendering.
# The service runs as an unprivileged user.
RUN apk add --no-cache lynx \
 && addgroup -S app \
 && adduser -S -G app -H -s /sbin/nologin app

COPY --from=builder /out/html2txt /usr/local/bin/html2txt

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/html2txt"]
