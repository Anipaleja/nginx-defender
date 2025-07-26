# Multi-stage build for nginx-defender
FROM golang:1.21-alpine AS build

# Add metadata labels for container registry
LABEL org.opencontainers.image.source=https://github.com/Anipaleja/nginx-defender
LABEL org.opencontainers.image.description="Advanced Nginx Security Defense System with AI-powered threat detection"
LABEL org.opencontainers.image.licenses=MIT

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Set the working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_HASH

# Build the application with optimizations
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitHash=${GIT_HASH}" \
    -a -installsuffix cgo \
    -o nginx-defender \
    ./cmd/nginx-defender

# Production stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iptables \
    ip6tables \
    curl \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S defender && \
    adduser -u 1001 -S defender -G defender

# Create necessary directories
RUN mkdir -p /app/config /app/data /app/logs /app/web/static /app/web/templates && \
    chown -R defender:defender /app

WORKDIR /app

# Copy binary from build stage
COPY --from=build /app/nginx-defender .
COPY --from=build /app/web/ ./web/
COPY --from=build /app/config.yaml ./config/
COPY --from=build /app/k8s/ ./k8s/

# Set ownership
RUN chown -R defender:defender /app

# Switch to non-root user
USER defender

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090

# Set entrypoint
ENTRYPOINT ["./nginx-defender"]
CMD ["-config", "/app/config/config.yaml"]

