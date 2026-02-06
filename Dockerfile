# Run this first to set dependencies:
# docker run --rm -v $(pwd):/app -w /app golang:1.23-bookworm go mod tidy

# ---- Build Stage ----
FROM golang:1.23-bookworm AS builder

WORKDIR /app

# Install build dependencies for CGO / SQLite
RUN apt-get update && \
    apt-get install -y build-essential gcc sqlite3 libsqlite3-dev git && \
    rm -rf /var/lib/apt/lists/*

# Copy mod files first
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source + templates + static
COPY . .

# Build binary
RUN go mod tidy && CGO_ENABLED=1 GOOS=linux go build -o api .

# ---- Runtime Stage ----
FROM debian:bookworm-slim

# Environment Variables
ENV HTTPS=true
ENV SESSION_KEY=your-random-secret-key-here-change-this
ENV APP_TITLE="Shop Mode"
ENV DEFAULT_ORGANIZATION=Default
ENV DEFAULT_LIST="Shopping"
ENV DEFAULT_ADMIN_USERNAME=admin
ENV DEFAULT_ADMIN_PASSWORD=admin

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 appuser

WORKDIR /app

# Copy binary + static files
COPY --from=builder /app/api .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Copy favicon.ico to app root for browser
COPY --from=builder /app/static/favicon.ico .

# Create data dir
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8888

CMD ["./api"]
