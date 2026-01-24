# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o taildrop-me .

# Final stage
FROM alpine:latest

# Install dependencies
RUN apk --no-cache add \
    ca-certificates \
    iptables \
    iproute2 \
    curl

# Install Tailscale
RUN wget -q https://pkgs.tailscale.com/stable/tailscale_latest_amd64.tgz && \
    tar xzf tailscale_latest_amd64.tgz --strip-components=1 -C /usr/local/bin && \
    rm tailscale_latest_amd64.tgz

# Create directory for Tailscale state
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/taildrop-me .

# Copy templates
COPY templates ./templates

# Copy start script
COPY start.sh .
RUN chmod +x start.sh

# Expose port
EXPOSE 8080

# Run the start script
CMD ["./start.sh"]
