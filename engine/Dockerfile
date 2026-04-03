# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/autoblock-engine ./cmd/engine
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/autoblock-api ./cmd/api

# Engine target
FROM scratch AS engine
COPY --from=builder /bin/autoblock-engine /autoblock-engine
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/autoblock-engine"]

# API target
FROM scratch AS api
COPY --from=builder /bin/autoblock-api /autoblock-api
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/autoblock-api"]
