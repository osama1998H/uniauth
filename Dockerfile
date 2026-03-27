# ─── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o uniauth ./cmd/server

# ─── Runtime stage ───────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/uniauth /uniauth
COPY --from=builder /app/migrations /migrations

EXPOSE 8080

ENTRYPOINT ["/uniauth"]
