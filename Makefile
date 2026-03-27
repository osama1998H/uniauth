.PHONY: all build run test lint fmt clean migrate generate help

BINARY=uniauth
CMD=./cmd/server

# ─── Build ───────────────────────────────────────────────────────────────────

all: build

build:
	@echo "==> Building $(BINARY)..."
	go build -o bin/$(BINARY) $(CMD)

run:
	@echo "==> Starting dependencies..."
	docker compose up -d postgres redis
	@echo "==> Running server..."
	go run $(CMD)

# ─── Testing ─────────────────────────────────────────────────────────────────

test:
	go test ./... -v -race -timeout 120s

test-short:
	go test ./... -short -timeout 30s

# ─── Code Quality ────────────────────────────────────────────────────────────

lint:
	golangci-lint run ./...

fmt:
	gofmt -l -w .
	goimports -l -w .

vet:
	go vet ./...

# ─── Database ────────────────────────────────────────────────────────────────

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

migrate-status:
	migrate -path migrations -database "$(DATABASE_URL)" version

# ─── Code Generation ─────────────────────────────────────────────────────────

generate:
	@echo "==> Running go generate..."
	go generate ./...

sqlc:
	sqlc generate

# ─── Docker ──────────────────────────────────────────────────────────────────

docker-build:
	docker build -t uniauth:latest .

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

# ─── Dev setup ───────────────────────────────────────────────────────────────

setup: ## Install development tools
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install golang.org/x/tools/cmd/goimports@latest

clean:
	rm -rf bin/

help: ## Display available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
