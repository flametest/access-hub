SHELL := /bin/bash
APP   := access-hub

.PHONY: help fmt lint build run migrate keys test tidy compose-up compose-down smoke

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-14s %s\n", $$1, $$2}'

fmt: ## go fmt ./...
	go fmt ./...

lint: ## golangci-lint run (auto-fix)
	golangci-lint run --verbose --fix

build: ## build server + migrate binaries
	CGO_ENABLED=1 go build -o bin/$(APP) ./cmd/$(APP)
	CGO_ENABLED=1 go build -o bin/$(APP)-migrate ./cmd/migrate

run: ## run the server with the dev config
	go run ./cmd/$(APP) --config deploy/server-config.yaml

migrate: ## apply migration/*.sql to the dev database
	go run ./cmd/migrate --config deploy/server-config.yaml --dir migration

keys: ## generate the RS256 keypair used for JWT signing (dev)
	@mkdir -p deploy/keys
	@if [ -f deploy/keys/private.pem ]; then echo "deploy/keys/private.pem already exists, skip"; else \
		openssl genrsa -out deploy/keys/private.pem 2048 2>/dev/null; \
		openssl rsa -in deploy/keys/private.pem -pubout -out deploy/keys/public.pem 2>/dev/null; \
		echo "wrote deploy/keys/{private,public}.pem"; \
	fi

test: ## run all Go tests
	go test ./...

tidy: ## go mod tidy
	go mod tidy

compose-up: ## start postgres + redis + mailhog (dev)
	docker compose up -d

compose-down: ## stop the dev stack
	docker compose down

smoke: ## end-to-end smoke against a running server on :8080
	@bash scripts/smoke.sh
