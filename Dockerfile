# Multi-stage build, mirrors taskd's Dockerfile.
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-hub ./cmd/access-hub && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-hub-migrate ./cmd/migrate

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/access-hub /app/access-hub
COPY --from=builder /out/access-hub-migrate /app/access-hub-migrate
COPY deploy/server-config.yaml /etc/access-hub/server-config.yaml
EXPOSE 8080
ENTRYPOINT ["/app/access-hub", "--config", "/etc/access-hub/server-config.yaml"]
