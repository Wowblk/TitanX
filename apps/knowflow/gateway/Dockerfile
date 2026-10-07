FROM golang:1.23-alpine AS build
WORKDIR /workspace

COPY gateway/go.mod gateway/go.sum ./
RUN go mod download

COPY gateway/ ./
RUN go build -o /out/mini-gateway ./cmd/gateway/main.go

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/mini-gateway /app/bin/mini-gateway
COPY gateway/config /app/config
COPY deploy/gateway-config.yaml /app/config/config.yaml

EXPOSE 8380
CMD ["/app/bin/mini-gateway"]

