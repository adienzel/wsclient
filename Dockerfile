# Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o ws-client .

FROM alpine
WORKDIR /root/
COPY --from=builder /app/ws-client .

ENV SERVER_ADDR: "example.com"
ENV START_PORT: "443"
ENV PORT_COUNT: "1"
ENV NUM_CLIENTS: "10"
ENV MESSAGES_PER_CLIENT: "100"
ENV MESSAGES_PER_SECOND: "4"
ENV CLIENT_CERT: "/certs/client.crt"
ENV CLIENT_KEY: "/certs/client.key"
ENV CA_CERT: "/certs/ca.crt"
ENV PROM_PUSHGATEWAY_URL: "http://localhost:9091"

CMD ["./ws-client"]
