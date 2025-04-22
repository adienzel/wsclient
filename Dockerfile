# Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o ws-client .

FROM alpine
WORKDIR /root/
COPY --from=builder /app/ws-client .
CMD ["./ws-client"]
