FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /mindgame ./cmd/mindgame/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /mindgame /usr/local/bin/mindgame
RUN mkdir /data
EXPOSE 8080 9090
ENTRYPOINT ["mindgame", "-db", "/data/audit.db", "-ca-dir", "/data"]
