FROM golang:1 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /mindgame ./cmd/mindgame/

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=builder /mindgame /usr/local/bin/mindgame
RUN mkdir /data
EXPOSE 2080 2180
ENTRYPOINT ["mindgame", "-db", "/data/audit.db", "-ca-dir", "/data"]
