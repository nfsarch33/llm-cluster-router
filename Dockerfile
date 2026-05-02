FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /llm-cluster-router .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /llm-cluster-router /usr/local/bin/llm-cluster-router

EXPOSE 8080 9091
ENTRYPOINT ["llm-cluster-router"]
CMD ["serve", "-config", "/etc/llm-cluster-router/router.yml"]
