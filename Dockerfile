# syntax=docker/dockerfile:1.6

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=docker

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/sentinel ./cmd/sentinel

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S sentinel && adduser -S sentinel -G sentinel
WORKDIR /app
COPY --from=builder --chown=sentinel:sentinel /out/sentinel .
RUN mkdir -p /app/data /app/rules.d && chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 9100
ENTRYPOINT ["./sentinel"]
CMD ["--config=/etc/sentinel/config.yaml"]
