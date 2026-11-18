# Copyright 2026 Beacon Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o beacon-push ./cmd/beacon-push

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 push && adduser -S -D -H -u 10001 -G push push \
 && mkdir -p /data && chown push:push /data
COPY --from=builder /app/beacon-push /usr/local/bin/beacon-push
USER push
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["beacon-push", "healthcheck"]
CMD ["beacon-push"]
