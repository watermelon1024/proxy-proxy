# syntax=docker/dockerfile:1

# Build on the runner's own platform and cross-compile: compiling under QEMU emulation is many times slower.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/proxy-proxy .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H -u 65532 proxyproxy
COPY --from=build /out/proxy-proxy /usr/local/bin/proxy-proxy

# Mount your config (ideally its whole directory, see README) here.
ENV PP_CONFIG=/etc/proxy-proxy/proxy-proxy.yaml

USER proxyproxy
EXPOSE 8080
# Checks the default port; if you override listen/PP_LISTEN, adjust or disable.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["proxy-proxy"]
