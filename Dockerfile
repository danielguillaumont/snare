# syntax=docker/dockerfile:1
# Snare server image: static binary on distroless, non-root, nothing else in the image.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# modernc.org/sqlite is pure Go, so CGO stays off and the binary is fully static.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/snare ./cmd/snare \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/snare /usr/local/bin/snare
COPY --from=build --chown=65532:65532 /out/data /data
ENV SNARE_DB=/data/snare.db \
    SNARE_HTTP_ADDR=:8080 \
    SNARE_ADMIN_ADDR=:8081 \
    SNARE_DASHBOARD_ADDR=:8090 \
    SNARE_DNS_ADDR=:5353
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080 8081 8090 5353/udp 5353/tcp
ENTRYPOINT ["/usr/local/bin/snare"]
CMD ["serve"]
