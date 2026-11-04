FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fimagent ./cmd/fimagent

FROM debian:bookworm-slim
COPY --from=build /out/fimagent /usr/local/bin/fimagent
COPY docker/agent-entrypoint.sh /usr/local/bin/agent-entrypoint.sh
RUN chmod +x /usr/local/bin/agent-entrypoint.sh && mkdir -p /var/lib/fimagent && chmod 700 /var/lib/fimagent
ENV FIM_CONFIG=/etc/fimagent/config.yaml
ENTRYPOINT ["/usr/local/bin/agent-entrypoint.sh"]
CMD ["watch"]
