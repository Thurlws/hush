# hushd in a container. docker compose up -d, then open http://localhost:8080
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libsodium-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src src
COPY web web
RUN make && make install PREFIX=/opt/hush

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libsodium23 libsqlite3-0 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /data --create-home --shell /usr/sbin/nologin hush
COPY --from=build /opt/hush /opt/hush
USER hush
WORKDIR /data
VOLUME /data
EXPOSE 7777 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=1s CMD curl -fs http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/opt/hush/bin/hushd", "-C", "/data"]
