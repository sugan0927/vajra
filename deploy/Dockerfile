# docker build -f deploy/Dockerfile -t vajra .
FROM rust:1.82-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --no-create-home vajra
COPY --from=build /src/target/release/vajra /usr/local/bin/vajra
COPY vajra.toml /etc/vajra/vajra.toml
COPY public /var/www
USER vajra
EXPOSE 8080/tcp 8443/tcp 8443/udp
# io_uring is blocked by Docker's default seccomp profile on some releases. If the server
# reports "io_uring setup failed", run with:  --security-opt seccomp=unconfined  (or a profile allowing io_uring_*)
ENTRYPOINT ["/usr/local/bin/vajra", "--config", "/etc/vajra/vajra.toml"]
