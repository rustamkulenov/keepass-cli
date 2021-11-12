FROM rust:1.55 as builder
WORKDIR /usr/src/keepass-cli
COPY . .
RUN cargo install --path .

FROM debian:buster-slim
#RUN apt-get update && apt-get install -y extra-runtime-dependencies && rm -rf /var/lib/apt/lists/*
RUN apt-get update && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/keepass-cli /usr/local/bin/keepass-cli
CMD ["keepass-cli"]