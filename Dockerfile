FROM docker.io/node:17-alpine AS npm

WORKDIR /src
ADD static/dist /src
RUN npm ci

FROM docker.io/rust:1.59-alpine AS builder
MAINTAINER Dominik Süß <dominik@suess.wtf>
WORKDIR /usr/src/laada

RUN apk add --no-cache pkgconfig openssl-dev musl-dev
# == Build dependencies without our own code separately for caching ==
#
# Need a fake main.rs since Cargo refuses to build anything otherwise.
#
# See https://github.com/rust-lang/cargo/issues/2644 for a Cargo feature
# request that would allow just dependencies to be compiled, presumably
# regardless of whether source files are available.
RUN mkdir src && echo 'fn main() {}' > src/main.rs
ENV RUSTFLAGS="-C target-feature=-crt-static"
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release && rm -r src
ADD static static
COPY --from=npm /src/node_modules static/dist/
ADD src src
RUN touch src/main.rs && cargo build --release

FROM docker.io/alpine:3.15
RUN apk add --no-cache libgcc
COPY --from=builder /usr/src/laada/target/release/laada /bin/laada
ENV RUST_LOG=laada=debug
ENTRYPOINT ["/bin/laada"]
