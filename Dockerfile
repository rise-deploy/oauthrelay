# syntax=docker/dockerfile:1.7
FROM --platform=$TARGETPLATFORM rust:1.97.1-bookworm AS build
ARG TARGETARCH
RUN apt-get update \
    && apt-get install --yes --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=cargo-registry-$TARGETARCH,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-$TARGETARCH,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-$TARGETARCH,target=/src/target,sharing=locked \
    case "$(uname -m)" in \
      x86_64) target=x86_64-unknown-linux-musl ;; \
      aarch64) target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && rustup target add "$target" \
    && cargo build --locked --release --target "$target" -p oauthrelay \
    && cp "target/$target/release/oauthrelay" /oauthrelay

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /oauthrelay /oauthrelay
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/oauthrelay"]
