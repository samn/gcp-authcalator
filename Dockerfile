# Lightweight image containing only the compiled gcp-authcalator binary on a
# minimal distroless base (no shell, no package manager). Published multi-arch
# (linux/amd64, linux/arm64) to ghcr.io/samn/gcp-authcalator on every release.
FROM gcr.io/distroless/cc-debian12:nonroot

ARG TARGETARCH

# Container user. Override at build time with
#   --build-arg CONTAINER_USER=<name|uid[:gid]>
# to match the user a devcontainer expects, or override at run time with
#   docker run --user <uid[:gid]>
# The distroless base only ships the `root` (0) and `nonroot` (65532) accounts,
# so a name must be one of those; any other value must be a numeric uid[:gid].
# Defaults to the unprivileged nonroot user (uid 65532).
ARG CONTAINER_USER=nonroot

COPY gcp-authcalator-linux-${TARGETARCH} /usr/local/bin/gcp-authcalator

USER ${CONTAINER_USER}

# Smoke-test that the selected user can execute the binary.
RUN ["/usr/local/bin/gcp-authcalator", "--version"]

ENTRYPOINT ["/usr/local/bin/gcp-authcalator"]
