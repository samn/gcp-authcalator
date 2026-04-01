FROM gcr.io/distroless/cc-debian12:nonroot

ARG TARGETARCH

COPY gcp-authcalator-linux-${TARGETARCH} /usr/local/bin/gcp-authcalator

RUN ["/usr/local/bin/gcp-authcalator", "--version"]

ENTRYPOINT ["/usr/local/bin/gcp-authcalator"]
