FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH

COPY gcp-authcalator-linux-${TARGETARCH} /usr/local/bin/gcp-authcalator

ENTRYPOINT ["/usr/local/bin/gcp-authcalator"]
