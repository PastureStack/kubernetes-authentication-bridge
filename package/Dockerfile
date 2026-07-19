FROM gcr.io/distroless/static-debian12@sha256:4b2a093ef4649bccd586625090a3c668b254cfe180dee54f4c94f3e9bd7e381e

ARG IMAGE_VERSION=dev
ARG SOURCE_REVISION=unknown

COPY ./kubernetes-authentication-bridge /usr/local/bin/kubernetes-authentication-bridge
COPY ./LICENSE ./SECURITY.md ./ORIGIN.md ./COMPATIBILITY.md /licenses/

LABEL org.opencontainers.image.title="pasturestack-kubernetes-authentication-bridge" \
      org.opencontainers.image.description="PastureStack Kubernetes authentication compatibility bridge" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/PastureStack/kubernetes-authentication-bridge" \
      io.pasturestack.compatibility.contract="legacy-kubernetes-tokenreview-v1beta1"

USER 65532:65532
EXPOSE 8080 10240
ENTRYPOINT ["/usr/local/bin/kubernetes-authentication-bridge"]
