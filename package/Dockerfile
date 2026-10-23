# syntax=docker/dockerfile:1.7
FROM gcr.io/distroless/static-debian12@sha256:4b2a093ef4649bccd586625090a3c668b254cfe180dee54f4c94f3e9bd7e381e AS original-runtime
FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b AS security-rootfs
COPY --from=original-runtime / /rootfs/
ADD --checksum=sha256:c6bdac9aa03e89a112c8d900cb60321889cfec535e0397b74383bd10c8b3cb44 https://security.debian.org/debian-security/pool/updates/main/t/tzdata/tzdata_2026c-0+deb12u1_all.deb /tmp/tzdata.deb
ADD --checksum=sha256:b9f76b5271a7ac373fd5e7e1b5b826a71ddd702b42a0d104955ecb1acfffc94b https://security.debian.org/debian-security/pool/updates/main/c/ca-certificates/ca-certificates_20250419~deb12u2_all.deb /tmp/ca-certificates.deb
# Update actual package payloads and their installed metadata together.
# Only this build-owned rootfs is changed; no shell/package manager enters the runtime.
RUN set -eux; \
    test "$(dpkg-deb -f /tmp/tzdata.deb Version)" = '2026c-0+deb12u1'; \
    test "$(dpkg-deb -f /tmp/ca-certificates.deb Version)" = '20250419~deb12u2'; \
    rm -rf /rootfs/etc/ssl/certs /rootfs/usr/share/ca-certificates; \
    for package in tzdata ca-certificates; do \
        test "$(dpkg-deb -f "/tmp/$package.deb" Package)" = "$package"; \
        status_file=$(grep -l "^Package: $package$" /rootfs/var/lib/dpkg/status.d/* || true); \
        if [ "$package" = ca-certificates ] && [ -z "$status_file" ]; then \
            status_file=/rootfs/var/lib/dpkg/status.d/ca-certificates; \
            touch "$status_file"; \
        fi; \
        test "$(printf '%s\n' "$status_file" | wc -l)" -eq 1; \
        test -f "$status_file"; \
        dpkg-deb --extract "/tmp/$package.deb" /rootfs; \
        { dpkg-deb --field "/tmp/$package.deb"; printf 'Status: install ok installed\n'; } > "$status_file"; \
    done; \
    mkdir -p /rootfs/etc/ssl/certs; \
    find /rootfs/usr/share/ca-certificates -type f -name '*.crt' | LC_ALL=C sort | \
        while IFS= read -r certificate; do \
            sed -e '$a\' "$certificate"; \
            name=$(basename "$certificate" .crt); \
            ln -s "${certificate#/rootfs}" "/rootfs/etc/ssl/certs/$name.pem"; \
        done > /rootfs/etc/ssl/certs/ca-certificates.crt; \
    test -s /rootfs/etc/ssl/certs/ca-certificates.crt; \
    test ! -e /rootfs/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt; \
    test ! -e /rootfs/usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt; \
    test ! -e /rootfs/bin/sh; \
    test ! -e /rootfs/usr/bin/apt-get

FROM scratch
COPY --from=security-rootfs /rootfs/ /
# Preserve original-runtime configuration (verified from its immutable config).
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /

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
