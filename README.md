# PastureStack Kubernetes Authentication Bridge

Kubernetes Authentication Bridge validates Kubernetes `TokenReview` requests against the compatibility control plane and maps authenticated identities into Kubernetes user and group information.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/kubernetes-auth`](https://github.com/rancher/kubernetes-auth). This GitHub fork preserves the upstream Git history, authorship, dates, tags, and license notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Candidate

The reviewed numeric candidate is `0.0.12`. If publication is separately approved, its image tag will be:

```text
ghcr.io/pasturestack/kubernetes-authentication-bridge:v0.0.12
```

The source review does not publish or deploy that image. Existing historical releases remain immutable. Every new PastureStack build uses plain numeric semantic versions without a product or maintenance-count suffix.

The Runtime is a static, standard-library-only Go binary in a digest-pinned distroless image. It runs as UID/GID `65532`, contains no shell or package manager, follows no HTTP redirect while carrying credentials, applies bounded request and archive limits, and logs only bounded token fingerprints when debug mode is explicitly enabled. The old vendored CLI, logging, Kubernetes client, and generated control-plane client trees are no longer part of the active source or artifact.

## Configuration

Preferred settings are `PLATFORM_URL`, `PLATFORM_ACCESS_KEY`, `PLATFORM_SECRET_KEY`, `PLATFORM_METADATA_ADDRESS`, and `PLATFORM_CA_ROOT`. Historical `CATTLE_*`, metadata-address, and CA-path names remain temporary compatibility aliases.

`PLATFORM_CA_ROOT`, when set, must select the managed mount at `/var/lib/pasturestack/etc/ssl/ca.crt` or its historical compatibility mount. To use a private CA, mount its PEM bundle at the managed path rather than granting this process access to an arbitrary host path.

The process retrieves the Kubernetes service certificate action through the existing metadata and control-plane APIs, reconstructs the download URL from the operator-configured control-plane origin, and enforces the exact approved origin again at the final network transport boundary. Redirects, ambient proxies, Host overrides, and cross-origin credential delivery are rejected. The process validates a bounded ZIP archive entirely in memory and derives the bootstrap token from the validated PEM private key. Control-plane credentials are never sent to the metadata endpoint. No certificate archive or private key is written to the container filesystem.

The non-root webhook listens on port `8080`; the health check remains on port `10240`. A matching Kubernetes package or Catalog revision must set:

```text
AUTHENTICATION_BRIDGE_URL=http://platform-kubernetes-authentication:8080
```

Set `PASTURESTACK_LOCALE=en-US` or `PASTURESTACK_LOCALE=zh-TW` for operator messages. TokenReview JSON, identity values, usernames, group names, and protocol errors remain language-neutral.

## Build and test

Run from a Docker-capable Linux host:

```sh
make validate
make test
make build VERSION_OVERRIDE=0.0.12
make package VERSION_OVERRIDE=0.0.12 TAG=v0.0.12 \
  IMAGE_NAME=pasturestack/kubernetes-authentication-bridge
```

The package target creates a local image only. See [COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and [ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
