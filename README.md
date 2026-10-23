# PastureStack Kubernetes Authentication Bridge

Kubernetes Authentication Bridge validates Kubernetes `TokenReview` requests against the compatibility control plane and maps authenticated identities into Kubernetes user and group information.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/kubernetes-auth`](https://github.com/rancher/kubernetes-auth). This GitHub fork preserves the upstream Git history, authorship, dates, tags, and license notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Published release

The current [published release is v0.0.12](https://github.com/PastureStack/kubernetes-authentication-bridge/releases/tag/v0.0.12). Its user-facing image tag is:

```text
ghcr.io/pasturestack/kubernetes-authentication-bridge:v0.0.12
```

The exact producer `bff34a6be17711eba25a03a77c619ee4ee264fdd` was published by [run 39963092840](https://github.com/PastureStack/kubernetes-authentication-bridge/actions/runs/39963092840), with registry digest `sha256:bb6f0f9428bb97915f0a39aadd49026ebcb0f632a4a3102f0b727355fbf2789f`. This component publication does not deploy Server. After all required checks pass, the separate manual release workflow accepts a successful security-gate run and publishes only its checksum-verified runtime archive. Its source tree must match the annotated release tag, and an existing registry tag is never replaced. Existing historical releases remain immutable. Every new PastureStack build uses plain numeric semantic versions without a product or maintenance-count suffix.

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

## October 2026 security maintenance

Maintained Go builds select the patched Go 1.27.3 compiler without raising the existing Go language requirement. Ubuntu build/runtime stages apply the checksum-pinned `ca-certificates 20260816ubuntu0.26.04.1` security package after their frozen APT baseline; the final trust store and installed version are verified. Release artifacts must pass the repository's existing checks before publication.

## Full-severity security release

The compatible security release [v0.0.13](https://github.com/PastureStack/kubernetes-authentication-bridge/releases/tag/v0.0.13) is published. It retains the existing Go binary/API contract and shell-free, non-root runtime, and overlays the official Debian 12 tzdata 2026c-0+deb12u1 and ca-certificates 20250419~deb12u2 payloads. Package metadata is updated from the same verified packages; revoked roots are removed rather than merged back.

The published image records producer `c78969e9a8e7093e5f686231e83c4de11d70b7f1`
and manifest digest
`sha256:d68cbec22259e249f326b91f5cb13c4645f72d37a5769e04b0306f3408994fc2`.
The release tag points to `4beaa6574eac40f044bbdbe21f297d4c31d355ae`, whose source
tree matches that producer. See the [official publication](https://github.com/PastureStack/kubernetes-authentication-bridge/actions/runs/39974185280)
for artifact evidence; deployment acceptance remains separate.

The full-severity runtime gate rejects every finding with an official fix,
including LOW, MEDIUM and UNKNOWN. Only exact reviewed LOW/MEDIUM no-fix entries
may pass. Existing v0.0.12 remains published for provenance and is superseded by
v0.0.13.

### Complete build-environment gate

The Dapper scan retains all severities and requires nonempty package analysis for the expected Go binaries. Any available fixed version fails, including Low, Medium and Unknown findings. Other Low/Medium findings require an exact package/version/PURL entry backed by the official vendor tracker. The pinned userspace kernel-header exception additionally requires the reviewed CVE set, actual header payload paths, and absence of kernel images/modules; it never permits an available fix. Unknown module findings require the separately verified exact source package graph, not a generic severity exemption.
