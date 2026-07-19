# Security Policy

## Supported state

The numeric `0.0.12` candidate is review-only until the exact source commit, Runtime image, Kubernetes 1.12 TokenReview integration, source secret scan, reachable Go vulnerability analysis, Runtime scan, build-environment scan, SBOM, and reproducibility checks all pass. Source review does not authorize a Release, registry push, Catalog update, or deployment.

The candidate must not enter a Catalog until its matching Kubernetes package sets the non-root webhook URL and the complete isolated stack passes. Existing suffix-bearing historical artifacts are immutable compatibility records, not names for new builds.

## Security boundaries

- Raw and decoded tokens must never be logged. Debug mode may log only bounded fingerprints.
- TokenReview request bodies and upstream identity responses are size-limited and time-bounded.
- Unauthorized, malformed, redirected, and oversized requests fail closed without exposing token material.
- Service credentials and decoded authorization values are sent only to the configured control-plane origin. An exact scheme, host, and port allowlist is enforced immediately before every network exchange; redirects, ambient proxies, and Host overrides are disabled.
- Certificate bootstrap accepts only the same origin, a bounded archive, safe paths, an exact file allowlist, and one valid PEM private key. Private material remains in memory.
- TLS clients require TLS 1.2 or later and may add only an explicitly supplied PEM root to the system trust pool.
- Webhook and health listeners use separate HTTP muxes, explicit timeouts, and graceful shutdown.
- The Runtime is a standard-library-only static binary in a digest-pinned distroless image, runs as UID/GID `65532`, and needs no Linux capability, shell, package manager, or writable root filesystem.
- No API key, bootstrap token, certificate, private endpoint, or identity response may be committed or uploaded as evidence.
- Outbound metadata and control-plane requests must pass the final transport-layer origin policy, keep their configured origins, avoid redirects and ambient proxies, reject Host overrides, and never send control-plane credentials to metadata.
- Private CA material may be read only from the managed container mount. Configuration must not select an arbitrary host path.
- Publication is blocked by any applicable Critical or High Runtime finding, detected source or Runtime secret, reachable Go vulnerability, unreviewed build-environment finding, non-reproducible binary, or failed Kubernetes 1.12 TokenReview round trip.

The candidate's build-environment OpenVEX file is intentionally narrow. It lists each observed Critical or High finding separately and is accepted only when its vulnerability-and-package pairs exactly match the raw scan. The statements cover Linux kernel code represented by the header-only `linux-libc-dev` package and daemon-only Moby authorization or container-copy paths reported against the client-only Buildx plugin. New, removed, unmatched, or unexplained findings fail the gate instead of being silently ignored.

## Reporting

Report suspected vulnerabilities through this repository's private security advisory channel. Do not include live tokens, credentials, or identity data in a public issue.
