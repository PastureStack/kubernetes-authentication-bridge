# Compatibility Contract

The migration preserves the Kubernetes `authentication.k8s.io/v1beta1` `TokenReview` request and response shape, bootstrap-token behavior, identity and project-membership lookup flow, Kubernetes `system:masters` mapping, certificate-action bootstrap, and the separate health endpoint.

Preferred settings use `PLATFORM_URL`, `PLATFORM_ACCESS_KEY`, `PLATFORM_SECRET_KEY`, `PLATFORM_METADATA_ADDRESS`, and `PLATFORM_CA_ROOT`. Historical settings remain temporary aliases so credentials and application behavior do not have to change in the same rollout.

The CA setting now selects only the managed container mount at `/var/lib/pasturestack/etc/ssl/ca.crt` or its historical compatibility mount. Operators using a private CA keep the same trust behavior by mounting the PEM bundle at the managed location; arbitrary filesystem paths are intentionally rejected.

The generated control-plane client and old Kubernetes client are replaced by minimal internal JSON contracts that retain the same API field names: `identity`, `account`, `project`, `projectMember`, and `setting`. The inherited `rancher_id` identity discriminator is a stored protocol value and is not renamed. An empty project list now fails closed instead of panicking.

The operator-configured control-plane and metadata addresses remain compatible with HTTP or HTTPS, IP addresses, DNS names, ports, and the existing control-plane base path. Their exact normalized origins are bound to the outbound client and checked again immediately before the network transport runs. This prevents a compromised action response, Host override, redirect, proxy setting, or credential-bearing metadata request from changing the destination.

Candidate `0.0.12` changes the webhook listener from privileged port `80` to non-root port `8080`. A matching Catalog revision must set `AUTHENTICATION_BRIDGE_URL=http://platform-kubernetes-authentication:8080`; historical Catalog revisions are not modified. The health endpoint remains `GET /healthcheck` on port `10240`.

Operator messages support `en-US` and `zh-TW`. TokenReview JSON, tokens, identity values, usernames, groups, and protocol errors are never translated.

Before release, validate bootstrap, disabled-auth, administrator, owner, member, unauthorized, malformed base64, oversized request, redirect rejection, archive traversal, duplicate or invalid key material, redaction, custom CA trust, non-root read-only Runtime, health isolation, graceful shutdown, and a real Kubernetes 1.12 TokenReview round trip against the exact candidate.
