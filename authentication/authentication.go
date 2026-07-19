package authentication

import "context"

// UserInfo is the language-neutral identity returned to the Kubernetes
// TokenReview webhook. It intentionally contains only the fields used by the
// compatibility contract.
type UserInfo struct {
	Username string
	UID      string
	Groups   []string
}

type Provider interface {
	Lookup(ctx context.Context, token string) (*UserInfo, error)
}
