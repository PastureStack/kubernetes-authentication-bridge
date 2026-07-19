package testauthentication

import (
	"context"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
)

var (
	testUserInfo = map[string]authentication.UserInfo{
		"test1": {
			Username: "test1",
		},
		"test2": {
			Username: "test2",
		},
		"test3": {
			Username: "test3",
		},
		"admin": {
			Username: "admin",
		},
	}
)

type Provider struct{}

func (p *Provider) Lookup(_ context.Context, token string) (*authentication.UserInfo, error) {
	userInfo, ok := testUserInfo[token]
	if !ok {
		return nil, nil
	}
	return &userInfo, nil
}
