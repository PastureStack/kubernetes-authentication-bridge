package platformauthentication

import (
	"fmt"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
)

type identity struct {
	ID             string `json:"id"`
	ExternalIDType string `json:"externalIdType"`
	Login          string `json:"login"`
	User           bool   `json:"user"`
}

type identityCollection struct {
	Data []identity `json:"data"`
}

type account struct {
	Kind string `json:"kind"`
}

type accountCollection struct {
	Data []account `json:"data"`
}

type settingResponse struct {
	Value string `json:"value"`
}

type project struct {
	ID string `json:"id"`
}

type projectCollection struct {
	Data []project `json:"data"`
}

type projectMember struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

type projectMemberCollection struct {
	Data []projectMember `json:"data"`
}

func getUserInfoFromIdentityCollection(collection *identityCollection) (authentication.UserInfo, bool) {
	var legacyIdentity identity
	var otherIdentity identity
	groups := make([]string, 0, len(collection.Data))
	for _, item := range collection.Data {
		if item.User {
			if item.ExternalIDType == "rancher_id" {
				legacyIdentity = item
			} else if otherIdentity.ID == "" {
				otherIdentity = item
			}
			continue
		}
		if item.ExternalIDType != "" && item.Login != "" {
			groups = appendUnique(groups, fmt.Sprintf("%s:%s", item.ExternalIDType, item.Login))
		}
	}

	selected := otherIdentity
	if selected.ID == "" {
		selected = legacyIdentity
	}
	if selected.ID == "" || selected.Login == "" {
		return authentication.UserInfo{}, false
	}
	return authentication.UserInfo{
		Username: selected.Login,
		UID:      selected.ID,
		Groups:   groups,
	}, true
}

func shouldBeAuthenticated(collection identityCollection, environmentIdentities map[string]projectMember) (bool, bool) {
	authenticated := false
	master := false
	for _, item := range collection.Data {
		if environmentIdentity, ok := environmentIdentities[item.ID]; ok {
			authenticated = true
			if environmentIdentity.Role == "owner" {
				master = true
				break
			}
		}
	}
	return authenticated, master
}
