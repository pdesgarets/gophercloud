package testing

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestAuthenticate(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	// Mock OIDC Discovery
	fakeServer.Mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token_endpoint": "%stoken"}`, fakeServer.Endpoint())
	})

	// Mock OIDC Token
	fakeServer.Mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "POST")
		th.TestFormValues(t, r, map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     "my-client",
			"client_secret": "my-secret",
			"scope":         "openid profile",
		})
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "oidc-access-token"}`)
	})

	// Mock Keystone Federated Auth
	fakeServer.Mux.HandleFunc("/auth/OS-FEDERATION/identity_providers/my-idp/protocols/openid/auth", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "POST")
		th.TestHeader(t, r, "Authorization", "Bearer oidc-access-token")

		w.Header().Add("X-Subject-Token", "keystone-token")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{
			"token": {
				"expires_at": "2014-10-02T13:45:00.000000Z",
				"catalog": []
			}
		}`)
	})

	client := &gophercloud.ProviderClient{
		HTTPClient:       http.Client{},
		IdentityEndpoint: fakeServer.Endpoint(),
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint:  fakeServer.Endpoint(),
		IdentityProvider:  "my-idp",
		Protocol:          "openid",
		DiscoveryEndpoint: fakeServer.Endpoint() + ".well-known/openid-configuration",
		ClientID:          "my-client",
		ClientSecret:      "my-secret",
		OpenIDScope:       "openid profile",
	}

	err := oidc.Authenticate(context.TODO(), client, opts)
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "keystone-token", client.TokenID)
}

func TestAuthenticateIDToken(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	// Mock OIDC Discovery
	fakeServer.Mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token_endpoint": "%stoken"}`, fakeServer.Endpoint())
	})

	// Mock OIDC Token
	fakeServer.Mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "POST")
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, `{"id_token": "oidc-id-token"}`)
	})

	// Mock Keystone Federated Auth
	fakeServer.Mux.HandleFunc("/auth/OS-FEDERATION/identity_providers/my-idp/protocols/openid/auth", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "POST")
		th.TestHeader(t, r, "Authorization", "Bearer oidc-id-token")

		w.Header().Add("X-Subject-Token", "keystone-token")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token": {"expires_at": "2014-10-02T13:45:00.000000Z"}}`)
	})

	client := &gophercloud.ProviderClient{
		HTTPClient:       http.Client{},
		IdentityEndpoint: fakeServer.Endpoint(),
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint:  fakeServer.Endpoint(),
		IdentityProvider:  "my-idp",
		Protocol:          "openid",
		DiscoveryEndpoint: fakeServer.Endpoint() + ".well-known/openid-configuration",
		ClientID:          "my-client",
		AccessTokenType:   "id_token",
	}

	err := oidc.Authenticate(context.TODO(), client, opts)
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "keystone-token", client.TokenID)
}
