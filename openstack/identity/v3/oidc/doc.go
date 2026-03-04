/*
Package oidc provides support for OpenID Connect (OIDC) authentication
methods, specifically the Client Credentials grant type.

# Authentication via OIDC Client Credentials

This method allows a machine or service to authenticate using a client ID
and secret against an OIDC provider, obtain an access token or ID token,
and then exchange that token for an OpenStack Keystone token.

# Example Usage

	import (
		"context"

		"github.com/gophercloud/gophercloud/v2"
		"github.com/gophercloud/gophercloud/v2/openstack"
		"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
	)

	// Configure authentication options
	opts := gophercloud.AuthOptions{
		IdentityEndpoint:  "https://keystone.example.org:5000/v3",
		IdentityProvider:  "my-idp",
		Protocol:          "openid",
		DiscoveryEndpoint: "https://oidc.example.org/.well-known/openid-configuration",
		ClientID:          "my-client-id",
		ClientSecret:      "my-client-secret",
		AccessTokenType:   "access_token",
		OpenIDScope:       "openid profile email",
	}

	// Create a provider client and authenticate
	provider, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		panic(err)
	}

	err = oidc.Authenticate(context.TODO(), provider, opts)
	if err != nil {
		panic(err)
	}
*/
package oidc
