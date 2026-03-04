package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

// Authenticate uses OIDC client credentials to authenticate to Keystone.
func Authenticate(ctx context.Context, client *gophercloud.ProviderClient, opts gophercloud.AuthOptions) error {
	if opts.DiscoveryEndpoint == "" {
		return fmt.Errorf("discoveryEndpoint is required for OIDC client credentials authentication")
	}
	if opts.ClientID == "" {
		return fmt.Errorf("clientID is required for OIDC client credentials authentication")
	}
	if opts.IdentityProvider == "" {
		return fmt.Errorf("identityProvider is required for OIDC client credentials authentication")
	}
	if opts.Protocol == "" {
		return fmt.Errorf("protocol is required for OIDC client credentials authentication")
	}

	// 1. Discover OIDC token endpoint
	tokenEndpoint, err := discoverTokenEndpoint(ctx, client, opts.DiscoveryEndpoint)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC token endpoint: %v", err)
	}

	// 2. Get OIDC token
	oidcToken, err := getOIDCToken(ctx, client, tokenEndpoint, opts)
	if err != nil {
		return fmt.Errorf("failed to get OIDC token: %v", err)
	}

	// 3. Authenticate with Keystone
	return authenticateWithKeystone(ctx, client, oidcToken, opts)
}

func discoverTokenEndpoint(ctx context.Context, client *gophercloud.ProviderClient, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery request failed with status %d", resp.StatusCode)
	}

	var discovery struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", err
	}

	if discovery.TokenEndpoint == "" {
		return "", fmt.Errorf("no token_endpoint found in discovery response")
	}

	return discovery.TokenEndpoint, nil
}

func getOIDCToken(ctx context.Context, client *gophercloud.ProviderClient, endpoint string, opts gophercloud.AuthOptions) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", opts.ClientID)
	if opts.ClientSecret != "" {
		data.Set("client_secret", opts.ClientSecret)
	}
	if opts.OpenIDScope != "" {
		data.Set("scope", opts.OpenIDScope)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}

	tokenType := opts.AccessTokenType
	if tokenType == "" {
		tokenType = "access_token"
	}

	token, ok := tokenResp[tokenType].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("could not find %s in token response", tokenType)
	}

	return token, nil
}

func authenticateWithKeystone(ctx context.Context, client *gophercloud.ProviderClient, oidcToken string, opts gophercloud.AuthOptions) error {
	v3Client, err := NewIdentityV3(client, gophercloud.EndpointOpts{})
	if err != nil {
		return err
	}

	url := federatedAuthURL(v3Client, opts.IdentityProvider, opts.Protocol)

	reqOpts := &gophercloud.RequestOpts{
		MoreHeaders: map[string]string{
			"Authorization": "Bearer " + oidcToken,
		},
	}

	var result tokens.CreateResult
	resp, err := v3Client.Post(ctx, url, nil, &result.Body, reqOpts)
	_, result.Header, result.Err = gophercloud.ParseResponse(resp, err)
	if result.Err != nil {
		return result.Err
	}

	if _, err := result.ExtractToken(); err != nil {
		return err
	}

	if _, err := result.ExtractServiceCatalog(); err != nil {
		return err
	}

	// Set the token and reauth function
	if err := client.SetTokenAndAuthResult(&result); err != nil {
		return err
	}

	client.ReauthFunc = func(ctx context.Context) error {
		return Authenticate(ctx, client, opts)
	}

	return nil
}

// ExtractServiceCatalog extracts the service catalog from an AuthResult.
func ExtractServiceCatalog(authResult gophercloud.AuthResult) (*tokens.ServiceCatalog, error) {
	if result, ok := authResult.(*tokens.CreateResult); ok {
		return result.ExtractServiceCatalog()
	}
	return nil, fmt.Errorf("AuthResult is not a tokens.CreateResult")
}

func NewIdentityV3(client *gophercloud.ProviderClient, opts gophercloud.EndpointOpts) (*gophercloud.ServiceClient, error) {
	return &gophercloud.ServiceClient{
		ProviderClient: client,
		Endpoint:       client.IdentityEndpoint,
		ResourceBase:   client.IdentityEndpoint,
	}, nil
}
