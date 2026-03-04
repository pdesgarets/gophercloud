package oidc

import "github.com/gophercloud/gophercloud/v2"

const (
	rootPath       = "auth"
	federationPath = "OS-FEDERATION"
	idpPath        = "identity_providers"
	protocolsPath  = "protocols"
	authPath       = "auth"
)

func federatedAuthURL(c *gophercloud.ServiceClient, idp, protocol string) string {
	return c.ServiceURL(rootPath, federationPath, idpPath, idp, protocolsPath, protocol, authPath)
}
