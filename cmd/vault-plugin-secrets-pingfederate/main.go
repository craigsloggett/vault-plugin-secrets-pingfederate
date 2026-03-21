package main

import (
	"log"
	"os"

	pingfederate "github.com/craigsloggett/vault-plugin-secrets-pingfederate/plugin"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: pingfederate.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Fatalf("plugin shutting down: %v", err)
	}
}
