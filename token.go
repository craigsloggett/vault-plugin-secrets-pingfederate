package pingfederate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// getBrokeredToken authenticates to PingFederate's token endpoint as the
// foothold client, enriching the request with Vault identity context.
// This is a standard OAuth 2.0 client_credentials request — not an admin API call.
func getBrokeredToken(ctx context.Context, httpClient *http.Client, cfg *pingFederateConfig, scope string, entityID string, metadata map[string]string) (*AccessTokenResponse, error) {
	data := url.Values{
		"grant_type":      {"client_credentials"},
		"vault_entity_id": {entityID},
	}

	if scope != "" {
		data.Set("scope", scope)
	}

	for k, v := range metadata {
		data.Set(k, v)
	}

	var useBasicAuth bool

	switch cfg.AuthMethod {
	case "", "client_secret":
		useBasicAuth = true
	case "private_key_jwt":
		assertion, err := buildJWTAssertion(cfg.ClientID, cfg.TokenURL, cfg.PrivateKeyID, cfg.SigningAlgorithm, cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to build JWT assertion: %w", err)
		}
		data.Set("client_id", cfg.ClientID)
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", assertion)
	default:
		return nil, fmt.Errorf("unsupported auth_method: %s", cfg.AuthMethod)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if useBasicAuth {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request brokered token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PingFederate token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}
