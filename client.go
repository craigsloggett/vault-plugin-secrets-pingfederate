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

// PingFederateClient defines the interface for interacting with PingFederate.
type PingFederateClient interface {
	// GetClientSecret retrieves an OAuth client's secret via the admin API.
	GetClientSecret(ctx context.Context, clientID string) (string, error)

	// UpdateClientSecret rotates an OAuth client's secret via the admin API.
	// Returns the new plaintext secret.
	UpdateClientSecret(ctx context.Context, clientID string) (string, error)

	// GetAccessToken obtains a bearer token via the client_credentials grant.
	GetAccessToken(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error)
}

// AccessTokenResponse represents the OAuth 2.0 token endpoint response.
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// clientSecretResponse represents the PingFederate admin API client secret response.
type clientSecretResponse struct {
	Secret          string `json:"secret,omitempty"`
	EncryptedSecret string `json:"encryptedSecret,omitempty"`
}

type pingFederateClient struct {
	adminURL             string
	tokenURL             string
	footholdClientID     string
	footholdClientSecret string
	httpClient           *http.Client
}

func newPingFederateClient(cfg *pingFederateConfig) *pingFederateClient {
	return &pingFederateClient{
		adminURL:             strings.TrimRight(cfg.URL, "/"),
		tokenURL:             cfg.TokenURL,
		footholdClientID:     cfg.ClientID,
		footholdClientSecret: cfg.ClientSecret,
		httpClient:           &http.Client{},
	}
}

func (c *pingFederateClient) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	reqURL := fmt.Sprintf("%s/pf-admin-api/v1/oauth/clients/%s/clientAuth/clientSecret",
		c.adminURL, url.PathEscape(clientID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.footholdClientID, c.footholdClientSecret)
	req.Header.Set("X-XSRF-Header", "PingFederate")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get client secret: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PingFederate admin API returned %d: %s", resp.StatusCode, string(body))
	}

	var secretResp clientSecretResponse
	if err := json.Unmarshal(body, &secretResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if secretResp.Secret == "" {
		return "", fmt.Errorf("PingFederate returned empty secret for client %s (may only have encrypted secret)", clientID)
	}

	return secretResp.Secret, nil
}

func (c *pingFederateClient) UpdateClientSecret(ctx context.Context, clientID string) (string, error) {
	reqURL := fmt.Sprintf("%s/pf-admin-api/v1/oauth/clients/%s/clientAuth/clientSecret",
		c.adminURL, url.PathEscape(clientID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader("{}"))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.footholdClientID, c.footholdClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-XSRF-Header", "PingFederate")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to update client secret: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PingFederate admin API returned %d: %s", resp.StatusCode, string(body))
	}

	var secretResp clientSecretResponse
	if err := json.Unmarshal(body, &secretResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if secretResp.Secret == "" {
		return "", fmt.Errorf("PingFederate returned empty secret after rotation for client %s", clientID)
	}

	return secretResp.Secret, nil
}

func (c *pingFederateClient) GetAccessToken(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error) {
	data := url.Values{
		"grant_type": {"client_credentials"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
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
