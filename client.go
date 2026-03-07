package pingfederate

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// newHTTPClient creates an HTTP client with optional TLS skip-verify.
func newHTTPClient(insecureTLS bool) *http.Client {
	if insecureTLS {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user-configured for self-signed certs
			},
		}
	}
	return &http.Client{}
}

// generateRandomSecret creates a cryptographically random 32-byte hex-encoded secret.
func generateRandomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// PingFederateClient defines the interface for interacting with PingFederate.
type PingFederateClient interface {
	// UpdateClientSecret rotates an OAuth client's secret via the admin API.
	// Generates a new secret, sets it in PingFederate, and returns the plaintext.
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

type pingFederateClient struct {
	adminURL             string
	tokenURL             string
	footholdClientID     string
	footholdClientSecret string
	adminUsername        string
	adminPassword        string
	httpClient           *http.Client
}

func newPingFederateClient(cfg *pingFederateConfig) *pingFederateClient {
	return &pingFederateClient{
		adminURL:             strings.TrimRight(cfg.URL, "/"),
		tokenURL:             cfg.TokenURL,
		footholdClientID:     cfg.ClientID,
		footholdClientSecret: cfg.ClientSecret,
		adminUsername:        cfg.AdminUsername,
		adminPassword:        cfg.AdminPassword,
		httpClient:           newHTTPClient(cfg.InsecureTLS),
	}
}

func (c *pingFederateClient) UpdateClientSecret(ctx context.Context, clientID string) (string, error) {
	newSecret, err := generateRandomSecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate new secret: %w", err)
	}

	reqURL := fmt.Sprintf("%s/pf-admin-api/v1/oauth/clients/%s/clientAuth/clientSecret",
		c.adminURL, url.PathEscape(clientID))

	payload := fmt.Sprintf(`{"secret":%q}`, newSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if c.adminUsername != "" && c.adminPassword != "" {
		req.SetBasicAuth(c.adminUsername, c.adminPassword)
	} else {
		req.SetBasicAuth(c.footholdClientID, c.footholdClientSecret)
	}
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

	return newSecret, nil
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
