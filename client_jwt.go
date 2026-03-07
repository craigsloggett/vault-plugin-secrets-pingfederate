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

type pingFederateJWTClient struct {
	adminURL         string
	tokenURL         string
	clientID         string
	privateKeyPEM    string
	privateKeyID     string
	signingAlgorithm string
	httpClient       *http.Client
}

func newPingFederateJWTClient(cfg *pingFederateConfig) *pingFederateJWTClient {
	return &pingFederateJWTClient{
		adminURL:         strings.TrimRight(cfg.URL, "/"),
		tokenURL:         cfg.TokenURL,
		clientID:         cfg.ClientID,
		privateKeyPEM:    cfg.PrivateKey,
		privateKeyID:     cfg.PrivateKeyID,
		signingAlgorithm: cfg.SigningAlgorithm,
		httpClient:       &http.Client{},
	}
}

func (c *pingFederateJWTClient) setJWTAuth(req *http.Request, audience string) error {
	token, err := buildJWTAssertion(c.clientID, audience, c.privateKeyID, c.signingAlgorithm, c.privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to build JWT assertion: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func (c *pingFederateJWTClient) UpdateClientSecret(ctx context.Context, clientID string) (string, error) {
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

	if err := c.setJWTAuth(req, c.adminURL); err != nil {
		return "", err
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

// GetAccessToken obtains a bearer token using the target client's credentials.
// This uses Basic Auth with the target client's ID and secret, not the foothold's JWT.
func (c *pingFederateJWTClient) GetAccessToken(ctx context.Context, clientID, clientSecret string) (*AccessTokenResponse, error) {
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
