package pingfederate

import (
	"context"
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
	adminUsername    string
	adminPassword    string
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
		adminUsername:    cfg.AdminUsername,
		adminPassword:    cfg.AdminPassword,
		httpClient:       newHTTPClient(cfg.InsecureTLS),
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

	if c.adminUsername != "" && c.adminPassword != "" {
		req.SetBasicAuth(c.adminUsername, c.adminPassword)
	} else if err := c.setJWTAuth(req, c.adminURL); err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-XSRF-Header", "PingFederate")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to update client secret: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
	return getAccessToken(ctx, c.httpClient, c.tokenURL, clientID, clientSecret)
}

func (c *pingFederateJWTClient) HTTPClient() *http.Client {
	return c.httpClient
}
