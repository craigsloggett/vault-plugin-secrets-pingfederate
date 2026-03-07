//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// ---------------------------------------------------------------------------
// Config CRUD
// ---------------------------------------------------------------------------

func TestIntegration_ConfigWrite_ClientSecret(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	writePluginConfig(t, client, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	secret := readPluginConfig(t, client)
	if secret == nil {
		t.Fatal("expected config, got nil")
	}

	if v := requireField(t, secret.Data, "client_id"); v != "vault-foothold-secret" {
		t.Errorf("client_id = %q, want %q", v, "vault-foothold-secret")
	}
	if v := requireField(t, secret.Data, "auth_method"); v != "client_secret" {
		t.Errorf("auth_method = %q, want %q", v, "client_secret")
	}
	if v := requireField(t, secret.Data, "url"); v != pfAdminURL {
		t.Errorf("url = %q, want %q", v, pfAdminURL)
	}
	if v := requireField(t, secret.Data, "token_url"); v != pfTokenURL {
		t.Errorf("token_url = %q, want %q", v, pfTokenURL)
	}
}

func TestIntegration_ConfigWrite_PrivateKeyJWT_InternalKey(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	writePluginConfig(t, client, map[string]any{
		"client_id":   "vault-foothold-jwt",
		"auth_method": "private_key_jwt",
		"url":         pfAdminURL,
		"token_url":   pfTokenURL,
	})

	secret := readPluginConfig(t, client)
	if secret == nil {
		t.Fatal("expected config, got nil")
	}

	if v := requireField(t, secret.Data, "auth_method"); v != "private_key_jwt" {
		t.Errorf("auth_method = %q, want %q", v, "private_key_jwt")
	}
	if v := requireField(t, secret.Data, "key_source"); v != "internal" {
		t.Errorf("key_source = %q, want %q", v, "internal")
	}
	if v := requireField(t, secret.Data, "signing_algorithm"); v != "RS256" {
		t.Errorf("signing_algorithm = %q, want %q", v, "RS256")
	}
	kid := requireField(t, secret.Data, "private_key_id")
	if kid == "" {
		t.Error("private_key_id should not be empty")
	}
}

func TestIntegration_ConfigWrite_PrivateKeyJWT_ExternalKey(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	// Generate an EC key to provide externally.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	writePluginConfig(t, client, map[string]any{
		"client_id":         "vault-foothold-jwt",
		"auth_method":       "private_key_jwt",
		"signing_algorithm": "ES256",
		"private_key":       string(keyPEM),
		"url":               pfAdminURL,
		"token_url":         pfTokenURL,
	})

	secret := readPluginConfig(t, client)
	if secret == nil {
		t.Fatal("expected config, got nil")
	}

	if v := requireField(t, secret.Data, "key_source"); v != "external" {
		t.Errorf("key_source = %q, want %q", v, "external")
	}
	if v := requireField(t, secret.Data, "signing_algorithm"); v != "ES256" {
		t.Errorf("signing_algorithm = %q, want %q", v, "ES256")
	}
}

func TestIntegration_ConfigUpdate_PartialFields(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	// Write initial config.
	writePluginConfig(t, client, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"default_ttl":   300,
	})

	// Update only default_ttl.
	writePluginConfig(t, client, map[string]any{
		"default_ttl": 600,
	})

	secret := readPluginConfig(t, client)
	if secret == nil {
		t.Fatal("expected config, got nil")
	}

	// Verify updated field.
	ttl, ok := secret.Data["default_ttl"]
	if !ok {
		t.Fatal("expected default_ttl in response")
	}
	ttlNum, ok := ttl.(json.Number)
	if !ok {
		t.Fatalf("default_ttl type = %T, want json.Number", ttl)
	}
	if ttlNum.String() != "600" {
		t.Errorf("default_ttl = %s, want 600", ttlNum.String())
	}

	// Verify other fields retained.
	if v := requireField(t, secret.Data, "client_id"); v != "vault-foothold-secret" {
		t.Errorf("client_id = %q, want %q (should be retained)", v, "vault-foothold-secret")
	}
}

func TestIntegration_ConfigDelete(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)

	// Write config.
	writePluginConfig(t, client, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	// Delete.
	deletePluginConfig(t, client)

	// Read should return nil.
	secret := readPluginConfig(t, client)
	if secret != nil {
		t.Errorf("expected nil after delete, got: %+v", secret.Data)
	}
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

func TestIntegration_JWKS_EmptyWithClientSecret(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	writePluginConfig(t, client, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	secret, err := client.Logical().Read(pluginPath + "/jwks")
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if secret == nil {
		t.Fatal("expected JWKS response, got nil")
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		t.Fatal("expected 'keys' in JWKS response")
	}
	keysSlice, ok := keysRaw.([]any)
	if !ok {
		t.Fatalf("keys type = %T, want []any", keysRaw)
	}
	if len(keysSlice) != 0 {
		t.Errorf("expected empty keys array, got %d keys", len(keysSlice))
	}
}

func TestIntegration_JWKS_ReturnsKeyWithPrivateKeyJWT(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	writePluginConfig(t, client, map[string]any{
		"client_id":   "vault-foothold-jwt",
		"auth_method": "private_key_jwt",
		"url":         pfAdminURL,
		"token_url":   pfTokenURL,
	})

	// Read the config to get the kid.
	cfg := readPluginConfig(t, client)
	expectedKID := requireField(t, cfg.Data, "private_key_id")

	secret, err := client.Logical().Read(pluginPath + "/jwks")
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if secret == nil {
		t.Fatal("expected JWKS response, got nil")
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		t.Fatal("expected 'keys' in JWKS response")
	}
	keysSlice, ok := keysRaw.([]any)
	if !ok {
		t.Fatalf("keys type = %T, want []any", keysRaw)
	}
	if len(keysSlice) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keysSlice))
	}

	key, ok := keysSlice[0].(map[string]any)
	if !ok {
		t.Fatalf("key type = %T, want map[string]any", keysSlice[0])
	}
	if kid, _ := key["kid"].(string); kid != expectedKID {
		t.Errorf("kid = %q, want %q", kid, expectedKID)
	}
	if alg, _ := key["alg"].(string); alg != "RS256" {
		t.Errorf("alg = %q, want %q", alg, "RS256")
	}
	if use, _ := key["use"].(string); use != "sig" {
		t.Errorf("use = %q, want %q", use, "sig")
	}
}

func TestIntegration_JWKS_Unauthenticated(t *testing.T) {
	skipIfNotReady(t)
	client := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, client) })

	writePluginConfig(t, client, map[string]any{
		"client_id":   "vault-foothold-jwt",
		"auth_method": "private_key_jwt",
		"url":         pfAdminURL,
		"token_url":   pfTokenURL,
	})

	statusCode, result := readJWKSRaw(t)
	if statusCode != 200 {
		t.Errorf("JWKS status = %d, want 200", statusCode)
	}

	keysRaw, ok := result["keys"]
	if !ok {
		t.Fatal("expected 'keys' in unauthenticated JWKS response")
	}
	keysSlice, ok := keysRaw.([]any)
	if !ok {
		t.Fatalf("keys type = %T, want []any", keysRaw)
	}
	if len(keysSlice) == 0 {
		t.Error("expected at least 1 key in unauthenticated JWKS response")
	}
}

// ---------------------------------------------------------------------------
// Token Brokering
// ---------------------------------------------------------------------------

func TestIntegration_TokenBroker_ClientSecret(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	userClient := vaultUserClient(t)

	secret, err := userClient.Logical().Read(pluginPath + "/token")
	if err != nil {
		t.Fatalf("failed to read token: %v", err)
	}
	if secret == nil {
		t.Fatal("expected token response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
	tokenType := requireField(t, secret.Data, "token_type")
	if tokenType == "" {
		t.Error("token_type should not be empty")
	}
	if _, ok := secret.Data["expires_in"]; !ok {
		t.Error("expected expires_in in response")
	}
}

func TestIntegration_TokenBroker_PrivateKeyJWT(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":   "vault-foothold-jwt",
		"auth_method": "private_key_jwt",
		"url":         pfAdminURL,
		"token_url":   pfTokenURL,
	})

	userClient := vaultUserClient(t)

	secret, err := userClient.Logical().Read(pluginPath + "/token")
	if err != nil {
		t.Fatalf("failed to read token: %v", err)
	}
	if secret == nil {
		t.Fatal("expected token response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
}

func TestIntegration_TokenBroker_WithScope(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	userClient := vaultUserClient(t)

	// Write with scope parameter (UpdateOperation).
	secret, err := userClient.Logical().Write(pluginPath+"/token", map[string]any{
		"scope": "openid",
	})
	if err != nil {
		t.Fatalf("failed to request token with scope: %v", err)
	}
	if secret == nil {
		t.Fatal("expected token response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
}

func TestIntegration_TokenBroker_NoEntity(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	// Root token has no entity — should fail.
	secret, err := rootClient.Logical().Read(pluginPath + "/token")
	if err != nil {
		// API errors from logical.ErrorResponse come back as error.
		return // expected
	}
	if secret != nil && secret.Data != nil {
		// Check if the response contains an error.
		if _, hasError := secret.Data["error"]; hasError {
			return // expected
		}
		t.Error("expected error for token request without entity, but got a response")
	}
}

// ---------------------------------------------------------------------------
// Rotate Root
// ---------------------------------------------------------------------------

func TestIntegration_RotateRoot_ClientSecret(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	// Rotate.
	_, err := rootClient.Logical().Write(pluginPath+"/rotate-root", nil)
	if err != nil {
		t.Fatalf("failed to rotate root: %v", err)
	}

	// Verify the plugin still works — get a brokered token.
	userClient := vaultUserClient(t)
	secret, err := userClient.Logical().Read(pluginPath + "/token")
	if err != nil {
		t.Fatalf("token brokering failed after root rotation: %v", err)
	}
	if secret == nil {
		t.Fatal("expected token response after rotation, got nil")
	}
	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty after rotation")
	}
}

func TestIntegration_RotateRoot_PrivateKeyJWT(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":   "vault-foothold-jwt",
		"auth_method": "private_key_jwt",
		"url":         pfAdminURL,
		"token_url":   pfTokenURL,
	})

	// Read initial kid.
	cfg := readPluginConfig(t, rootClient)
	oldKID := requireField(t, cfg.Data, "private_key_id")

	// Rotate.
	rotateResp, err := rootClient.Logical().Write(pluginPath+"/rotate-root", nil)
	if err != nil {
		t.Fatalf("failed to rotate root: %v", err)
	}
	if rotateResp == nil {
		t.Fatal("expected rotate-root response, got nil")
	}

	newKID := requireField(t, rotateResp.Data, "private_key_id")
	if newKID == oldKID {
		t.Error("private_key_id should change after rotation")
	}

	// Verify JWKS serves the new key.
	secret, err := rootClient.Logical().Read(pluginPath + "/jwks")
	if err != nil {
		t.Fatalf("failed to read JWKS after rotation: %v", err)
	}
	if secret == nil {
		t.Fatal("expected JWKS response, got nil")
	}

	keysSlice, ok := secret.Data["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		t.Fatal("expected at least 1 key in JWKS after rotation")
	}
	key, _ := keysSlice[0].(map[string]any)
	if kid, _ := key["kid"].(string); kid != newKID {
		t.Errorf("JWKS kid = %q, want %q", kid, newKID)
	}
}

// ---------------------------------------------------------------------------
// Static Roles & Creds
// ---------------------------------------------------------------------------

func TestIntegration_StaticRole_CRUD(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient) })

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	roleName := "test-role"
	rolePath := pluginPath + "/static-roles/" + roleName

	// Create.
	_, err := rootClient.Logical().Write(rolePath, map[string]any{
		"client_id": "target-service-account",
		"ttl":       300,
	})
	if err != nil {
		t.Fatalf("failed to create static role: %v", err)
	}

	// Read.
	secret, err := rootClient.Logical().Read(rolePath)
	if err != nil {
		t.Fatalf("failed to read static role: %v", err)
	}
	if secret == nil {
		t.Fatal("expected static role, got nil")
	}
	if v := requireField(t, secret.Data, "client_id"); v != "target-service-account" {
		t.Errorf("client_id = %q, want %q", v, "target-service-account")
	}

	// Update.
	_, err = rootClient.Logical().Write(rolePath, map[string]any{
		"ttl": 600,
	})
	if err != nil {
		t.Fatalf("failed to update static role: %v", err)
	}

	// Verify update.
	secret, err = rootClient.Logical().Read(rolePath)
	if err != nil {
		t.Fatalf("failed to read updated static role: %v", err)
	}
	if secret == nil {
		t.Fatal("expected static role after update, got nil")
	}
	ttl, ok := secret.Data["ttl"]
	if !ok {
		t.Fatal("expected ttl in static role")
	}
	ttlNum, ok := ttl.(json.Number)
	if !ok {
		t.Fatalf("ttl type = %T, want json.Number", ttl)
	}
	if ttlNum.String() != "600" {
		t.Errorf("ttl = %s, want 600", ttlNum.String())
	}

	// List.
	listSecret, err := rootClient.Logical().List(pluginPath + "/static-roles")
	if err != nil {
		t.Fatalf("failed to list static roles: %v", err)
	}
	if listSecret == nil {
		t.Fatal("expected list response, got nil")
	}
	keysRaw, ok := listSecret.Data["keys"]
	if !ok {
		t.Fatal("expected 'keys' in list response")
	}
	keysSlice, ok := keysRaw.([]any)
	if !ok {
		t.Fatalf("keys type = %T, want []any", keysRaw)
	}
	found := false
	for _, k := range keysSlice {
		if k == roleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("role %q not found in list: %v", roleName, keysSlice)
	}

	// Delete.
	_, err = rootClient.Logical().Delete(rolePath)
	if err != nil {
		t.Fatalf("failed to delete static role: %v", err)
	}

	// Verify deletion.
	secret, err = rootClient.Logical().Read(rolePath)
	if err != nil {
		t.Fatalf("failed to read after delete: %v", err)
	}
	if secret != nil {
		t.Error("expected nil after delete, got non-nil")
	}
}

func TestIntegration_StaticCreds_RetrieveToken(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		rootClient.Logical().Delete(pluginPath + "/static-roles/creds-test") //nolint:errcheck
		deletePluginConfig(t, rootClient)
	})

	writePluginConfig(t, rootClient, map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
	})

	// Create a static role.
	_, err := rootClient.Logical().Write(pluginPath+"/static-roles/creds-test", map[string]any{
		"client_id": "target-service-account",
	})
	if err != nil {
		t.Fatalf("failed to create static role: %v", err)
	}

	// Read static creds.
	secret, err := rootClient.Logical().Read(pluginPath + "/static-creds/creds-test")
	if err != nil {
		t.Fatalf("failed to read static creds: %v", err)
	}
	if secret == nil {
		t.Fatal("expected static creds response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
	tokenType := requireField(t, secret.Data, "token_type")
	if tokenType == "" {
		t.Error("token_type should not be empty")
	}
	if _, ok := secret.Data["expires_in"]; !ok {
		t.Error("expected expires_in in response")
	}
}
