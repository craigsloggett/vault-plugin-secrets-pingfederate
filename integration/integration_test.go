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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	secret := readPluginConfig(t, client, "test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":    "vault-foothold-jwt",
		"auth_method":  "private_key_jwt",
		"url":          pfAdminURL,
		"token_url":    pfTokenURL,
		"insecure_tls": true,
	})

	secret := readPluginConfig(t, client, "test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

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

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":         "vault-foothold-jwt",
		"auth_method":       "private_key_jwt",
		"signing_algorithm": "ES256",
		"private_key":       string(keyPEM),
		"url":               pfAdminURL,
		"token_url":         pfTokenURL,
		"insecure_tls":      true,
	})

	secret := readPluginConfig(t, client, "test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	// Write initial config.
	writePluginConfig(t, client, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	// Update only insecure_tls.
	writePluginConfig(t, client, "test", map[string]any{
		"insecure_tls": false,
	})

	secret := readPluginConfig(t, client, "test")
	if secret == nil {
		t.Fatal("expected config, got nil")
	}

	// Verify updated field.
	insecure, ok := secret.Data["insecure_tls"]
	if !ok {
		t.Fatal("expected insecure_tls in response")
	}
	if insecure != false {
		t.Errorf("insecure_tls = %v, want false", insecure)
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
	writePluginConfig(t, client, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	// Delete.
	deletePluginConfig(t, client, "test")

	// Read should return nil.
	secret := readPluginConfig(t, client, "test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	secret, err := client.Logical().Read(pluginPath + "/jwks/test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":    "vault-foothold-jwt",
		"auth_method":  "private_key_jwt",
		"url":          pfAdminURL,
		"token_url":    pfTokenURL,
		"insecure_tls": true,
	})

	// Read the config to get the kid.
	cfg := readPluginConfig(t, client, "test")
	expectedKID := requireField(t, cfg.Data, "private_key_id")

	secret, err := client.Logical().Read(pluginPath + "/jwks/test")
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
	t.Cleanup(func() { deletePluginConfig(t, client, "test") })

	writePluginConfig(t, client, "test", map[string]any{
		"client_id":    "vault-foothold-jwt",
		"auth_method":  "private_key_jwt",
		"url":          pfAdminURL,
		"token_url":    pfTokenURL,
		"insecure_tls": true,
	})

	statusCode, result := readJWKSRaw(t, "test")
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
// Token Brokering (via creds/{role})
// ---------------------------------------------------------------------------

func TestIntegration_Creds_ClientSecret(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		deletePluginRole(t, rootClient, "test-role")
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	writePluginRole(t, rootClient, "test-role", map[string]any{
		"connection_name": "test",
	})

	userClient := vaultUserClient(t)

	secret, err := userClient.Logical().Read(pluginPath + "/creds/test-role")
	if err != nil {
		t.Fatalf("failed to read creds: %v", err)
	}
	if secret == nil {
		t.Fatal("expected creds response, got nil")
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

func TestIntegration_Creds_PrivateKeyJWT(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		deletePluginRole(t, rootClient, "test-role")
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":    "vault-foothold-jwt",
		"auth_method":  "private_key_jwt",
		"url":          pfAdminURL,
		"token_url":    pfTokenURL,
		"insecure_tls": true,
	})

	writePluginRole(t, rootClient, "test-role", map[string]any{
		"connection_name": "test",
	})

	userClient := vaultUserClient(t)

	secret, err := userClient.Logical().Read(pluginPath + "/creds/test-role")
	if err != nil {
		t.Fatalf("failed to read creds: %v", err)
	}
	if secret == nil {
		t.Fatal("expected creds response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
}

func TestIntegration_Creds_WithScope(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		deletePluginRole(t, rootClient, "test-role")
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	writePluginRole(t, rootClient, "test-role", map[string]any{
		"connection_name": "test",
	})

	userClient := vaultUserClient(t)

	// Write with scope parameter (UpdateOperation).
	secret, err := userClient.Logical().Write(pluginPath+"/creds/test-role", map[string]any{
		"scope": "openid",
	})
	if err != nil {
		t.Fatalf("failed to request creds with scope: %v", err)
	}
	if secret == nil {
		t.Fatal("expected creds response, got nil")
	}

	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty")
	}
}

func TestIntegration_Creds_NoEntity(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		deletePluginRole(t, rootClient, "test-role")
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":     "vault-foothold-secret",
		"client_secret": footholdSecret,
		"url":           pfAdminURL,
		"token_url":     pfTokenURL,
		"insecure_tls":  true,
	})

	writePluginRole(t, rootClient, "test-role", map[string]any{
		"connection_name": "test",
	})

	// Root token has no entity — should fail.
	secret, err := rootClient.Logical().Read(pluginPath + "/creds/test-role")
	if err != nil {
		// API errors from logical.ErrorResponse come back as error.
		return // expected
	}
	if secret != nil && secret.Data != nil {
		// Check if the response contains an error.
		if _, hasError := secret.Data["error"]; hasError {
			return // expected
		}
		t.Error("expected error for creds request without entity, but got a response")
	}
}

// ---------------------------------------------------------------------------
// Rotate Root
// ---------------------------------------------------------------------------

func TestIntegration_RotateRoot_ClientSecret(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() {
		deletePluginRole(t, rootClient, "test-role")
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":      "vault-foothold-secret",
		"client_secret":  footholdSecret,
		"url":            pfAdminURL,
		"token_url":      pfTokenURL,
		"insecure_tls":   true,
		"admin_username": pfAdminUser,
		"admin_password": pfAdminPassword,
	})

	writePluginRole(t, rootClient, "test-role", map[string]any{
		"connection_name": "test",
	})

	// Rotate.
	_, err := rootClient.Logical().Write(pluginPath+"/rotate-root/test", nil)
	if err != nil {
		t.Fatalf("failed to rotate root: %v", err)
	}

	// Verify the plugin still works — get a brokered token.
	userClient := vaultUserClient(t)
	secret, err := userClient.Logical().Read(pluginPath + "/creds/test-role")
	if err != nil {
		t.Fatalf("creds failed after root rotation: %v", err)
	}
	if secret == nil {
		t.Fatal("expected creds response after rotation, got nil")
	}
	accessToken := requireField(t, secret.Data, "access_token")
	if accessToken == "" {
		t.Error("access_token should not be empty after rotation")
	}
}

func TestIntegration_RotateRoot_PrivateKeyJWT(t *testing.T) {
	skipIfNotReady(t)
	rootClient := vaultClient(t)
	t.Cleanup(func() { deletePluginConfig(t, rootClient, "test") })

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":    "vault-foothold-jwt",
		"auth_method":  "private_key_jwt",
		"url":          pfAdminURL,
		"token_url":    pfTokenURL,
		"insecure_tls": true,
	})

	// Read initial kid.
	cfg := readPluginConfig(t, rootClient, "test")
	oldKID := requireField(t, cfg.Data, "private_key_id")

	// Rotate.
	rotateResp, err := rootClient.Logical().Write(pluginPath+"/rotate-root/test", nil)
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
	secret, err := rootClient.Logical().Read(pluginPath + "/jwks/test")
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
	t.Cleanup(func() { deletePluginConfig(t, rootClient, "test") })

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":      "vault-foothold-secret",
		"client_secret":  footholdSecret,
		"url":            pfAdminURL,
		"token_url":      pfTokenURL,
		"insecure_tls":   true,
		"admin_username": pfAdminUser,
		"admin_password": pfAdminPassword,
	})

	roleName := "test-role"
	rolePath := pluginPath + "/static-roles/" + roleName

	// Create.
	_, err := rootClient.Logical().Write(rolePath, map[string]any{
		"client_id":       "target-service-account",
		"connection_name": "test",
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
	if v := requireField(t, secret.Data, "connection_name"); v != "test" {
		t.Errorf("connection_name = %q, want %q", v, "test")
	}

	// Update with rotation_period.
	_, err = rootClient.Logical().Write(rolePath, map[string]any{
		"rotation_period": 3600,
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
	rp, ok := secret.Data["rotation_period"]
	if !ok {
		t.Fatal("expected rotation_period in static role")
	}
	rpNum, ok := rp.(json.Number)
	if !ok {
		t.Fatalf("rotation_period type = %T, want json.Number", rp)
	}
	if rpNum.String() != "3600" {
		t.Errorf("rotation_period = %s, want 3600", rpNum.String())
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
		deletePluginConfig(t, rootClient, "test")
	})

	writePluginConfig(t, rootClient, "test", map[string]any{
		"client_id":      "vault-foothold-secret",
		"client_secret":  footholdSecret,
		"url":            pfAdminURL,
		"token_url":      pfTokenURL,
		"insecure_tls":   true,
		"admin_username": pfAdminUser,
		"admin_password": pfAdminPassword,
	})

	// Create a static role.
	_, err := rootClient.Logical().Write(pluginPath+"/static-roles/creds-test", map[string]any{
		"client_id":       "target-service-account",
		"connection_name": "test",
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
