package middleware_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CentraGlobal/backend-payment-go/internal/config"
	"github.com/CentraGlobal/backend-payment-go/internal/middleware"
	"github.com/gofiber/fiber/v2"
)

// setupAuthApp builds a minimal Fiber app with the auth middleware applied to /v1.
func setupAuthApp(cfg config.AuthConfig) *fiber.App {
	app := fiber.New()

	v1 := app.Group("/v1", middleware.RequireSharedSecret(cfg))
	v1.Get("/session", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	return app
}

func authConfig(secret string) config.AuthConfig {
	return config.AuthConfig{
		SharedSecret: secret,
		HeaderName:   "X-Payment-Service-Auth",
		Require:      true,
	}
}

// TestRequireSharedSecret_MissingHeader verifies that a request without the
// auth header is rejected with 401 Unauthorized.
func TestRequireSharedSecret_MissingHeader(t *testing.T) {
	app := setupAuthApp(authConfig("supersecret"))

	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if result["error"] != "missing authorization header" {
		t.Errorf("unexpected error message: %q", result["error"])
	}
}

// TestRequireSharedSecret_InvalidSecret verifies that a request with an
// incorrect secret is rejected with 403 Forbidden.
func TestRequireSharedSecret_InvalidSecret(t *testing.T) {
	app := setupAuthApp(authConfig("supersecret"))

	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	req.Header.Set("X-Payment-Service-Auth", "wrongsecret")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if result["error"] != "invalid authorization" {
		t.Errorf("unexpected error message: %q", result["error"])
	}
}

// TestRequireSharedSecret_ValidSecret verifies that a request with the correct
// secret is allowed through.
func TestRequireSharedSecret_ValidSecret(t *testing.T) {
	app := setupAuthApp(authConfig("supersecret"))

	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	req.Header.Set("X-Payment-Service-Auth", "supersecret")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestRequireSharedSecret_Disabled verifies that when Require is false
// all requests pass through regardless of auth header presence.
func TestRequireSharedSecret_Disabled(t *testing.T) {
	cfg := config.AuthConfig{
		SharedSecret: "supersecret",
		HeaderName:   "X-Payment-Service-Auth",
		Require:      false,
	}
	app := setupAuthApp(cfg)

	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	// No auth header - should still pass because Require=false.
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 when auth disabled, got %d", resp.StatusCode)
	}
}

// TestRequireSharedSecret_CustomHeader verifies that a custom header name is
// respected.
func TestRequireSharedSecret_CustomHeader(t *testing.T) {
	cfg := config.AuthConfig{
		SharedSecret: "mysecret",
		HeaderName:   "X-Custom-Auth",
		Require:      true,
	}
	app := setupAuthApp(cfg)

	// Wrong header name → 401
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	req.Header.Set("X-Payment-Service-Auth", "mysecret")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Correct custom header → 200
	req2 := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	req2.Header.Set("X-Custom-Auth", "mysecret")
	resp2, err := app.Test(req2)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
}
