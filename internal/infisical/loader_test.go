package infisical_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CentraGlobal/backend-payment-go/internal/infisical"
)

// authSuccessHandler returns a handler that responds to the Infisical
// universal-auth login with a synthetic access token and delegates all
// other requests to next.
func authSuccessHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"accessToken":       "test-token",
				"expiresIn":         3600,
				"accessTokenMaxTTL": 7200,
				"tokenType":         "Bearer",
			})
			return
		}
		next(w, r)
	}
}

// emptySecretsHandler returns a handler that serves an empty secrets list.
func emptySecretsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secrets": []interface{}{},
		"imports": []interface{}{},
	})
}

// TestLoadSecrets_NoCreds_IsNoOp verifies that LoadSecrets is a no-op when
// neither credential env var is set.
func TestLoadSecrets_NoCreds_IsNoOp(t *testing.T) {
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "")

	if err := infisical.LoadSecrets(context.Background()); err != nil {
		t.Fatalf("expected nil error when creds are empty, got: %v", err)
	}
}

// TestLoadSecrets_PartialCreds_IsNoOp verifies that LoadSecrets is a no-op
// when only one of the two credentials is set.
func TestLoadSecrets_PartialCreds_IsNoOp(t *testing.T) {
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "")

	if err := infisical.LoadSecrets(context.Background()); err != nil {
		t.Fatalf("expected nil error for partial creds, got: %v", err)
	}
}

// TestLoadSecrets_MissingProjectID_ReturnsError verifies that an error is
// returned when both credentials are set but INFISICAL_PROJECT_ID is absent.
func TestLoadSecrets_MissingProjectID_ReturnsError(t *testing.T) {
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "")

	err := infisical.LoadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error when INFISICAL_PROJECT_ID is missing")
	}
}

// TestLoadSecrets_AuthFailure_ReturnsError verifies that an authentication
// error from Infisical is propagated as a non-nil error.
func TestLoadSecrets_AuthFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"invalid credentials"}`))
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "bad-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "bad-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "test-project")
	t.Setenv("INFISICAL_SITE_URL", srv.URL)

	err := infisical.LoadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error on authentication failure")
	}
}

// TestLoadSecrets_FetchFailure_ReturnsError verifies that a secrets-fetch
// error (auth succeeds, list fails) is propagated as a non-nil error.
func TestLoadSecrets_FetchFailure_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(authSuccessHandler(func(w http.ResponseWriter, r *http.Request) {
		// Secrets endpoint fails.
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"access denied"}`))
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "test-project")
	t.Setenv("INFISICAL_SITE_URL", srv.URL)

	err := infisical.LoadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error on secrets fetch failure")
	}
}

// TestLoadSecrets_EnvSelection verifies that APP_ENV is forwarded to
// Infisical as the target environment.
func TestLoadSecrets_EnvSelection(t *testing.T) {
	var capturedEnv string
	srv := httptest.NewServer(authSuccessHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedEnv = r.URL.Query().Get("environment")
		emptySecretsHandler(w, r)
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "test-project")
	t.Setenv("INFISICAL_SITE_URL", srv.URL)
	t.Setenv("APP_ENV", "production")

	if err := infisical.LoadSecrets(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedEnv != "production" {
		t.Errorf("expected environment=production, got %q", capturedEnv)
	}
}

// TestLoadSecrets_EnvDefault verifies that the environment defaults to
// "development" (matching the AppConfig default) when APP_ENV is unset.
func TestLoadSecrets_EnvDefault(t *testing.T) {
	var capturedEnv string
	srv := httptest.NewServer(authSuccessHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedEnv = r.URL.Query().Get("environment")
		emptySecretsHandler(w, r)
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "test-project")
	t.Setenv("INFISICAL_SITE_URL", srv.URL)
	t.Setenv("APP_ENV", "") // explicitly clear

	if err := infisical.LoadSecrets(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedEnv != "development" {
		t.Errorf("expected default environment=development, got %q", capturedEnv)
	}
}

// TestLoadSecrets_Timeout verifies that LoadSecrets respects the context
// deadline and returns a context error instead of hanging indefinitely.
func TestLoadSecrets_Timeout(t *testing.T) {
	// Server that hangs to simulate a slow/unreachable Infisical instance.
	// The sleep must be longer than the context deadline used below so that
	// the deadline fires first, but short enough to keep the test suite fast.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "test-id")
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("INFISICAL_PROJECT_ID", "test-project")
	t.Setenv("INFISICAL_SITE_URL", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := infisical.LoadSecrets(ctx)
	if err == nil {
		t.Fatal("expected error on timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}
