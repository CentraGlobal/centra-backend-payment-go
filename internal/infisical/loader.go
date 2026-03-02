package infisical

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	infisical "github.com/infisical/go-sdk"
)

// infisicalTimeout is the maximum time allowed for the full Infisical
// auth + secret-fetch sequence during application startup.
const infisicalTimeout = 30 * time.Second

// LoadSecrets fetches all secrets from the Infisical instance and attaches
// them to the process environment. It is a no-op when
// INFISICAL_UNIVERSAL_AUTH_CLIENT_ID or INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
// are empty, which preserves the normal local-dev workflow of reading
// variables directly from the environment (or a .env file).
func LoadSecrets(ctx context.Context) error {
	clientID := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	clientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		log.Println("infisical: credentials not set, skipping secret load")
		return nil
	}

	projectID := os.Getenv("INFISICAL_PROJECT_ID")
	if projectID == "" {
		return fmt.Errorf("infisical: INFISICAL_PROJECT_ID is required when universal auth credentials are provided")
	}

	siteURL := os.Getenv("INFISICAL_SITE_URL")
	if siteURL == "" {
		siteURL = "https://app.infisical.com"
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// Enforce a bounded timeout so a misconfigured or unreachable Infisical
	// instance cannot hang the application startup indefinitely.
	timeoutCtx, cancel := context.WithTimeout(ctx, infisicalTimeout)
	defer cancel()

	type result struct{ err error }
	done := make(chan result, 1)

	go func() {
		client := infisical.NewInfisicalClient(timeoutCtx, infisical.Config{
			SiteUrl: siteURL,
		})

		if _, err := client.Auth().UniversalAuthLogin(clientID, clientSecret); err != nil {
			done <- result{fmt.Errorf("infisical: authentication failed: %w", err)}
			return
		}

		if _, err := client.Secrets().List(infisical.ListSecretsOptions{
			ProjectID:          projectID,
			Environment:        env,
			SecretPath:         "/",
			AttachToProcessEnv: true,
		}); err != nil {
			done <- result{fmt.Errorf("infisical: failed to fetch secrets: %w", err)}
			return
		}

		log.Printf("infisical: secrets loaded successfully for environment %q", env)
		done <- result{nil}
	}()

	select {
	case r := <-done:
		return r.err
	case <-timeoutCtx.Done():
		return fmt.Errorf("infisical: timed out loading secrets: %w", timeoutCtx.Err())
	}
}
