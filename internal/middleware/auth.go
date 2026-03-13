package middleware

import (
	"crypto/subtle"

	"github.com/CentraGlobal/backend-payment-go/internal/config"
	"github.com/gofiber/fiber/v2"
)

// RequireSharedSecret returns a Fiber middleware that enforces server-to-server
// authentication using a static shared secret transmitted via an HTTP header.
//
// Behavior:
//   - If cfg.Require is false, all requests pass through (development mode only).
//   - If the configured header is absent, returns 401 Unauthorized.
//   - If the header value does not match cfg.SharedSecret (constant-time compare),
//     returns 403 Forbidden.
//   - Otherwise the request is forwarded to the next handler.
func RequireSharedSecret(cfg config.AuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !cfg.Require {
			return c.Next()
		}

		provided := c.Get(cfg.HeaderName)
		if provided == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		if subtle.ConstantTimeCompare([]byte(provided), []byte(cfg.SharedSecret)) != 1 {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "invalid authorization",
			})
		}

		return c.Next()
	}
}
