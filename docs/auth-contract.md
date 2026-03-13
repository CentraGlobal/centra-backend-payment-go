# Payment Service Auth Contract

## Overview

The payment service (`centra-backend-payment-go`) exposes payment and session
APIs under `/v1`. These endpoints are intended exclusively for **trusted
internal callers** (e.g. `centra-backend-api-nodejs`) and must not be accessed
directly by end-users or external systems.

All `/v1` routes are protected by a shared-secret middleware. The `/health`
endpoint remains unauthenticated to support load-balancer health checks.

---

## Authentication Mechanism

### Shared Secret

A static shared secret is distributed to trusted services via secure
environment variables (Infisical or equivalent secret manager).

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_SHARED_SECRET` | Yes | — | The shared secret string. Must be identical across `centra-backend-payment-go` and all trusted callers. |
| `AUTH_HEADER_NAME` | No | `X-Payment-Service-Auth` | The HTTP header used to transmit the secret. |
| `AUTH_REQUIRE` | No | `true` | Set to `false` to disable enforcement in development. **Never `false` in production.** |

### Authorization Flow

1. The caller adds the auth header to every request to `/v1/*`.
2. The middleware extracts the header value and compares it to `AUTH_SHARED_SECRET` using constant-time comparison (mitigates timing attacks).
3. **Missing header** → `401 Unauthorized`
4. **Wrong secret** → `403 Forbidden`
5. **Correct secret** → request forwarded to the handler.

### Excluded Paths

| Path | Authenticated |
|---|---|
| `GET /health` | No |
| `GET /v1/session` | **Yes** |
| `POST /v1/payments/tokenize` | **Yes** |
| `POST /v1/payments/charge` | **Yes** |
| `GET /v1/payments/cards/:token` | **Yes** |
| `DELETE /v1/payments/cards/:token` | **Yes** |

---

## Caller Contract (`centra-backend-api-nodejs`)

Every HTTP request to the payment service must include the auth header:

```
X-Payment-Service-Auth: <shared-secret>
```

### Example (TypeScript / axios)

```typescript
import axios from "axios";

const paymentServiceClient = axios.create({
  baseURL: process.env.PAYMENT_SERVICE_URL,
  headers: {
    "X-Payment-Service-Auth": process.env.PAYMENT_SERVICE_SHARED_SECRET,
  },
});

// GET /v1/session
const session = await paymentServiceClient.get("/v1/session", {
  params: { scope: "card" },
});

// POST /v1/payments/charge
const charge = await paymentServiceClient.post("/v1/payments/charge", {
  card_token: "tok_xxx",
  method: "POST",
  url: "https://...",
  headers: {},
  body: "...",
});
```

### Security Requirements for Callers

- Store `PAYMENT_SERVICE_SHARED_SECRET` in Infisical (or equivalent). Never commit it to source control.
- Do **not** log the secret or include it in error messages.
- Rotate the secret periodically. During rotation, coordinate with the payment service to avoid downtime (see *Rotation* below).

---

## Rotation Strategy

To rotate the shared secret without downtime:

1. Update `AUTH_SHARED_SECRET` in the payment service to the new value and redeploy.
2. Update `PAYMENT_SERVICE_SHARED_SECRET` in all callers and redeploy.

> **Future enhancement:** Support a two-secret overlap window where both the old
> and new secrets are accepted simultaneously during the rollover period.

---

## Security Considerations

- The middleware uses `crypto/subtle.ConstantTimeCompare` to prevent timing side-channels.
- The secret is never echoed in response bodies or server logs.
- `AUTH_REQUIRE=false` is provided for local development only. CI and production environments must always have `AUTH_REQUIRE=true`.
