# TA-14 Sandbox Usage Control Setup

## What this build does

- Leaves public GET pages and OpenAPI documentation open.
- Meters only POST `/v1/*` evaluation routes.
- Anonymous callers: 5 requests per hour and 20 per day per originating IP.
- API-key callers: monthly quota defined per key.
- Returns HTTP 429 with an upgrade path when quota is exhausted.
- Adds rate-limit response headers.
- Uses Render Key Value / Redis when `TA14_REDIS_URL` is configured.
- Falls back to in-memory counters if Redis is unavailable. This fallback resets on redeploy and should not be treated as production persistence.

## Render setup

1. Create a Render Key Value instance.
2. Copy its Internal Redis URL.
3. Open the API web service in Render.
4. Go to Environment.
5. Add:

   `TA14_REDIS_URL=<internal redis url>`

6. Confirm these environment variables:

   - `TA14_RATE_LIMIT_ENABLED=true`
   - `TA14_ANON_HOURLY_LIMIT=5`
   - `TA14_ANON_DAILY_LIMIT=20`
   - `TA14_KEY_MONTHLY_LIMIT=100`
   - `TA14_MAX_BODY_BYTES=65536`

7. Save changes and deploy the latest commit.

## Optional API keys

Set `TA14_API_KEYS_JSON` in Render, not in GitHub.

Example:

```json
[
  {
    "key": "replace-with-a-long-random-key",
    "name": "Developer One",
    "plan": "developer_free",
    "monthly_limit": 100,
    "active": true
  },
  {
    "key": "replace-with-another-long-random-key",
    "name": "Paid Partner",
    "plan": "partner_sandbox",
    "monthly_limit": 5000,
    "active": true
  }
]
```

Raw keys are never written to usage-storage keys. The application hashes them before identification.

## Response headers

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `X-RateLimit-Scope`
- `X-RateLimit-Plan`

## Quota response

When a quota is exhausted, the API returns HTTP 429 with code:

`SANDBOX_QUOTA_EXHAUSTED`
