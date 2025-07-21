[![Deploy Cloudflare Worker](https://github.com/EMQX-Auth-Worker/actions/workflows/deploy.yml/badge.svg?branch=main)](https://github.com/EMQX-Auth-Worker/actions/workflows/deploy.yml)

# EMQX Auth Worker (Cloudflare)

This Cloudflare Worker provides HTTP endpoints for EMQX authentication and ACL checks, backed by Cloudflare KV (free tier compatible).

## Features
- `/auth` endpoint: Verifies username/password using bcrypt hash from KV
- `/acl` endpoint: Checks if a user is allowed to publish/subscribe to a topic
- CORS enabled
- Logging via `console.log` (viewable in Cloudflare dashboard)
- Minimal KV reads (1 per request)
- **API key protected**: Only requests with the correct Bearer token are allowed
- **Rate limiting**: Only failed requests count toward the per-IP limit

## KV Data Model
- **Key:** `user:<username>`
- **Value:**
  ```json
  {
    "password_hash": "bcrypt$2b$12$...",
    "acls": [
      { "action": "subscribe", "topic": "sports/#" },
      { "action": "publish", "topic": "updates/user/kit" }
    ]
  }
  ```

## Setup

1. **Install dependencies:**
   ```sh
   npm install
   ```

2. **Configure Cloudflare KV:**
   - Create a KV namespace in the Cloudflare dashboard.
   - Copy the namespace ID (not the name) for use in CI/CD.

3. **Configure GitHub Repository Variables/Secrets:**
   - Go to your GitHub repo → Settings → Secrets and variables → Actions.
   - Add the following:
     - **Variable:** `EMQX_KV_NAMESPACE_ID` (set to your Cloudflare KV namespace ID)
     - **Secret:** `EMQX_AUTH_API_KEY` (set to your desired Bearer token for EMQX)
     - **Secret:** `CLOUDFLARE_API_TOKEN` (Cloudflare API token for deployment)
     - **Secret:** `CLOUDFLARE_ACCOUNT_ID` (Cloudflare account ID)

4. **Configure wrangler.toml:**
   - The `id` field for the KV namespace is set to `$EMQX_KV_NAMESPACE_ID` and will be replaced at deploy time by the workflow.
   - The `binding` field (e.g., `USERS`) is the variable name used in the Worker code and does not need to match the dashboard name.

5. **Deploy (CI/CD):**
   - On push to `main`, GitHub Actions will:
     - Substitute the KV namespace ID into `wrangler.toml` using `envsubst`.
     - Set the Worker secret `API_KEY` to the value of `EMQX_AUTH_API_KEY`.
     - Deploy the Worker using Wrangler.

6. **Upload users to KV:**
   - Use the Cloudflare dashboard or API to add user records as shown above.

## Endpoints

### `/auth` (POST)
- **Body:** `{ "username": "...", "password": "..." }`
- **Response:** `{ "result": "allow" }` or `{ "result": "deny" }`

### `/acl` (POST)
- **Body:** `{ "username": "...", "action": "publish|subscribe", "topic": "..." }`
- **Response:** `{ "result": "allow" }` or `{ "result": "deny" }`

## EMQX HTTP Auth Example

```yaml
auth:
  http:
    enable: true
    auth_req:
      url: "https://<your-worker-url>/auth"
      method: post
      headers:
        Authorization: "Bearer <your-api-key>"
      body:
        username: "%u"
        password: "%P"
    acl_req:
      url: "https://<your-worker-url>/acl"
      method: post
      headers:
        Authorization: "Bearer <your-api-key>"
      body:
        username: "%u"
        action: "%A"
        topic: "%t"
```

## CI/CD Configuration

- The GitHub Actions workflow will:
  - Use `envsubst` to inject the value of `EMQX_KV_NAMESPACE_ID` into `wrangler.toml` before deployment.
  - Set the Worker secret `API_KEY` from the `EMQX_AUTH_API_KEY` secret.
  - Deploy using the Cloudflare API token and account ID.
- **No sensitive values are hardcoded.**
- To change the KV namespace or API key, update the corresponding GitHub variable/secret.

## Logging
- All requests and results are logged with `console.log`.
- View logs in the Cloudflare dashboard under Workers > your worker > Logs.

## Notes
- This worker is designed for the Cloudflare free tier (100k reads/day, 1k writes/day, 1GB storage).
- No user management API is included; manage users via KV dashboard or scripts. 