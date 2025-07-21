[![Deploy Cloudflare Worker](https://github.com/cconkrig/EMQX-Auth-Worker/actions/workflows/deploy.yml/badge.svg?branch=main)](https://github.com/cconkrig/EMQX-Auth-Worker/actions/workflows/deploy.yml)

# EMQX Auth Worker (Cloudflare)

This Cloudflare Worker provides HTTP endpoints for EMQX authentication and ACL checks, backed by Cloudflare KV (free tier compatible), and a secure Svelte-based admin UI for user/ACL management.

## Features
- `/auth` endpoint: Verifies username/password using bcrypt hash from KV
- `/acl` endpoint: Checks if a user is allowed to publish/subscribe to a topic
- **Admin UI at `/admin`**: Svelte SPA for login, user/ACL management, and audit logging
- CORS enabled
- Logging via `console.log` (viewable in Cloudflare dashboard)
- Minimal KV reads (1 per request)
- **API key protected**: Only requests with the correct Bearer token are allowed
- **Rate limiting**: Only failed requests count toward the per-IP limit
- **Custom domain routing**: Route your Worker to a custom domain using a GitHub Actions variable
- **Advanced logging**: Cloudflare Workers Logs enabled for full observability

## Admin UI

The `/admin` route serves a Svelte-based admin panel for managing users and ACLs.
- **Login**: JWT-protected login for admin users (credentials stored in KV as `admin:<username>`)
- **User management**: List, create, update, and delete users
- **ACL management**: View, add, update, and remove ACLs for each user
- **Audit logging**: All admin actions are logged to the console for traceability
- **Confirmation dialogs**: Deleting a user requires confirmation
- **Error/success feedback**: All actions show clear feedback

To build the admin UI:
```sh
npm run build
```
This will output the static assets to `static/` for the Worker to serve.

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
- **Key:** `admin:<username>`
- **Value:**
  ```json
  {
    "password_hash": "bcrypt$2b$12$...",
    "roles": ["admin"]
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
     - **Variable:** `EMQX_CUSTOM_DOMAIN` (set to your custom domain route, e.g. `api.example.com`)
     - **Secret:** `EMQX_AUTH_API_KEY` (set to your desired Bearer token for EMQX)
     - **Secret:** `CLOUDFLARE_API_TOKEN` (Cloudflare API token for deployment)
     - **Secret:** `CLOUDFLARE_ACCOUNT_ID` (Cloudflare account ID)
     - **Secret:** `JWT_SECRET` (secret for signing admin JWTs)

4. **Configure wrangler.toml:**
   - The `id` field for the KV namespace is set to `$EMQX_KV_NAMESPACE_ID` and the custom domain is set via the `routes` array with `$EMQX_CUSTOM_DOMAIN`. Both will be replaced at deploy time by the workflow.
   - The `binding` field (e.g., `USERS`) is the variable name used in the Worker code and does not need to match the dashboard name.
   - Example:
     ```toml
     routes = [
         { pattern = "$EMQX_CUSTOM_DOMAIN", custom_domain = true }
     ]

     [[kv_namespaces]]
     binding = "USERS"
     id = "$EMQX_KV_NAMESPACE_ID"

     [observability.logs]
     enabled = true
     head_sampling_rate = 1 # 100% sampling rate
     ```

5. **Deploy (CI/CD):**
   - On push to `main`, GitHub Actions will:
     - Build the Svelte admin UI (`npm run build`)
     - Substitute the KV namespace ID and custom domain into `wrangler.toml` using `envsubst`.
     - Set the Worker secret `API_KEY` to the value of `EMQX_AUTH_API_KEY`.
     - Set the Worker secret `JWT_SECRET` for admin JWTs.
     - Deploy the Worker using Wrangler.

6. **Upload users to KV:**
   - Use the Cloudflare dashboard or API to add user records as shown above.
   - To add an admin, store a record as `admin:<username>` with a bcrypt-hashed password and `roles: ["admin"]`.

## Endpoints

### `/auth` (POST)
- **Body:** `{ "username": "...", "password": "..." }`
- **Response:** `{ "result": "allow" }` or `{ "result": "deny" }`

### `/acl` (POST)
- **Body:** `{ "username": "...", "action": "publish|subscribe", "topic": "..." }`
- **Response:** `{ "result": "allow" }` or `{ "result": "deny" }`

### **Admin API Endpoints**
- `/admin/api/login` (POST): Admin login, returns JWT
- `/admin/api/user` (POST): Create/update user (JWT required)
- `/admin/api/user` (DELETE): Delete user (JWT required)
- `/admin/api/acl` (POST): Update ACLs for a user (JWT required)
- `/admin/api/users` (GET): List all users (JWT required)
- `/admin/api/user-details?username=...` (GET): Get a user's ACLs (JWT required)

## Custom Domains

This project uses Cloudflare Workers [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) to map your Worker to a domain or subdomain you own. The domain is set dynamically via the `EMQX_CUSTOM_DOMAIN` GitHub Actions variable and configured in `wrangler.toml`:

```toml
routes = [
    { pattern = "$EMQX_CUSTOM_DOMAIN", custom_domain = true }
]
```

For more details and advanced usage, see the [Cloudflare Custom Domains documentation](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).

## Advanced Logging (Workers Logs)

Cloudflare [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/) are enabled for this Worker via the `[observability.logs]` section in `wrangler.toml`:

```toml
[observability.logs]
enabled = true
head_sampling_rate = 1 # 100% sampling rate
```

You can view logs in the Cloudflare dashboard under Workers > your Worker > Logs, or use the Workers Logs API.

## CI/CD Configuration

- The GitHub Actions workflow will:
  - Build the Svelte admin UI (`npm run build`)
  - Use `envsubst` to inject the values of `EMQX_KV_NAMESPACE_ID` and `EMQX_CUSTOM_DOMAIN` into `wrangler.toml` before deployment.
  - Set the Worker secret `API_KEY` from the `EMQX_AUTH_API_KEY` secret.
  - Set the Worker secret `JWT_SECRET` for admin JWTs.
  - Deploy using the Cloudflare API token and account ID.
- **No sensitive values are hardcoded.**
- To change the KV namespace, custom domain, or API key, update the corresponding GitHub variable/secret.

## Logging
- All requests and results are logged with `console.log`.
- Logs are always enabled in Cloudflare Workers and can be viewed in the Cloudflare dashboard or with `wrangler tail`.
- **Admin actions are audit-logged to the console.**

## Notes
- This worker is designed for the Cloudflare free tier (100k reads/day, 1k writes/day, 1GB storage).
- No user management API is included; manage users via KV dashboard or scripts if not using the admin UI. 