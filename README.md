# EMQX Auth Worker (Cloudflare)

This Cloudflare Worker provides HTTP endpoints for EMQX authentication and ACL checks, backed by Cloudflare KV (free tier compatible).

## Features
- `/auth` endpoint: Verifies username/password using bcrypt hash from KV
- `/acl` endpoint: Checks if a user is allowed to publish/subscribe to a topic
- CORS enabled
- Logging via `console.log` (viewable in Cloudflare dashboard)
- Minimal KV reads (1 per request)

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

2. **Configure KV:**
   - Create a KV namespace in the Cloudflare dashboard.
   - Copy the namespace ID into `wrangler.toml` under `id` for the `USERS` binding.

3. **Deploy:**
   ```sh
   npx wrangler deploy
   ```

4. **Upload users to KV:**
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
      body:
        username: "%u"
        password: "%P"
    acl_req:
      url: "https://<your-worker-url>/acl"
      method: post
      body:
        username: "%u"
        action: "%A"
        topic: "%t"
```

## Logging
- All requests and results are logged with `console.log`.
- View logs in the Cloudflare dashboard under Workers > your worker > Logs.

## Notes
- This worker is designed for the Cloudflare free tier (100k reads/day, 1k writes/day, 1GB storage).
- No user management API is included; manage users via KV dashboard or scripts. 