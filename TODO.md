# Backlog

## 1. Sessions never expire

`sessions.created_at` is recorded and never read. A session token stays valid until
someone deletes the row, so a phone that signed in once is authorised indefinitely —
losing the device means the session outlives any reasonable window.

Add a TTL check in `verify_token` (compare `created_at` against a `SESSION_LIFETIME`),
and delete expired rows opportunistically on login so the table does not grow forever.
A sliding window would be friendlier than a hard cutoff, but needs a `last_used` column
and a write per request; a fixed lifetime of a few weeks is probably right for this.

Note the frontend already handles the failure gracefully: `api()` treats 401 as "signed
out", clears the stored token and returns to the login screen. So expiry needs no client
change.

## 2. No way to see or revoke individual sessions

The `label` column exists for exactly this — the web UI sends `"web"` — but nothing
surfaces it. Revoking one device currently means direct DB access. Wants
`GET /sessions` and `DELETE /sessions/{token}`, plus somewhere to show them.

## 3. Creating a user takes two admin calls

`/users/add` mints a token, `/users/password` sets a password separately. Fine for three
users, awkward beyond that. Could accept an optional password on `/users/add`.

## 4. Credential files are world-readable

`.env` is 644/664 and the SQLite databases are 644, on all three machines — any local
account can read the API tokens, and on the API host the password hashes and every
session token. Single-user boxes, so low risk, but `chmod 600` costs nothing.

Note the `.env.bak-*` files created on 2026-08-17 (toem2 and the VPS) have the same
permissions and contain real secrets, including the pre-rotation Spotify refresh token.
Either tighten or delete them.

## 5. No HSTS on the API

`toemapi.johannesbernet.com` sends no `Strict-Transport-Security`. Plain HTTP does 301 to
HTTPS, but a first-ever request over HTTP is interceptable before that redirect lands.
The players use `https://` explicitly so this mainly concerns browsers. One `add_header`
in the nginx vhost, though it applies to the whole domain once set, so check the other
`*.johannesbernet.com` vhosts first.

Same place, same cost: the frontend page has no `X-Content-Type-Options` or
`frame-ancestors`. It holds a session token in localStorage, so framing it is not
harmless.

## 6. Residual: login lockout is still per-user

Fixed the worst of it — the counter was unbounded and only cleared on a successful login,
so ten wrong guesses locked an account until the process restarted, and anyone knowing a
username could trigger it deliberately. It is now a 900s moving window that recovers on
its own, and returns `Retry-After`.

What remains: an attacker who knows a username can still deny that user login for 15
minutes at a time by burning ten attempts. Inherent to per-user lockout. Per-IP counting
would fix it, but the app is behind nginx and would need `X-Forwarded-For` handling and a
trusted-proxy assumption. Given PBKDF2 already costs ~0.35s per attempt and the passwords
are long, dropping the lockout entirely and relying on that cost is also defensible.
