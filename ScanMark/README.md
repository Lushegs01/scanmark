# ScanMark

## CampOS integration

ScanMark receives CampOS SSO hand-offs at `/sso/callback`. CampOS redirects the
browser with an opaque one-time `code`; ScanMark exchanges it server-to-server
at `POST /api/modules/sso/exchange`, validates the returned HS256 JWT for
issuer `campos-core` and audience `scanmark`, then creates or refreshes the
local Flask login session. The signed JWT is never placed in browser history.

Configure these variables in the ScanMark deployment:

- `CAMPOS_CORE_URL`: the public CampOS origin, such as
  `https://campos-core.vercel.app` (origin only; no API suffix or path).
- `CAMPOS_INSTITUTION_SLUG`: the exact CampOS institution slug served by this
  ScanMark deployment. `CAMPOS_INSTITUTION_ID` is an alternative immutable-ID
  lock. Production SSO refuses to run unless at least one lock is configured.
- `CAMPOS_SSO_SECRET`: the same value as CampOS Core's
  `SSO_JWT_SECRET_SCANMARK`. The legacy ScanMark name `SSO_JWT_SECRET` remains
  a temporary rollout fallback. This value is required in local development
  too; ScanMark never uses a published/default signing secret.
- `CAMPOS_API_KEY`: an institution-scoped key issued to the `scanmark` module
  with `write:attendance` permission.

CampOS must register ScanMark's base URL (or set `SSO_URL_SCANMARK`) to the
public ScanMark origin. It appends `/sso/callback` automatically. Keep Redis
enabled in both production deployments: CampOS stores single-use SSO codes in
Redis, while ScanMark uses Redis for server-side sessions and live QR state.

After a successful scan, ScanMark asynchronously sends the student identity,
course, class-session details, timestamp, and a stable external attendance ID
to CampOS. Transient network, rate-limit, and server failures are retried with
bounded backoff without delaying the student's scan response.

Run the focused integration tests with:

```bash
python -m pytest test_campos_integration.py -q
```
