# The backbone: contracts and the URL

The family's view of website-city is in [docs/backbone.md](../../../docs/backbone.md); this is gs-auth's half.

## Contracts this code depends on

Verified against website-city's source. If these drift, gs-auth breaks here:

| Endpoint | Contract source | Used by |
| --- | --- | --- |
| `POST /api/app/v1/auth/device` | `~/types/app-api/contract.ts` `DeviceStartRequest` | `GSAuthClient.start_device_login` |
| `POST /api/app/v1/auth/token` | `DeviceTokenRequest`, `TokenResponse` | `GSAuthClient._poll_for_token` |
| `POST /api/app/v1/auth/refresh` | `RefreshRequest` | `GSAuthClient.refresh` |
| `POST /api/app/v1/auth/revoke` | none | `GSAuthClient.sign_out` |
| `GET /api/app/v1/me` | `SessionUserSchema` | issuer + legacy `INTROSPECT` without a backbone |
| `POST /api/app/v1/play/join-token` | `{ audience, address? }` → `{ token, audience, expiresIn, addressVerified? }` (address sent and verification required only with `bind_join_address`) | `GSAuthClient.request_join_token` |
| `POST /api/integration/v1/player/introspect` | website-city `docs/api/integration-api.md` | `GSAuthServer` INTROSPECT with a backbone |
| `POST /api/content/server/integration/stats` | `~/types/integration/server.ts` `IngestServerStatsInput` | `GSBackboneClient.report_stats` |
| `POST /api/content/server/integration/users` | `IngestServerUsersInput` | `GSBackboneClient.report_users` |
| `GET /api/integration/v1/user/lookup` | `IngestUserLookupInput` | `GSBackboneClient.lookup_user` |

`GSAuthClient.post_app` / `get_app` are the seam for anything a PLAYER reports about themselves; `GSBackboneClient.post_integration` / `get_integration` are the seam other addons reach the backbone through as a server.

Details that are easy to get wrong and are already handled:

- **Poll outcomes are 202 with an error envelope**, not HTTP failures. `authorization_pending`, `slow_down`, `access_denied`, `expired_token` are read from the JSON `code`, which `GSHttp` preserves as the error's detail; `_envelope_code()` recovers it without a second request.
- **`slow_down` must be honoured** over the configured interval. Polling faster than told burns the grant.
- **`token_reuse` on refresh is not a generic error.** The backbone has signed every device out. `GSAuthClient` clears the store and emits `session_revoked` so the UI can show a security notice.
- **`ClientInfoSchema.platform` has no `web` member.** A browser build reports `unknown` via `GSPlatform.backbone_platform()` rather than failing validation.
- **Integration requests need `ts` (Unix *seconds*) and `nonce`.** Milliseconds are refused by the backbone's skew window. `GSBackboneClient._stamp()` is the only place this is done.
- **A retry is a new request with a new nonce.** The backbone refuses a nonce it has seen, so `GSHttp`'s own retry (which resends the same bytes) is off for the backbone client, and `GSBackboneClient` retries transport errors, 5xx and 429 itself (`max_retries`, 0 = never), stamping each attempt. A failure after retries keeps the first one's status and body in its detail and context (`first_http`, `first_error`, `attempts`): the first is usually the real fault.
- **Roster reports are absolute, not incremental.** An empty list closes every session, so a server that does not know its roster must not call the endpoint. When the list is truncated at 512, `setCount` is forced off, or it would report a count lower than the truth every tick.
- **`SERVER_STATS` and `SERVER_USERS` are separate scopes** on purpose: a player list is personal data about third parties. `report_roster` is off by default.

## The backbone URL is a security property

`GSAuthConfig.backbone_url` defaults to `https://moddingcommunity.com`. A default endpoint decides where a device-code grant (the opening request of an authentication flow) is sent, so a wrong default that does not resolve fails loudly, and the same wrong default the day somebody registers the name fails *quietly*. Check any default URL against what website-city actually serves. See [history](history.md).

**Overriding it.** It is an ordinary `GSConfig` field: `GS_AUTH_BACKBONE_URL`, `--auth-backbone-url` and a JSON file, layered by `GSAuthClient.start()`. A browser build has neither an environment nor an argv, so a web client is told through a JSON file shipped in its export; `gs-server-deploy/client/auth.json` is the worked example. It is deliberately **not** read from the page's query string: this URL decides where a single-use sign-in code is redeemed, and a link that could aim it at another host would be a credential-forwarding link.

## Back-off and logging once

When a call to the backbone fails for the backbone's reasons (transport, 5xx, 429) after its retries, `GSBackboneClient` stops calling for `backoff_base_sec` (10 s), doubling per further failed call up to `backoff_max_sec` (300 s; 0 = no ceiling; base 0 turns it off). A call during the pause returns at once with a `GSError.CODE_STATE` result whose `context.backoff` is true (`GSBackboneClient.is_backoff(res)`) and whose `retry_after` is the time left; callers that log failures should skip those. The outage logs one WARN when it starts and one INFO when the backbone answers again; reports in between log at debug. A 4xx never pauses. gs-stats's reporter still warns per flush on a pause result (not yet changed).
