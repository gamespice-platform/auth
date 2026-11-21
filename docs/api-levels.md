# API levels

What each level of `GSAuthApi` added. The bump rule is on `GSAddonApi`.

1. Everything before the file existed (an absent file reads as 1).
2. `GSAuthSessionReporter.report_offline_now()`, `follow_server()` and `offline_timeout_sec`; `GSAuthServer.session_reporter` and `create_session_reporter` (the auth server builds the reporter itself when `session_report_url` is set).
3. `GSAuthClient.SERVICE` (the client registers itself as `dot_auth_client`, the name `GSClientLink` looks up to attach a sign-in) and `GSAuthClient.account_key()`.
4. `GSAuthClient.redeem_handoff(code)`, the launcher's sign-in code on any platform.
5. `GSAuthClient.request_join_token(audience)` and `is_first_party(audience)`; `GSAuthConfig.first_party_audiences`, `join_audience` and `is_audience()`; `GSAuthServer.join_audience()`. INTROSPECT now carries a join token, never an access token.
6. `GSAuthConfig.apply_cfg_file` and `load_cfg` read `cfg/addons/dot_auth/auth.yml` and the operator's `cfg/server/addons/dot_auth/`, with the flat `cfg/auth.yml` as a shim until the end of 2026. Needs GameSpice Core API level 16 (`GSAddonConfig.apply_file`). Secrets stay file-only.
7. Connect tickets by dialled address: `GSAuthClient.request_ticket_for_address()`; `GSAuthServer.adopt_ticket_trust()`, `ticket_trust_ready()` and `ticket_key_wanted` (key rotation by kid); `GSAuthConfig.adopt_ticket_trust`, `ticket_public_keys`, `ticket_issuer_url`.
8. Tickets bound to a connection: `authenticate(credential, rate_key, connection_nonce)`, `request_ticket_for_address(address, issuer_url, nonce)`, `GSAuthTicket.issue(..., nonce)`, `GSAuthConfig.require_ticket_binding` and `ticket_replay_max`; `revoke_ticket_keys()`. A ticket with no jti is refused; the site's revoked kids and refreshSec are honoured.
