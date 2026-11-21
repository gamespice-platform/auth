class_name GSAuthTicket
extends RefCounted

## A short-lived, audience-scoped, single-use, RS256-signed credential proving who a connecting player is.
##
## Encoded as a compact JWS, see [GSJwt]. Why a ticket and not the account token: docs/tickets.md.

const CHANNEL := "auth.ticket"


## Mints a ticket. Issuer side only; needs the private key.
static func issue(
	identity: GSAuthIdentity,
	server_id: String,
	private_key_pem: String,
	issuer_name: String,
	ttl_sec: int,
	key_id: String = "default",
	nonce: String = ""
) -> GSResult:
	if server_id.strip_edges() == "":
		return GSResult.fail(
			GSError.CODE_INVALID,
			"A ticket must name a server.",
			"an unscoped ticket is valid everywhere, which defeats the purpose"
		)

	if not identity.is_valid():
		return GSResult.fail(
			GSError.CODE_INVALID, "Cannot issue a ticket for an invalid identity."
		)

	var claims := GSJwt.base_claims(
		issuer_name, identity.uid, server_id, ttl_sec
	)

	# The identity travels inside the ticket so the server needs no lookup. It is
	# a snapshot: a name changed after issue is stale until the next ticket, which
	# is the correct trade for not making every join a backbone round trip.
	claims["name"] = identity.display_name
	claims["username"] = identity.username
	claims["provider"] = identity.provider
	claims["role"] = identity.role

	if identity.avatar_url != "":
		claims["avatar"] = identity.avatar_url
	if not identity.claims.is_empty():
		claims["claims"] = identity.claims
	# Binds the ticket to the one connection whose challenge carried this nonce.
	if nonce != "":
		claims["nonce"] = nonce

	return GSJwt.encode_rs256(claims, private_key_pem, key_id)


## Verifies a ticket and returns its [GSAuthIdentity].
##
## [param expected_server_id] must match the audience; [code]""[/code] disables the check and makes every ticket universal.
static func verify(
	ticket: String,
	public_key_pem: String,
	expected_server_id: String,
	leeway_sec: int = 60
) -> GSResult:
	var verified := GSJwt.verify_rs256(ticket, public_key_pem, leeway_sec)
	if not verified.ok:
		return verified

	var claims: Dictionary = verified.value

	var audience := str(claims.get("aud", ""))
	if expected_server_id != "":
		if audience != expected_server_id:
			return GSResult.fail(
				GSError.CODE_FORBIDDEN,
				"This ticket was issued for a different server.",
				"ticket names '%s', this server is '%s'"
					% [audience, expected_server_id]
			)
	else:
		GSLog.warn(
			CHANNEL,
			"verifying a ticket without checking its audience — any ticket for "
			+ "any server will be accepted"
		)

	var subject := str(claims.get("sub", ""))
	if subject == "":
		return GSResult.fail(
			GSError.CODE_INVALID, "The ticket names no user."
		)

	var identity := GSAuthIdentity.new()
	identity.uid = subject
	identity.provider = str(claims.get("provider", "backbone"))
	# uid is namespaced "provider:id"; recovering the bare id keeps the two
	# consistent for anything matching on provider_id.
	identity.provider_id = subject.split(":", true, 1)[-1]
	identity.display_name = str(claims.get("name", ""))
	identity.username = str(claims.get("username", ""))
	identity.avatar_url = str(claims.get("avatar", ""))
	identity.role = str(claims.get("role", ""))
	identity.authenticated_at = int(claims.get("iat", 0))
	identity.expires_at = int(claims.get("exp", 0))

	if claims.get("claims") is Dictionary:
		identity.claims = claims["claims"]

	if identity.display_name == "":
		identity.display_name = identity.username if identity.username != "" else "Player"

	return GSResult.success({
		"identity": identity,
		"jti": str(claims.get("jti", "")),
		"exp": int(claims.get("exp", 0)),
		"nonce": str(claims.get("nonce", "")),
	})


## Reads a ticket's audience without verifying it; for routing only, never for authorisation.
static func peek_audience(ticket: String) -> String:
	var peeked := GSJwt.peek(ticket)
	if not peeked.ok:
		return ""
	var d: Dictionary = peeked.value
	return str((d["payload"] as Dictionary).get("aud", ""))
