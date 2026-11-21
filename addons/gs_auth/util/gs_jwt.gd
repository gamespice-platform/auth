class_name GSJwt
extends RefCounted

## Compact JWS encoding, signing and verification for [GSAuthTicket].
##
## RS256 and HS256 only. HS256 lets any verifier forge, so use RS256 across a trust boundary.

# No log channel: a codec. Every refusal is a GSResult, and a verifier that logged a bad
# token would write a line per forged request with nobody to name. GSAuthServer, which
# holds the request, counts the refusal and emits it as `rejected`.

const ALG_RS256 := "RS256"
const ALG_HS256 := "HS256"

## Seconds of clock skew tolerated on [code]exp[/code] and [code]nbf[/code].
const DEFAULT_LEEWAY_SEC := 60



## Signs a payload with an RSA private key.
static func encode_rs256(
	payload: Dictionary,
	private_key_pem: String,
	key_id: String = ""
) -> GSResult:
	var header := {"alg": ALG_RS256, "typ": "JWT"}
	if key_id != "":
		header["kid"] = key_id

	var signing_input := _signing_input(header, payload)

	var key := CryptoKey.new()
	var err := key.load_from_string(private_key_pem, false)
	if err != OK:
		return GSResult.fail(
			GSError.CODE_INVALID,
			"Could not read the signing key.",
			error_string(err)
		)

	var crypto := Crypto.new()
	var sig := crypto.sign(
		HashingContext.HASH_SHA256, _sha256(signing_input), key
	)

	if sig.is_empty():
		return GSResult.fail(
			GSError.CODE_INTERNAL,
			"Signing failed.",
			"the key may be a public key, or too small"
		)

	return GSResult.success(
		"%s.%s" % [signing_input, GSHash.base64url_encode(sig)]
	)


## Signs a payload with a shared secret; only safe inside one trust domain.
static func encode_hs256(payload: Dictionary, secret: String) -> GSResult:
	if secret.length() < 32:
		# A short HMAC secret is brute-forceable offline from a single token, and
		# a token is by design something the attacker holds.
		return GSResult.fail(
			GSError.CODE_INVALID,
			"The HS256 secret must be at least 32 characters.",
			"got %d" % secret.length()
		)

	var header := {"alg": ALG_HS256, "typ": "JWT"}
	var signing_input := _signing_input(header, payload)

	var mac := GSHash.hmac_sha256(
		secret.to_utf8_buffer(), signing_input.to_utf8_buffer()
	)

	return GSResult.success(
		"%s.%s" % [signing_input, GSHash.base64url_encode(mac)]
	)



## Reads claims [b]without verifying[/b]; never use the result for an authorisation decision.
static func peek(token: String) -> GSResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return GSResult.fail(
			GSError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var header: Variant = JSON.parse_string(
		GSHash.base64url_decode_text(parts[0])
	)
	var payload: Variant = JSON.parse_string(
		GSHash.base64url_decode_text(parts[1])
	)

	if not (header is Dictionary) or not (payload is Dictionary):
		return GSResult.fail(
			GSError.CODE_PARSE, "Token segments are not JSON objects."
		)

	return GSResult.success({"header": header, "payload": payload})


## Verifies a token against an RSA public key and checks its time claims.
##
## [param expected_algorithm] is pinned by the caller and must match the token's [code]alg[/code], or [code]none[/code] and HS256-with-the-public-key forgeries pass.
static func verify_rs256(
	token: String,
	public_key_pem: String,
	leeway_sec: int = DEFAULT_LEEWAY_SEC
) -> GSResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return GSResult.fail(
			GSError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var peeked := peek(token)
	if not peeked.ok:
		return peeked

	var d: Dictionary = peeked.value
	var header: Dictionary = d["header"]

	if str(header.get("alg", "")) != ALG_RS256:
		return GSResult.fail(
			GSError.CODE_INTEGRITY,
			"Unexpected token algorithm.",
			"expected %s, got '%s'" % [ALG_RS256, header.get("alg", "")]
		)

	var key := CryptoKey.new()
	var err := key.load_from_string(public_key_pem, true)
	if err != OK:
		return GSResult.fail(
			GSError.CODE_INVALID,
			"Could not read the verification key.",
			error_string(err)
		)

	var signing_input := "%s.%s" % [parts[0], parts[1]]
	var sig := GSHash.base64url_decode(parts[2])

	if sig.is_empty():
		return GSResult.fail(
			GSError.CODE_INTEGRITY, "The token signature is not valid base64url."
		)

	var crypto := Crypto.new()
	if not crypto.verify(
		HashingContext.HASH_SHA256, _sha256(signing_input), sig, key
	):
		return GSResult.fail(
			GSError.CODE_INTEGRITY, "The token signature is invalid."
		)

	return _check_times(d["payload"], leeway_sec)


## Verifies a token against a shared secret and checks its time claims.
static func verify_hs256(
	token: String,
	secret: String,
	leeway_sec: int = DEFAULT_LEEWAY_SEC
) -> GSResult:
	var parts := token.split(".")
	if parts.size() != 3:
		return GSResult.fail(
			GSError.CODE_PARSE, "Malformed token.", "expected 3 segments"
		)

	var peeked := peek(token)
	if not peeked.ok:
		return peeked

	var d: Dictionary = peeked.value
	var header: Dictionary = d["header"]

	if str(header.get("alg", "")) != ALG_HS256:
		return GSResult.fail(
			GSError.CODE_INTEGRITY,
			"Unexpected token algorithm.",
			"expected %s, got '%s'" % [ALG_HS256, header.get("alg", "")]
		)

	var signing_input := "%s.%s" % [parts[0], parts[1]]
	var expected := GSHash.hmac_sha256(
		secret.to_utf8_buffer(), signing_input.to_utf8_buffer()
	)
	var actual := GSHash.base64url_decode(parts[2])

	# Constant time: a byte-by-byte comparison that returns early leaks how much
	# of a forged MAC was right, which reduces forgery to 32 rounds of 256 tries.
	if not GSHash.constant_time_equal(expected, actual):
		return GSResult.fail(
			GSError.CODE_INTEGRITY, "The token signature is invalid."
		)

	return _check_times(d["payload"], leeway_sec)


## Checks [code]exp[/code] and [code]nbf[/code] against the wall clock.
static func _check_times(payload: Dictionary, leeway_sec: int) -> GSResult:
	var now := int(Time.get_unix_time_from_system())

	if payload.has("exp"):
		var exp := int(payload["exp"])
		if now > exp + leeway_sec:
			return GSResult.fail(
				GSError.CODE_AUTH,
				"This login has expired.",
				"expired %d seconds ago" % (now - exp)
			)

	if payload.has("nbf"):
		var nbf := int(payload["nbf"])
		if now + leeway_sec < nbf:
			return GSResult.fail(
				GSError.CODE_AUTH,
				"This token is not valid yet.",
				"valid in %d seconds" % (nbf - now)
			)

	return GSResult.success(payload)


static func _signing_input(header: Dictionary, payload: Dictionary) -> String:
	return "%s.%s" % [
		GSHash.base64url_encode_text(JSON.stringify(header)),
		GSHash.base64url_encode_text(JSON.stringify(payload)),
	]


static func _sha256(text: String) -> PackedByteArray:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	ctx.update(text.to_utf8_buffer())
	return ctx.finish()


## Standard claims for a new token.
static func base_claims(
	issuer: String,
	subject: String,
	audience: String,
	ttl_sec: int
) -> Dictionary:
	var now := int(Time.get_unix_time_from_system())
	return {
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now,
		"nbf": now,
		"exp": now + ttl_sec,
		# A per-token id, so a verifier can refuse replays within the token's
		# lifetime. Without it a captured ticket is reusable until it expires.
		"jti": GSHash.random_token(16),
	}
