@tool
## Base of [GSAuthClient]: reading the backbone's response envelopes.
## Path-based, no class_name: it exists to keep each script under the size budget.
extends Node


## The app API's `{ok, data}` envelope, whatever `data` is.
## Unlike [method _unwrap], it accepts replies with no token (stats, scope keys).
func _unwrap_any(response: Variant) -> GSResult:
	if not (response is Dictionary):
		return GSResult.fail(
			GSError.CODE_PARSE, "The backbone sent an unexpected response."
		)
	var d := response as Dictionary
	if d.has("data"):
		return GSResult.success(d["data"])
	return GSResult.success(d)


## The app API's own error, when it sent one: flat `{ok: false, code, message, retryAfter?}`
## as website-city sends it, or the nested `{error: {code, message}}` shape. Keeps the
## site's code and message instead of the fallback text.
func _app_refusal(res: GSResult, fallback: String) -> GSResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = _envelope_of(res.error.detail)
	if parsed is Dictionary and (parsed as Dictionary).get("code") is String:
		var flat: Dictionary = parsed
		var err_flat := GSError.make(
			res.error.code, str(flat.get("message", fallback)), str(flat["code"])
		)
		err_flat.http_status = res.error.http_status
		err_flat.retry_after = float(flat["retryAfter"]) if flat.get("retryAfter") != null \
			else res.error.retry_after
		return GSResult.failure(err_flat)

	if parsed is Dictionary and (parsed as Dictionary).get("error") is Dictionary:
		var body: Dictionary = (parsed as Dictionary)["error"]
		var err := GSError.make(
			res.error.code, str(body.get("message", fallback)), str(body.get("code", ""))
		)
		err.http_status = res.error.http_status
		err.retry_after = res.error.retry_after
		return GSResult.failure(err)

	return res.wrap(fallback)


## Unwraps the backbone's `{ok: true, data: …}` success envelope.
func _unwrap(response: Variant) -> GSResult:
	if not (response is Dictionary):
		return GSResult.fail(
			GSError.CODE_PARSE, "The backbone sent an unexpected response."
		)

	var d := response as Dictionary

	if d.has("data"):
		var data: Variant = d["data"]
		if data is Dictionary:
			return GSResult.success(data)

	# Some endpoints answer with the payload directly. Accepting both keeps a
	# contract change from breaking sign-in outright.
	if d.has("accessToken") or d.has("deviceCode") or d.has("user"):
		return GSResult.success(d)

	return GSResult.fail(
		GSError.CODE_PARSE,
		"The backbone sent no data.",
		JSON.stringify(d).substr(0, 200)
	)


## The backbone's error `code` from a failed request, or [code]""[/code].
## It rides in the body of non-2xx replies, which [GSHttp] keeps as the detail.
func _envelope_code(res: GSResult) -> String:
	if res.ok:
		return ""
	if res.error == null or res.error.detail == "":
		return ""

	var parsed: Variant = _envelope_of(res.error.detail)
	if not (parsed is Dictionary):
		return ""

	return str((parsed as Dictionary).get("code", ""))


## A refusal's body as a Dictionary, or null, without the engine's own ERROR line.
## A transport failure or a proxy's HTML page is text, and `JSON.parse_string` prints an
## unsuppressible ERROR for each before answering null.
static func _envelope_of(detail: String) -> Variant:
	if not detail.strip_edges().begins_with("{"):
		return null
	var json := JSON.new()
	if json.parse(detail) != OK:
		return null
	return json.data


## The issuer's own refusal when it sent one, instead of "HTTP 403": its message is written for the player. [GSHttp] keeps the body as the error's detail.
func _issuer_refusal(res: GSResult, fallback: String) -> GSResult:
	if res.ok or res.error == null:
		return res

	var parsed: Variant = _envelope_of(res.error.detail)
	if parsed is Dictionary and (parsed as Dictionary).has("error"):
		var body := parsed as Dictionary
		var err := GSError.make(
			str(body.get("code", res.error.code)),
			str(body["error"]),
			fallback
		)
		err.http_status = res.error.http_status
		err.retry_after = res.error.retry_after
		return GSResult.failure(err)

	return res.wrap(fallback)
