@tool
class_name GSBackboneClient
extends Node

## Reports a dedicated server's own state to its listing on the backbone, with a server-scoped credential.
##
## The credential is bound to one server row, so nothing sent names a server and a leaked token cannot be pointed at another listing. Every request carries a Unix-seconds `ts` and a random `nonce` for replay protection.

const CHANNEL := "backbone"

## Registry name, so consumers (chat relay, stats reporter, leaderboard) find the client without the host wiring each one.
const SERVICE := &"gs_backbone_client"

## Scopes the backbone requires. Documented here so a misconfigured integration
## produces a useful log line rather than an opaque 403.
const SCOPE_STATS := "SERVER_STATS"
const SCOPE_USERS := "SERVER_USERS"

## The backbone caps a roster report at this many players.
const MAX_REPORTED_PLAYERS := 512

## Emitted after each report, successful or not.
signal reported(kind: String, result: GSResult)

@export var config: GSAuthConfig = null

## Report automatically on a timer once [method start] has run.
@export var auto_report: bool = true

## Retries after a retryable failure (transport, 5xx, 429); 0 sends once.
##
## Retried HERE, not in [GSHttp]: every attempt needs its own [code]ts[/code] and
## [code]nonce[/code], because the backbone remembers a nonce and refuses it the second
## time. GSHttp resending the same bytes turned a real 500 into a 400 "Unauthorized" on
## the retry, and the 500 was never logged.
@export_range(0, 10, 1, "or_greater") var max_retries: int = 2

## First pause, seconds, after a call that failed for a reason that is the backbone's (transport, 5xx, 429) once its retries are spent. Doubles per further failed call up to [member backoff_max_sec]; 0 turns the back-off off. During a pause every call fails at once without touching the network, so a wedged backbone is not hit by every report, loadout and ticket call of every server, and the log carries one line for the outage rather than one per report.
@export var backoff_base_sec: float = 10.0

## Longest pause; 0 means no ceiling.
@export var backoff_max_sec: float = 300.0

var _http: GSHttp = null
var _fail_streak: int = 0
var _resume_at_msec: int = 0
var _timer: Timer = null
var _limiter: GSRateLimiter = null
var _started: bool = false

## Supplies the current server state at report time (set by GameSpice Server), sampled when sent, not when it last changed.
var stats_provider: Callable = Callable()

## Supplies the current roster. Same contract as [member stats_provider].
var roster_provider: Callable = Callable()

## Registry name to publish under, or empty not to publish.
@export var register_as: StringName = SERVICE

var _last_error: String = ""
var _report_count: int = 0


func start() -> GSResult:
	if _started:
		return GSResult.success(self)

	if config == null:
		return GSResult.fail(
			GSError.CODE_STATE, "GSBackboneClient has no config."
		)

	if config.integration_token.strip_edges() == "":
		return GSResult.fail(
			GSError.CODE_STATE,
			"No integration token; server reporting is off.",
			"create a server-scoped integration on the site and set "
			+ "GSAuthConfig.integration_token"
		)

	_http = GSHttp.new()
	_http.name = "BackboneHttp"
	_http.timeout_sec = 15.0
	# Signed requests are retried by _signed(), re-stamped each time; see max_retries.
	_http.max_retries = 0
	add_child(_http)

	# A local ceiling so a bug — a retry loop, a stuck timer — cannot get the
	# server's credential rate-limited or revoked by the backbone.
	_limiter = GSRateLimiter.new(
		float(config.backbone_requests_per_minute) / 60.0,
		float(config.backbone_requests_per_minute)
	)

	if auto_report and config.report_interval_sec > 0.0:
		_timer = Timer.new()
		_timer.wait_time = config.report_interval_sec
		_timer.autostart = true
		_timer.timeout.connect(_on_report_due)
		add_child(_timer)

	_started = true

	if register_as != &"":
		GSRegistry.register(register_as, self)

	GSLog.info(
		CHANNEL,
		"backbone reporting ready",
		{
			"url": config.backbone_url,
			"interval": config.report_interval_sec,
			"roster": config.report_roster,
		}
	)

	return GSResult.success(self)


func _exit_tree() -> void:
	if register_as != &"" and GSRegistry.get_service(register_as) == self:
		GSRegistry.unregister(register_as)

	# A final "offline" so the listing does not show a dead server as full for
	# however long the backbone's staleness window is.
	if _started and _http != null:
		pass


## Reports offline and waits for it. Call before shutting down.
func report_offline() -> GSResult:
	if not _started:
		return GSResult.success(false)
	return await report_stats({"online": false, "curUsers": 0})



## Sends live server state as a PATCH: absent fields are left alone. Keys mirror the backbone's `IngestServerStatsInput`.
func report_stats(stats: Dictionary) -> GSResult:
	if not _started:
		return GSResult.fail(GSError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return GSResult.fail(
			GSError.CODE_RATE_LIMITED,
			"Local backbone request limit reached."
		)

	var body := stats.duplicate()

	# An empty string is refused by the backbone rather than treated as "clear",
	# so a reporter that does not know its map must omit the field entirely.
	if body.has("map") and str(body["map"]).strip_edges() == "":
		body.erase("map")

	# Clamp rather than let the backbone refuse the whole report: a bad number
	# from a game mode should not stop the player count being updated.
	for key in ["curUsers", "maxUsers", "bots"]:
		if body.has(key):
			body[key] = clampi(int(body[key]), 0, 10_000)

	if not body.has("os"):
		body["os"] = _os_tag()
	if not body.has("dedicated"):
		body["dedicated"] = GSPlatform.is_headless()

	var res := await _signed_post(config.server_stats_endpoint(), body)

	_note(res, "stats")
	reported.emit("stats", res)
	return res


## Sends the whole current roster.
##
## Absolute, not incremental: one dropped incremental report would leave somebody "online" forever. An empty list closes every open session, so a server that does not know its roster must not call this. Needs `SERVER_USERS`, kept apart from `SERVER_STATS` because a player list is personal data.
func report_users(
	users: Array,
	set_count: bool = true
) -> GSResult:
	if not _started:
		return GSResult.fail(GSError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return GSResult.fail(
			GSError.CODE_RATE_LIMITED,
			"Local backbone request limit reached."
		)

	var cleaned: Array = []

	for entry in users:
		if not (entry is Dictionary):
			continue

		var u := entry as Dictionary
		var name := str(u.get("name", "")).strip_edges()
		if name == "":
			continue

		var out := {"name": name.substr(0, 128)}

		if u.has("steamId") and str(u["steamId"]) != "":
			out["steamId"] = str(u["steamId"]).substr(0, 32)
		if u.has("score"):
			out["score"] = clampi(int(u["score"]), -1_000_000, 1_000_000)
		if u.has("seconds"):
			out["seconds"] = clampi(int(u["seconds"]), 0, 31_536_000)

		cleaned.append(out)

		if cleaned.size() >= MAX_REPORTED_PLAYERS:
			break

	# Truncating silently would make setCount a lie, so it is turned off when the
	# list did not fit — exactly the case the backbone's own docs warn about.
	var truncated := users.size() > cleaned.size()
	if truncated:
		GSLog.warn(
			CHANNEL,
			"roster truncated for reporting",
			{"had": users.size(), "sent": cleaned.size()}
		)

	var body := {
		"users": cleaned,
		"setCount": set_count and not truncated,
	}

	var res := await _signed_post(config.server_users_endpoint(), body)

	_note(res, "users")
	reported.emit("users", res)
	return res


## Resolves an in-game name to a site member, within a party only; it is not a general name lookup.
func lookup_user(
	party_id: String,
	name: String,
	steam_id: String = ""
) -> GSResult:
	if not _started:
		return GSResult.fail(GSError.CODE_STATE, "Not started.")

	var query := "partyId=%s&name=%s" % [
		party_id.uri_encode(), name.uri_encode()
	]
	if steam_id != "":
		query += "&steamId=%s" % steam_id.uri_encode()

	var url := config.integration_endpoint("user/lookup") + "?" + query
	var send := func() -> GSResult:
		return await _http.get_json(url, _headers())
	return await _signed(send, "user/lookup")


## POSTs to an arbitrary integration endpoint, with stamping and headers applied (the party endpoints, say).
func post_integration(path: String, body: Dictionary) -> GSResult:
	if not _started:
		return GSResult.fail(GSError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return GSResult.fail(
			GSError.CODE_RATE_LIMITED, "Local backbone request limit reached."
		)

	return await _signed_post(config.integration_endpoint(path), body)


## GETs an arbitrary integration endpoint; [code]ts[/code] goes in [param query] and the nonce in the header, as a GET has no body.
func get_integration(path: String, query: Dictionary = {}) -> GSResult:
	if not _started:
		return GSResult.fail(GSError.CODE_STATE, "Not started.")

	if not _limiter.allow("backbone"):
		return GSResult.fail(
			GSError.CODE_RATE_LIMITED, "Local backbone request limit reached."
		)

	var endpoint := config.integration_endpoint(path)
	var send := func() -> GSResult:
		var params := query.duplicate()
		params["ts"] = int(Time.get_unix_time_from_system())
		return await _http.get_json(endpoint + "?" + encode_query(params), _headers())
	return await _signed(send, path)


## `a=1&b=two`, every key and value URI-encoded.
static func encode_query(params: Dictionary) -> String:
	var parts := PackedStringArray()
	for key in params:
		parts.append("%s=%s" % [str(key).uri_encode(), str(params[key]).uri_encode()])
	return "&".join(parts)



## POSTs [param body] stamped afresh on every attempt; [param body] itself is not changed.
func _signed_post(url: String, body: Dictionary) -> GSResult:
	var send := func() -> GSResult:
		var payload := body.duplicate()
		_stamp(payload)
		return await _http.post_json(url, payload, _headers())
	return await _signed(send, url)


## Runs [param send] (one attempt, which must stamp a new [code]ts[/code] and nonce each call)
## until it succeeds, fails for good, or [member max_retries] are spent.
##
## A failure after retries keeps the FIRST failure in its detail and context
## ([code]first_http[/code], [code]first_error[/code], [code]attempts[/code]): the first is
## usually the real fault, and a later one is often only its echo.
func _signed(send: Callable, what: String) -> GSResult:
	var wait := backoff_remaining_sec()
	if wait > 0.0:
		var held := GSError.make(
			GSError.CODE_STATE, "The backbone is failing; not asking again for %.0fs." % wait
		)
		held.retry_after = wait
		held.context["backoff"] = true
		return GSResult.failure(held)

	var res := await _signed_attempts(send, what)
	_track_health(res)
	return res


## Seconds left of the pause after failed calls; 0 when calls go out.
func backoff_remaining_sec() -> float:
	return maxf(0.0, float(_resume_at_msec - Time.get_ticks_msec()) / 1000.0)


## True for the result [method _signed] hands back instead of calling during a pause.
static func is_backoff(res: GSResult) -> bool:
	return res != null and res.error != null and res.error.context.get("backoff", false)


func _track_health(res: GSResult) -> void:
	if res.ok:
		if _fail_streak > 0:
			GSLog.info(CHANNEL, "the backbone answers again", {"after_failures": _fail_streak})
		_fail_streak = 0
		_resume_at_msec = 0
		return
	if not _worth_retry(res) or backoff_base_sec <= 0.0:
		return
	_fail_streak += 1
	var pause := backoff_base_sec * pow(2.0, minf(float(_fail_streak - 1), 20.0))
	if backoff_max_sec > 0.0:
		pause = minf(pause, backoff_max_sec)
	_resume_at_msec = Time.get_ticks_msec() + int(pause * 1000.0)
	if _fail_streak == 1:
		GSLog.warn(CHANNEL, "the backbone is failing; backing off and logging once", {
			"why": res.error.message, "pause": "%.0fs" % pause,
		})


func _signed_attempts(send: Callable, what: String) -> GSResult:
	var first: GSResult = null
	var res: GSResult = null
	var attempt := 0

	while true:
		attempt += 1
		res = await send.call()

		if res.ok:
			return res

		if first == null:
			first = res

		if not _worth_retry(res) or attempt > max_retries:
			break

		var delay := _http._backoff_delay(attempt, res.error)
		GSLog.debug(CHANNEL, "retrying with a new nonce", {
			"what": what.get_slice("?", 0), "attempt": attempt, "in": "%.2fs" % delay,
			"http": res.error.http_status, "why": res.code(),
		})
		if is_inside_tree():
			await get_tree().create_timer(delay).timeout

	if attempt > 1 and first != res and res.error != null and first.error != null:
		res.error.context["attempts"] = attempt
		res.error.context["first_http"] = first.error.http_status
		res.error.context["first_error"] = str(first.error)
		var first_line := "first of %d attempts: %s" % [attempt, str(first.error)]
		res.error.detail = first_line if res.error.detail == "" else "%s; %s" % [res.error.detail, first_line]

	return res


## Transport errors, 5xx and 429 are retried; any other 4xx is a refusal, and resending it only spends the rate limit.
static func _worth_retry(res: GSResult) -> bool:
	if not res.is_retryable():
		return false
	var status := res.error.http_status
	return status == 0 or status == 429 or status >= 500


## Adds the replay-protection fields; [code]ts[/code] is Unix [b]seconds[/b], and the backbone refuses milliseconds loudly.
func _stamp(body: Dictionary) -> void:
	body["ts"] = int(Time.get_unix_time_from_system())
	body["nonce"] = GSHash.random_hex(16)


func _headers() -> Dictionary:
	return {
		"Authorization": "Bearer %s" % config.integration_token,
		# The backbone also reads the nonce from a header, which covers GET
		# requests that have no body to put it in.
		"x-tmc-nonce": GSHash.random_hex(16),
	}


## The platform tag the backbone's `ServerOsVals` enum expects.
func _os_tag() -> String:
	match GSPlatform.kind():
		GSPlatform.Kind.WINDOWS: return "WINDOWS"
		GSPlatform.Kind.LINUX: return "LINUX"
		GSPlatform.Kind.MACOS: return "MACOS"
		_: return "OTHER"


func _on_report_due() -> void:
	if stats_provider.is_valid():
		var stats: Variant = stats_provider.call()
		if stats is Dictionary:
			await report_stats(stats as Dictionary)

	if config.report_roster and roster_provider.is_valid():
		var roster: Variant = roster_provider.call()
		if roster is Array:
			await report_users(roster as Array)


func _note(res: GSResult, kind: String) -> void:
	if is_backoff(res):
		return
	if res.ok:
		_report_count += 1
		_last_error = ""
		GSLog.debug(CHANNEL, "reported", {"kind": kind})
		return

	_last_error = res.error.message

	# A 403 means the integration lacks the scope, and that will not fix itself —
	# say which scope so the operator can tick the box.
	if res.error.http_status == 403:
		GSLog.warn(
			CHANNEL,
			"the backbone refused a report; the integration may lack a scope",
			{
				"kind": kind,
				"need": SCOPE_STATS if kind == "stats" else SCOPE_USERS,
			}
		)
	elif _fail_streak > 1:
		# The outage was announced when it began; each report is only a count.
		GSLog.debug(CHANNEL, "report failed", {"kind": kind, "why": res.error.message})
	else:
		GSLog.warn(
			CHANNEL,
			"report failed",
			{"kind": kind, "why": res.error.message}
		)


func describe() -> Dictionary:
	return {
		"started": _started,
		"url": config.backbone_url if config != null else "",
		"reports": _report_count,
		"interval": config.report_interval_sec if config != null else 0.0,
		"roster": config.report_roster if config != null else false,
		"last_error": _last_error,
	}
