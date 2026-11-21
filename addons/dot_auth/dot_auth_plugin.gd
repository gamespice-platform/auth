@tool
extends EditorPlugin

## Editor entry point for GameSpice Auth. Registers inspector types only.

const _ICON := "res://addons/dot_auth/icon_placeholder.svg"


func _enter_tree() -> void:
	var icon: Texture2D = null
	if ResourceLoader.exists(_ICON):
		icon = load(_ICON) as Texture2D

	add_custom_type(
		"GSAuthClient",
		"Node",
		load("res://addons/dot_auth/client/dot_auth_client.gd"),
		icon
	)
	add_custom_type(
		"GSAuthServer",
		"Node",
		load("res://addons/dot_auth/server/dot_auth_server.gd"),
		icon
	)
	add_custom_type(
		"GSAuthIssuer",
		"Node",
		load("res://addons/dot_auth/server/dot_auth_issuer.gd"),
		icon
	)
	add_custom_type(
		"GSAuthSessionReporter",
		"Node",
		load("res://addons/dot_auth/server/dot_auth_session_reporter.gd"),
		icon
	)


func _exit_tree() -> void:
	remove_custom_type("GSAuthSessionReporter")
	remove_custom_type("GSAuthIssuer")
	remove_custom_type("GSAuthServer")
	remove_custom_type("GSAuthClient")
