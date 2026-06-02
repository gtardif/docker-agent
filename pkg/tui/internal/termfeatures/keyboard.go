package termfeatures

import "strings"

// SupportsModifiedEnter returns true for terminals that can distinguish
// Shift+Enter from Enter even when they do not report Kitty keyboard flags.
// This is a pre-render heuristic; the runtime KeyboardEnhancementsMsg path
// also sets this flag once the terminal replies to the Kitty protocol query.
func SupportsModifiedEnter(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}

	termProgram := strings.ToLower(getenv("TERM_PROGRAM"))
	term := strings.ToLower(getenv("TERM"))

	// WezTerm: supports Kitty protocol and sets its own env vars.
	if termProgram == "wezterm" ||
		getenv("WEZTERM_PANE") != "" ||
		getenv("WEZTERM_UNIX_SOCKET") != "" ||
		strings.Contains(term, "wezterm") {
		return true
	}

	// VSCode integrated terminal (xterm.js >= 5.3) supports the Kitty protocol.
	if termProgram == "vscode" {
		return true
	}

	// Kitty terminal itself.
	if termProgram == "kitty" || getenv("KITTY_WINDOW_ID") != "" {
		return true
	}

	return false
}
