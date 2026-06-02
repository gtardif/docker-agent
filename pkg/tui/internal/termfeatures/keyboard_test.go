package termfeatures

import "testing"

func TestSupportsModifiedEnter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "wezterm term program", env: map[string]string{"TERM_PROGRAM": "WezTerm"}, want: true},
		{name: "wezterm pane", env: map[string]string{"WEZTERM_PANE": "1"}, want: true},
		{name: "wezterm socket", env: map[string]string{"WEZTERM_UNIX_SOCKET": "/tmp/wezterm.sock"}, want: true},
		{name: "wezterm term", env: map[string]string{"TERM": "wezterm"}, want: true},
		{name: "vscode integrated terminal", env: map[string]string{"TERM_PROGRAM": "vscode"}, want: true},
		{name: "vscode case-insensitive", env: map[string]string{"TERM_PROGRAM": "VSCode"}, want: true},
		{name: "kitty term program", env: map[string]string{"TERM_PROGRAM": "kitty"}, want: true},
		{name: "kitty window id", env: map[string]string{"KITTY_WINDOW_ID": "1"}, want: true},
		{name: "kitty term program case-insensitive", env: map[string]string{"TERM_PROGRAM": "Kitty"}, want: true},
		{name: "apple terminal", env: map[string]string{"TERM_PROGRAM": "Apple_Terminal", "TERM": "xterm-256color"}, want: false},
		{name: "iterm2", env: map[string]string{"TERM_PROGRAM": "iTerm.app", "TERM": "xterm-256color"}, want: false},
		{name: "gnome terminal", env: map[string]string{"TERM": "xterm-256color"}, want: false},
		{name: "nil getenv", env: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var getenv func(string) string
			if tt.env != nil {
				getenv = func(key string) string { return tt.env[key] }
			}

			if got := SupportsModifiedEnter(getenv); got != tt.want {
				t.Fatalf("SupportsModifiedEnter() = %v, want %v", got, tt.want)
			}
		})
	}
}
