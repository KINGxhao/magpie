package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/plugin"
	"github.com/yetone/magpie/internal/settings"
)

// A backup file made with keys carries the subscriptions' sign-ins, and
// the Copilot editors' token as an account of magpie's; put back on
// another computer, they are added beside its own, which stay as they are.
func TestBackupFileCarriesSignIns(t *testing.T) {
	home(t)
	appdir.UseExecutable("")
	subscriptionMachine(t)
	os.MkdirAll(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "github-copilot"), 0o700)
	writeJSON(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "github-copilot", "apps.json"), map[string]any{
		"github.com:Iv1.b507a08c87ecfe98": map[string]any{"user": "octocat", "oauth_token": "fixture-copilot-editor-token"},
	})

	synced, err := Collect(true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if synced.SignIns != nil {
		t.Fatal("Collect, which sync uses, carried sign-ins")
	}
	keyless, _ := Collect(false, "test")
	if err := WithSignIns(&keyless); err != nil || keyless.SignIns != nil {
		t.Fatalf("a backup without keys carried sign-ins (%v)", err)
	}
	b, _ := Collect(true, "test")
	if err := WithSignIns(&b); err != nil {
		t.Fatal(err)
	}
	data, err := Seal(b, "pw")
	if err != nil {
		t.Fatal(err)
	}

	// another computer, its own Codex account and plugin key signed in
	home(t)
	if err := os.MkdirAll(settings.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(settings.Dir(), "logins.json"), []map[string]any{
		{"agent": "codex", "user": "me@example.com", "seen": "2026-09-01T12:00:00Z",
			"auth": map[string]any{"tokens": map[string]any{"refresh_token": "fixture-local-codex"}}},
	})
	writeJSON(t, plugin.AuthPath(), map[string]any{"opencode-copilot": map[string]any{"type": "api", "key": "fixture-local-plugin-key"}})

	opened, err := Open(data, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Restore(opened, Parts{Providers: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.SignedIn) == 0 {
		t.Fatal("restore added no sign-in")
	}
	logins, _ := os.ReadFile(filepath.Join(settings.Dir(), "logins.json"))
	auth, _ := os.ReadFile(plugin.AuthPath())
	for _, want := range []string{fixtureClaudeRefresh, "fixture-local-codex", "fixture-copilot-editor-token", "octocat"} {
		if !strings.Contains(string(logins), want) {
			t.Errorf("logins.json lacks %q after the restore:\n%s", want, logins)
		}
	}
	if strings.Contains(string(logins), fixtureCodexRefresh) {
		t.Error("the backup's Codex account replaced this computer's own of the same name")
	}
	for _, want := range []string{fixturePluginRefresh, fixturePluginSlot, fixturePluginKey, "fixture-local-plugin-key"} {
		if !strings.Contains(string(auth), want) {
			t.Errorf("plugin-auth.json lacks %q after the restore:\n%s", want, auth)
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(auth, &m); err != nil || len(m) != 4 {
		t.Errorf("plugin-auth.json holds %d sign-ins, want 4 (%v)", len(m), err)
	}

	again, err := Restore(opened, Parts{Providers: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.SignedIn) != 0 {
		t.Errorf("a second restore added %v again", again.SignedIn)
	}
}
