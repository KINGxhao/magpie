package provider

// Subscription sign-ins a backup file carries when it is made with keys, so
// another computer has the accounts without signing in again. Sync never
// carries them: two computers refreshing one rotating token sign each
// other out.

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/plugin"
)

// SignIns are the sign-ins magpie keeps of its own (logins.json and
// plugin-auth.json), and Copilot's editors' or CLI's token as an account
// of magpie's.
type SignIns struct {
	Logins     []savedLogin               `json:"logins,omitempty"`
	PluginAuth map[string]json.RawMessage `json:"pluginAuth,omitempty"`
}

// Count is how many accounts s carries.
func (s *SignIns) Count() int {
	if s == nil {
		return 0
	}
	return len(s.Logins) + len(s.PluginAuth)
}

// ExportSignIns gathers the sign-ins this computer can hand on. Left out:
// an agent's own sign-in that holds no credential (it is the agent's,
// read where the agent keeps it), a Grok account's home folder, the rows
// that list a plugin's accounts (plugin-auth.json is their truth), and a
// plugin sign-in that only points at the agent's own.
func ExportSignIns() (*SignIns, error) {
	if discoveryOff() {
		return nil, errAccountDiscoveryOff
	}
	s := &SignIns{}
	ls := readLogins()
	for _, l := range ls {
		if l.own() || l.Home != "" || strings.HasPrefix(l.Agent, "plugin:") {
			continue
		}
		l.Order, l.First, l.Held, l.Hidden, l.Paused = 0, false, false, "", false
		s.Logins = append(s.Logins, l)
	}
	if app, ok := copilotLogin(copilotConfigDir()); ok && app.Token != "" {
		name := CopilotAccountName(firstNonEmpty(app.User, "GitHub"), app.Host)
		if !slices.ContainsFunc(s.Logins, func(l savedLogin) bool { return l.Agent == "copilot" && accountKey(l.User) == accountKey(name) }) {
			a := map[string]any{"oauth_token": app.Token}
			if app.Host != "" {
				a["host"] = app.Host
			}
			if app.cli {
				a["cli"] = true
			}
			auth, _ := json.Marshal(a)
			l := savedLogin{Agent: "copilot", User: name, Auth: auth, Seen: time.Now().UTC().Truncate(time.Second)}
			for _, o := range ls {
				if o.Agent == "copilot" && accountKey(o.User) == accountKey(name) {
					l.Plan = o.Plan
				}
			}
			s.Logins = append(s.Logins, l)
		}
	}
	auths, err := plugin.AuthEntries()
	if err != nil {
		return nil, err
	}
	for k, raw := range auths {
		var a map[string]any
		if json.Unmarshal(raw, &a) != nil || pluginOwn(plugin.ProviderOf(k), a) {
			continue
		}
		if s.PluginAuth == nil {
			s.PluginAuth = map[string]json.RawMessage{}
		}
		s.PluginAuth[k] = raw
	}
	return s, nil
}

// ImportSignIns keeps the sign-ins in s this computer doesn't have: an
// account of the same agent and name here, its own or one magpie keeps,
// stays as it is. It gives what was added, as "agent: account".
func ImportSignIns(s *SignIns) ([]string, error) {
	if s.Count() == 0 {
		return nil, nil
	}
	if discoveryOff() {
		return nil, errAccountDiscoveryOff
	}
	var added []string
	if len(s.Logins) > 0 {
		ownCopilot := copilotOwnUser(copilotConfigDir())
		loginsMu.Lock()
		ls := readLogins()
		n := len(ls)
		for _, in := range s.Logins {
			if in.Agent == "" || in.own() || in.Home != "" {
				continue
			}
			same := func(l savedLogin) bool { return l.Agent == in.Agent && accountKey(l.User) == accountKey(in.User) }
			if slices.ContainsFunc(ls, same) || in.Agent == "copilot" && accountKey(ownCopilot) == accountKey(in.User) {
				continue
			}
			if slices.ContainsFunc(ls, func(l savedLogin) bool { return loginID(l) == loginID(in) }) {
				in.ID = ""
			}
			ls = append(ls, in)
			added = append(added, in.Agent+": "+in.User)
		}
		var err error
		if len(ls) > n {
			err = writeLogins(ls)
		}
		loginsMu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	keys, err := plugin.AddAuths(s.PluginAuth)
	return append(added, keys...), err
}
