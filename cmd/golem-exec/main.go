// golem-exec is the local shield's shell shim (https://docs.golem.team/shield).
//
// Installed as the agent's shell (CLAUDE_CODE_SHELL=~/.golem/bin/golem-zsh),
// it runs the real shell, with the arguments it was given, inside a kernel
// jail the witness parameterises per session. Everything the command starts
// inherits the jail, an absolute /bin/bash included.
//
// Installed under the old PATH names (bash, sh), it still asks the witness's
// policy-check before running, as the PATH shim always did.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// jailStage is the name the shim runs itself under to apply a jail it can
// only put on its own process (Landlock, seccomp) before it execs the shell.
const jailStage = "golem-shield-jail"

func main() {
	invoked := filepath.Base(os.Args[0])
	args := os.Args[1:]
	if invoked == jailStage {
		os.Exit(runJailStage(args))
	}
	witness := witnessURL(os.Getenv("GOLEM_WITNESS_URL"))

	if invoked == "bash" || invoked == "sh" {
		cmdline := strings.TrimSpace(invoked + " " + strings.Join(args, " "))
		if denied, reason := policyCheck(witness, cmdline, invoked); denied {
			fmt.Fprintf(os.Stderr, "golem-exec: blocked by Golem policy: %s\n", reason)
			os.Exit(126)
		}
	}
	os.Exit(newShim(witness).run(realShell(invoked), args))
}

const defaultWitness = "http://127.0.0.1:39393"

// witnessURL honours an override only on loopback. The shim trusts the answer
// to decide how tightly to jail, so it must not be pointable elsewhere.
func witnessURL(override string) string {
	for _, prefix := range []string{"http://127.0.0.1:", "http://localhost:", "http://[::1]:"} {
		if strings.HasPrefix(override, prefix) && !strings.ContainsAny(strings.TrimPrefix(override, prefix), "/@?#") {
			return override
		}
	}
	return defaultWitness
}

func policyCheck(witnessURL, command, toolName string) (denied bool, reason string) {
	body, _ := json.Marshal(map[string]any{
		"tool_name":  toolName,
		"command":    command,
		"asset_type": "bash_command",
	})
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(strings.TrimRight(witnessURL, "/")+"/api/v1/policy-check",
		"application/json", bytes.NewReader(body))
	if err != nil {
		// Fail-open on transport errors so a down witness doesn't brick shells;
		// the jail below still holds.
		return false, ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(data, &out)
	if out.Action == "block" || out.Action == "gate" {
		if out.Reason == "" {
			out.Reason = out.Action
		}
		return true, out.Reason
	}
	return false, ""
}
