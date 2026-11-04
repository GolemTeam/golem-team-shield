// Package secretpattern is the shapes of machine credentials, each anchored on
// its issuer's prefix: what the redaction engine hashes and what golem-check
// looks for in an agent's config. It is the one list, so the two recognize the
// same tokens.
//
// Two rules govern it:
//
//   - Prefer recall. A missed credential is a live secret at rest; an
//     over-matched non-secret costs one unreadable value.
//   - But only issuer-anchored patterns, never generic entropy. `ghp_` and
//     `AIza` have effectively no false positives, so recall costs nothing
//     there. A generic high-entropy rule would match every UUID, digest, and
//     base64 path in the text and destroy the signal redaction exists to
//     preserve.
package secretpattern

import (
	"regexp"
	"strings"
)

// Type names follow Presidio's SCREAMING_SNAKE shape and are named for the
// issuer.
const (
	GitHubToken   = "GITHUB_TOKEN"
	GitLabToken   = "GITLAB_TOKEN"
	SlackToken    = "SLACK_TOKEN"
	AnthropicKey  = "ANTHROPIC_API_KEY"
	OpenAIKey     = "OPENAI_API_KEY"
	GoogleAPIKey  = "GOOGLE_API_KEY"
	StripeKey     = "STRIPE_KEY"
	NPMToken      = "NPM_TOKEN"
	HFToken       = "HUGGINGFACE_TOKEN"
	PrivateKey    = "PRIVATE_KEY"
	JWT           = "JWT"
	BearerToken   = "BEARER_TOKEN"
	DBPassword    = "DB_PASSWORD"
	GenericSecret = "GENERIC_SECRET"
	GolemKey      = "GOLEM_KEY"
	AWSAccessKey  = "AWS_ACCESS_KEY"
)

// Pattern is one credential shape.
type Pattern struct {
	Type string
	Re   *regexp.Regexp
	// Group narrows the match to a capture group: for
	// `postgres://user:hunter2@host` the secret is the password alone. 0 is the
	// whole match.
	Group int
	// Score is the confidence of a match.
	Score float64
	// RejectPlaceholder drops a match that Placeholder says is an example.
	RejectPlaceholder bool
}

var secrets = []Pattern{
	{Type: GitHubToken, Re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})`), Score: 0.95},
	{Type: GitLabToken, Re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`), Score: 0.95},
	{Type: SlackToken, Re: regexp.MustCompile(`\b(?:xox[abprs]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9\-]{10,})`), Score: 0.95},
	{Type: AnthropicKey, Re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`), Score: 0.95},
	// The body disallows "-", which is what keeps this from also claiming
	// sk-ant-* : "ant" is three characters and then a hyphen, so it can never
	// reach the 20-character minimum.
	{Type: OpenAIKey, Re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b`), Score: 0.95},
	{Type: GoogleAPIKey, Re: regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}`), Score: 0.95},
	{Type: StripeKey, Re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`), Score: 0.95},
	{Type: NPMToken, Re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}`), Score: 0.95},
	{Type: HFToken, Re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`), Score: 0.9},
	{Type: PrivateKey, Re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), Score: 1.0},
	{Type: JWT, Re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), Score: 0.9},
	{Type: BearerToken, Re: regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9._~+/\-]{16,}=*)`), Group: 1, Score: 0.85, RejectPlaceholder: true},
	{Type: DBPassword, Re: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:@/\s]+:([^@/\s]+)@`), Group: 1, Score: 0.9, RejectPlaceholder: true},
	// Golem's own workspace key (glk_) and agent secret (gla_), both base64url
	// over 32 random bytes. gac_ is deliberately absent from the alternation:
	// the client id is public, and hiding it would hide WHICH agent principal
	// acted. Excluding gac_ by name rather than by length is what lets the
	// length stay open at {22,}, so a future change to the byte count cannot
	// silently stop matching.
	{Type: GolemKey, Re: regexp.MustCompile(`\b(?:gla|glk)_[A-Za-z0-9_\-]{22,}`), Score: 1.0},
	// No leading \b: "_" is a word character, so a boundary can never sit
	// between GITHUB_ and TOKEN, which would miss every env-var-style name.
	{Type: GenericSecret, Re: regexp.MustCompile(`(?i)(?:api[_\-]?key|secret|token|password|passwd|access[_\-]?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=_.\-]{16,})`), Group: 1, Score: 0.6, RejectPlaceholder: true},
}

// AWS is an AWS access key id. The redaction engine counts it among its
// structured types rather than its secrets, so it is not in Secrets.
var AWS = Pattern{Type: AWSAccessKey, Re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Score: 0.9}

// Secrets is every machine-credential pattern, in the order they are tried.
func Secrets() []Pattern { return append([]Pattern(nil), secrets...) }

// Placeholder reports a documentation value: an example, a template, a run of
// one character. Such a value is not a secret, and treating it as one would
// manufacture "a credential appeared here" out of an example.
func Placeholder(m string) bool {
	if m == "" {
		return true
	}
	l := strings.ToLower(m)
	for _, bad := range []string{"example", "changeme", "your_", "your-", "placeholder", "redacted", "xxxx", "<", "insert_", "dummy", "sample", "test_token", "fake"} {
		if strings.Contains(l, bad) {
			return true
		}
	}
	return strings.Count(l, string(l[0])) == len(l)
}

// Find reports the first credential type that value holds, AWS keys included,
// with placeholders rejected. It returns a type name only: a caller must never
// carry the matched text anywhere.
func Find(value string) (string, bool) {
	for _, p := range append(Secrets(), AWS) {
		for _, loc := range p.Re.FindAllStringSubmatchIndex(value, -1) {
			start, end := loc[0], loc[1]
			if p.Group > 0 {
				if 2*p.Group+1 >= len(loc) || loc[2*p.Group] < 0 {
					continue
				}
				start, end = loc[2*p.Group], loc[2*p.Group+1]
			}
			if p.RejectPlaceholder && Placeholder(value[start:end]) {
				continue
			}
			return p.Type, true
		}
	}
	return "", false
}
