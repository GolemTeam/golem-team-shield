package shield

import (
	"regexp"
	"strconv"
	"strings"
)

// Denial is one operation the kernel refused a jailed process, as Seatbelt
// logs it: "Sandbox: cat(97170) deny(1) file-read-data /Users/x/.ssh/config"
// followed by the run's tag line.
type Denial struct {
	Process   string
	PID       int
	Operation string
	Target    string
	RunTag    string
}

var denialRE = regexp.MustCompile(`^Sandbox: (.{1,256})\((\d{1,10})\) deny\(\d+\) (\S{1,64})(?: (.*))?$`)

// ParseDenial reads one Seatbelt log message. It accepts only messages that
// carry a run tag, so denials of processes the shield didn't start (every app
// sandbox on the machine logs the same way) are ignored. The caller must take
// messages only from the kernel's Sandbox sender: a process can log text of
// its own that looks like this.
func ParseDenial(message string) (Denial, bool) {
	head, tag, ok := strings.Cut(message, "\n")
	if !ok {
		return Denial{}, false
	}
	tag = strings.TrimSpace(tag)
	if !strings.HasPrefix(tag, DenialTag) {
		return Denial{}, false
	}
	tag = strings.TrimPrefix(tag, DenialTag)
	if !runTagRE.MatchString(tag) {
		return Denial{}, false
	}
	m := denialRE.FindStringSubmatch(strings.TrimSpace(head))
	if m == nil {
		return Denial{}, false
	}
	pid, err := strconv.Atoi(m[2])
	if err != nil {
		return Denial{}, false
	}
	return Denial{Process: m[1], PID: pid, Operation: m[3], Target: m[4], RunTag: tag}, true
}
