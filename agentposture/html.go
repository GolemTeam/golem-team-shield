package agentposture

import (
	"fmt"
	"html/template"
	"io"
	"time"
)

// HTMLMeta is what the HTML report says about its own making. It never
// carries the host or user name: the page is made to be handed on.
type HTMLMeta struct {
	Version string
	GOOS    string
	When    time.Time
}

type htmlFinding struct {
	Item
	Where string
}

type htmlArea struct {
	AreaScore
	Summary  string
	Findings []htmlFinding
	Notes    []htmlFinding
}

type htmlProtection struct{ Client, Line string }

type htmlPage struct {
	Meta        HTMLMeta
	Report      Report
	Repo        string
	Areas       []htmlArea
	Protections []htmlProtection
	Dangerous   int
	Suspicious  int
	NotRead     string
}

// WriteHTML writes a scan as one self-contained page: inline styles, no
// script, nothing fetched, so it opens the same from an email or a ticket.
func WriteHTML(w io.Writer, res Result, meta HTMLMeta) error {
	rep := Score(res)
	page := htmlPage{Meta: meta, Report: rep, Repo: res.Repo, NotRead: NotRead}
	byArea := map[string]*htmlArea{}
	for _, a := range rep.Areas {
		if a.Area == AreaProtections {
			continue
		}
		page.Areas = append(page.Areas, htmlArea{AreaScore: a, Summary: areaSummary(a)})
	}
	for i := range page.Areas {
		byArea[page.Areas[i].Area] = &page.Areas[i]
	}
	var protections []Item
	for _, it := range res.Items {
		area := it.Area
		if area == "" {
			area = areaOf(it.Check)
		}
		if area == AreaProtections {
			protections = append(protections, it)
			continue
		}
		where := it.Location
		if where == "" {
			where = it.Scope
		} else if it.Line > 0 {
			where = fmt.Sprintf("%s:%d", where, it.Line)
		}
		f := htmlFinding{Item: it, Where: where}
		f.Detail = summary(it)
		a := byArea[area]
		if a == nil {
			continue
		}
		switch it.Severity {
		case Dangerous:
			page.Dangerous++
			a.Findings = append(a.Findings, f)
		case Suspicious:
			page.Suspicious++
			a.Findings = append(a.Findings, f)
		default:
			a.Notes = append(a.Notes, f)
		}
	}
	if res.Repo == "" {
		for _, c := range res.Agents {
			page.Protections = append(page.Protections, htmlProtection{c, protectionLine(c, protections)})
		}
	}
	return htmlTemplate.Execute(w, page)
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"date": func(t time.Time) string { return t.UTC().Format("2 January 2006, 15:04 UTC") },
	"gradeClass": func(g string) string {
		switch g {
		case "A", "B":
			return "good"
		case "C":
			return "fair"
		case "":
			return "none"
		}
		return "poor"
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI agent security report</title>
<style>
:root{--bg:#fbfbfa;--panel:#ffffff;--text:#1d1d1b;--muted:#6b6b66;--line:#e6e5e0;--good:#2f7d4f;--fair:#a86a00;--poor:#b3261e;--danger:#b3261e;--warn:#a86a00;--note:#5f6b7a;--bar:#e9e8e3}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--text:#ecebe6;--muted:#a3a29b;--line:#2f2f2c;--good:#6cc58f;--fair:#e5a93b;--poor:#f08a80;--danger:#f08a80;--warn:#e5a93b;--note:#9aa7b6;--bar:#2f2f2c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}h3{font-size:15px;margin:0}
.meta{color:var(--muted);font-size:13px}
.summary{display:flex;gap:20px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:20px}
.grade{flex:none;width:84px;height:84px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:44px;font-weight:700;color:#fff}
.grade.good{background:var(--good)}.grade.fair{background:var(--fair)}.grade.poor{background:var(--poor)}.grade.none{background:var(--note);font-size:20px}
.score{font-size:20px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
td{padding:10px 14px;border-top:1px solid var(--line);vertical-align:middle}tr:first-child td{border-top:0}
td.n{width:48px;text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.bar{height:8px;background:var(--bar);border-radius:4px;min-width:80px}.bar span{display:block;height:8px;border-radius:4px;background:var(--good)}
.bar span.fair{background:var(--fair)}.bar span.poor{background:var(--poor)}
.muted{color:var(--muted)}
.area{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.finding{display:grid;grid-template-columns:96px 1fr;gap:4px 12px;padding:10px 0;border-top:1px solid var(--line)}
.finding:first-of-type{border-top:0}
.pill{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.03em}
.pill.dangerous{color:var(--danger)}.pill.suspicious{color:var(--warn)}.pill.info{color:var(--note)}
.where{grid-column:2;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);word-break:break-all}
.client{color:var(--muted);font-size:13px}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:13px}
ul.prot{list-style:none;margin:0;padding:0;background:var(--panel);border:1px solid var(--line);border-radius:12px}
ul.prot li{padding:10px 14px;border-top:1px solid var(--line)}ul.prot li:first-child{border-top:0}
.note{background:var(--panel);border:1px dashed var(--line);border-radius:12px;padding:14px 16px;color:var(--muted);font-size:14px;white-space:pre-line}
footer{margin-top:32px;color:var(--muted);font-size:13px}
@media (max-width:560px){.summary{flex-direction:column;align-items:flex-start}.finding{grid-template-columns:1fr}.where{grid-column:1}}
@media print{body{background:#fff}.area,.summary,table,ul.prot{break-inside:avoid}details{display:block}}
</style>
</head>
<body><main>
<h1>{{if .Repo}}Agent files in {{.Repo}}{{else}}AI coding agents on this machine{{end}}</h1>
<div class="meta">{{date .Meta.When}} · {{.Meta.GOOS}} · golem-check {{.Meta.Version}} · scoring {{.Report.Version}}</div>

<section class="summary">
<div class="grade {{gradeClass .Report.Grade}}">{{if .Report.Grade}}{{.Report.Grade}}{{else}}n/a{{end}}</div>
<div>
{{if .Report.Grade}}<div class="score">{{.Report.Score}} of 100</div>{{else}}<div class="score">{{if .Repo}}No agent files found{{else}}No AI coding agents found{{end}}</div>{{end}}
<div>{{.Dangerous}} dangerous, {{.Suspicious}} suspicious.</div>
<div class="muted">Read from the agents' own files on this machine. Nothing was sent anywhere.</div>
</div>
</section>

<h2>Areas</h2>
<table>
{{range .Areas}}{{if .Applies}}<tr><td>{{.Title}}</td><td class="n">{{.Score}}</td><td style="width:40%"><div class="bar"><span class="{{if lt .Score 60}}poor{{else if lt .Score 85}}fair{{end}}" style="width:{{.Score}}%"></span></div></td><td class="muted">{{.Summary}}</td></tr>
{{else}}<tr><td>{{.Title}}</td><td class="n muted">–</td><td colspan="2" class="muted">nothing to check</td></tr>
{{end}}{{end}}</table>
{{if .Protections}}
<h2>Protections</h2>
<p class="muted">{{range .Report.Areas}}{{if eq .Area "protections"}}{{.Score}} of 100: the share of agents whose shell commands run in a jail or a sandbox.{{end}}{{end}}</p>
<ul class="prot">{{range .Protections}}<li><strong>{{.Client}}</strong> <span class="muted">{{.Line}}</span></li>{{end}}</ul>
{{end}}
<h2>Findings</h2>
{{range .Areas}}{{if or .Findings .Notes}}<div class="area">
<h3>{{.Title}}</h3>
{{range .Findings}}<div class="finding"><div class="pill {{.Severity}}">{{.Severity}}</div><div>{{.Detail}} <span class="client">· {{.Client}}</span></div>{{if .Where}}<div class="where">{{.Where}}</div>{{end}}</div>
{{end}}{{if .Notes}}<details><summary>{{len .Notes}} more for information</summary>
{{range .Notes}}<div class="finding"><div class="pill info">note</div><div>{{.Detail}} <span class="client">· {{.Client}}</span></div>{{if .Where}}<div class="where">{{.Where}}</div>{{end}}</div>
{{end}}</details>{{end}}
</div>
{{end}}{{end}}
{{if not .Repo}}<h2>Not checked</h2>
<div class="note">{{.NotRead}}</div>{{end}}
<footer>Made by golem-check, open source at github.com/GolemTeam/golem-team-shield. Paths under the home directory are shown as ~; the host and user names are not in this report, and neither is any file's text.</footer>
</main></body>
</html>
`))
