// Package definition is what the agent is told about an asset: an MCP
// server's instructions, tools, prompts and resources, a skill's SKILL.md and
// the files it bundles, a plugin's manifest and hooks
// (docs/design-inventory-definitions-and-scanners.md).
//
// The witness writes a Snapshot as an asset_definition ledger entry: the
// snapshot is the entry's payload, so its text goes to BYOB, and Stamp puts
// the hashes in the entry's metadata, which is all conversation-worker and
// core-api ever see. Only the witness computes a hash, so this package is the
// whole meaning of "the same definition".
package definition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

const EventType = "asset_definition"

// A definition is per source: each sees a different part of the asset, so two
// sources disagreeing is not drift.
const (
	SourceGateway      = "gateway"
	SourceModelRequest = "model_request"
	SourceConfigScan   = "config_scan"
	// SourceLaunch is how an MCP server is started, as the agent's config says:
	// a projection that keeps the runner, the package or image and the URL's
	// host, and drops every other argument and the environment.
	SourceLaunch = "launch"
)

const (
	KindInstructions     = "instructions"
	KindServerInfo       = "server_info"
	KindTool             = "tool"
	KindToolMeta         = "tool_meta"
	KindPrompt           = "prompt"
	KindResource         = "resource"
	KindResourceTemplate = "resource_template"
	KindFile             = "file"
	// KindSkill is a plugin's bundled skill, by its own definition hash: the
	// plugin changes when the skill does, without holding its text twice.
	KindSkill = "skill"
	// KindLaunch is a launch definition's one part.
	KindLaunch = "launch"
	// KindModel is a model's details: format, family, size and quantization.
	KindModel = "model"
)

// Ledger metadata is a flat map, so the per-tool hashes are one JSON-encoded
// object.
const (
	MetaAssetType  = "definition_asset_type"
	MetaAssetKey   = "definition_asset_key"
	MetaHash       = "definition_hash"
	MetaSource     = "definition_source"
	MetaParts      = "definition_parts"
	MetaSize       = "definition_size"
	MetaTruncated  = "definition_truncated"
	MetaToolHashes = "definition_tool_hashes"
)

// A model's definition is what its Modelfile puts in front of the model on
// every call (KindInstructions parts named SYSTEM, TEMPLATE and MESSAGES).
// What it is called and where it came from ride the entry's metadata instead:
// a digest copied to a second name is the same model with the same text.
const (
	MetaModelRuntime       = "model_runtime"
	MetaModelName          = "model_name"
	MetaModelRegistry      = "model_registry"
	MetaModelNamespace     = "model_namespace"
	MetaModelSize          = "model_size"
	MetaModelFormat        = "model_format"
	MetaModelFamily        = "model_family"
	MetaModelParameterSize = "model_parameter_size"
	MetaModelQuantization  = "model_quantization"
)

// The limits cut what a snapshot keeps, never what it hashes: a definition
// that grew past them still changes its hash when it changes.
const (
	MaxPartBytes     = 256 << 10
	MaxSnapshotBytes = 2 << 20
	MaxParts         = 1000
	MaxNameBytes     = 512
	maxToolHashes    = 500
)

type Part struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Hash is over the full content: the canonical JSON for a JSON part, the
	// bytes for a text part.
	Hash      string          `json:"hash"`
	Size      int             `json:"size"`
	Text      string          `json:"text,omitempty"`
	JSON      json.RawMessage `json:"json,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Binary    bool            `json:"binary,omitempty"`
}

type Snapshot struct {
	Version   int    `json:"version"`
	AssetType string `json:"asset_type"`
	AssetKey  string `json:"asset_key"`
	Source    string `json:"source"`
	Hash      string `json:"hash"`
	Size      int    `json:"size"`
	Truncated bool   `json:"truncated,omitempty"`
	// Omitted parts are past MaxParts: in Hash, not in Parts.
	Omitted int    `json:"omitted,omitempty"`
	Parts   []Part `json:"parts"`
}

// Text keeps content only when it is UTF-8 with no NUL; anything else is
// hashed and sized as binary, so a bundled executable never lands in BYOB.
func Text(kind, name string, content []byte) Part {
	p := Part{Kind: kind, Name: fitName(name), Hash: sum(content), Size: len(content)}
	switch {
	case !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0:
		p.Binary = true
	case len(content) > MaxPartBytes:
		p.Text, p.Truncated = cutText(string(content), MaxPartBytes), true
	default:
		p.Text = string(content)
	}
	return p
}

// File hashes the whole of r but holds only what Text would keep, so a large
// bundled file costs its read and never its size in memory.
func File(name string, r io.Reader) (Part, error) {
	h := sha256.New()
	head := make([]byte, 0, 4096)
	buf := make([]byte, 32<<10)
	size := 0
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			size += n
			if keep := MaxPartBytes + utf8.UTFMax - len(head); keep > 0 {
				head = append(head, buf[:min(n, keep)]...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Part{}, err
		}
	}
	p := Part{Kind: KindFile, Name: fitName(name), Hash: hex.EncodeToString(h.Sum(nil)), Size: size}
	text := head
	if size > MaxPartBytes {
		text = []byte(cutText(string(head), MaxPartBytes))
		p.Truncated = true
	}
	if !utf8.Valid(text) || bytes.IndexByte(text, 0) >= 0 {
		p.Binary, p.Truncated = true, false
		return p, nil
	}
	p.Text = string(text)
	return p, nil
}

func JSON(kind, name string, raw []byte) (Part, error) {
	canon, err := Canonical(raw)
	if err != nil {
		return Part{}, err
	}
	p := Part{Kind: kind, Name: fitName(name), Hash: sum(canon), Size: len(canon)}
	if len(canon) > MaxPartBytes {
		p.Truncated = true
	} else {
		p.JSON = canon
	}
	return p, nil
}

// toolVisible are the fields of an MCP tool the model reads. They are the
// tool's own part so a tool hashes the same whichever source saw it: a model
// request carries only these, the gateway carries them with the rest.
var toolVisible = []string{"name", "description", "inputSchema"}

var ErrNoName = errors.New("definition: entry has no name")

func Tool(raw []byte) (Part, *Part, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Part{}, nil, err
	}
	var name string
	if err := json.Unmarshal(obj["name"], &name); err != nil || strings.TrimSpace(name) == "" {
		return Part{}, nil, ErrNoName
	}
	visible, rest := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	for k, v := range obj {
		if slices.Contains(toolVisible, k) {
			visible[k] = v
		} else {
			rest[k] = v
		}
	}
	tool, err := jsonOf(KindTool, name, visible)
	if err != nil {
		return Part{}, nil, err
	}
	if len(rest) == 0 {
		return tool, nil, nil
	}
	meta, err := jsonOf(KindToolMeta, name, rest)
	if err != nil {
		return Part{}, nil, err
	}
	return tool, &meta, nil
}

func Entry(kind string, raw []byte) (Part, error) {
	field := "name"
	switch kind {
	case KindResource:
		field = "uri"
	case KindResourceTemplate:
		field = "uriTemplate"
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Part{}, err
	}
	var name string
	if err := json.Unmarshal(obj[field], &name); err != nil || strings.TrimSpace(name) == "" {
		return Part{}, ErrNoName
	}
	return JSON(kind, name, raw)
}

func jsonOf(kind, name string, obj map[string]json.RawMessage) (Part, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return Part{}, err
	}
	return JSON(kind, name, raw)
}

// Build hashes one line per part, "kind \x1f name \x1f hash \n", ordered by
// kind and name, before any limit applies. Of two parts sharing kind and name
// the first is kept.
func Build(assetType, assetKey, source string, parts []Part) Snapshot {
	parts = slices.Clone(parts)
	slices.SortStableFunc(parts, func(a, b Part) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	parts = slices.CompactFunc(parts, func(a, b Part) bool { return a.Kind == b.Kind && a.Name == b.Name })

	s := Snapshot{Version: 1, AssetType: assetType, AssetKey: assetKey, Source: source}
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p.Kind + "\x1f" + p.Name + "\x1f" + p.Hash + "\n"))
		s.Size += p.Size
	}
	s.Hash = hex.EncodeToString(h.Sum(nil))

	if len(parts) > MaxParts {
		s.Omitted, parts = len(parts)-MaxParts, parts[:MaxParts]
	}
	kept := 0
	for i := range parts {
		p := &parts[i]
		n := len(p.Text) + len(p.JSON)
		if kept+n > MaxSnapshotBytes {
			p.Text, p.JSON = "", nil
			if !p.Binary {
				p.Truncated = true
			}
			n = 0
		}
		kept += n
		s.Truncated = s.Truncated || p.Truncated
	}
	s.Truncated = s.Truncated || s.Omitted > 0
	s.Parts = parts
	return s
}

func (s Snapshot) IsZero() bool { return len(s.Parts) == 0 && s.Omitted == 0 }

func (s Snapshot) Payload() ([]byte, error) { return json.Marshal(s) }

func (s Snapshot) Stamp(metadata map[string]any) {
	metadata[MetaAssetType] = s.AssetType
	metadata[MetaAssetKey] = s.AssetKey
	metadata[MetaHash] = s.Hash
	metadata[MetaSource] = s.Source
	metadata[MetaParts] = len(s.Parts) + s.Omitted
	metadata[MetaSize] = s.Size
	metadata[MetaTruncated] = s.Truncated
	delete(metadata, MetaToolHashes)
	tools := map[string]string{}
	for _, p := range s.Parts {
		if p.Kind == KindTool && len(tools) < maxToolHashes {
			tools[p.Name] = p.Hash
		}
	}
	if len(tools) > 0 {
		if b, err := json.Marshal(tools); err == nil {
			metadata[MetaToolHashes] = string(b)
		}
	}
}

// Canonical keeps numbers exactly as written (UseNumber) and sorts object
// keys, which encoding/json does for maps.
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("definition: trailing data after JSON value")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fitName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) <= MaxNameBytes {
		return name
	}
	return cutText(name, MaxNameBytes)
}

func cutText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
