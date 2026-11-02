// Package jsonobject edits JSON config files that belong to other programs:
// it keeps their key order and every value it was not asked to change.
package jsonobject

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Object is a JSON object that remembers its key order and keeps every value
// it was not asked to change as the original bytes.
//
// Both properties are load-bearing, because the files it edits belong to other
// programs. Decoding ~/.claude.json into a map[string]any and re-marshalling it
// would reshuffle every key on each write and round-trip numbers through
// float64 — which turns a millisecond timestamp like 1786000000000 into
// 1.786e+12. Correct JSON, gratuitously rewritten state, in a file Claude Code
// is also writing.
type Object struct {
	keys []string
	vals map[string]json.RawMessage
}

// New is an empty object.
func New() *Object {
	return &Object{vals: map[string]json.RawMessage{}}
}

// Parse decodes a JSON object, preserving key order. A duplicate key
// keeps its first position and takes the last value, matching what encoding/json
// does when unmarshalling.
func Parse(data []byte) (*Object, error) {
	o := New()
	if len(bytes.TrimSpace(data)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("expected a string key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		o.Set(key, raw)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return o, nil
}

// Get is the value at key, as the bytes it was read or set as.
func (o *Object) Get(key string) (json.RawMessage, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// Set puts val at key, keeping the key's position if it was already there.
func (o *Object) Set(key string, val json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = val
}

// Remove drops key.
func (o *Object) Remove(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Empty reports whether the object has no keys.
func (o *Object) Empty() bool { return len(o.keys) == 0 }

// MarshalJSON writes the keys in order, each value compacted.
func (o *Object) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		// Compact so the final json.Indent produces one consistent shape rather
		// than re-indenting around whatever whitespace the original carried.
		if err := json.Compact(&buf, o.vals[k]); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// ReadFile loads a JSON object from disk. A missing file yields an
// empty object and existed=false; a present-but-empty file is treated the same,
// since a zero-byte config is not something to refuse to repair.
func ReadFile(path string) (*Object, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), false, nil
		}
		return nil, false, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return New(), false, nil
	}
	o, err := Parse(b)
	if err != nil {
		return nil, true, err
	}
	return o, true, nil
}

// WriteFile writes the document atomically — temp file in the same
// directory, then rename — so a client reading the config concurrently sees
// either the old file or the new one, never a half-written one.
func WriteFile(path string, doc *Object) error {
	compact, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		return err
	}
	pretty.WriteByte('\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".golem-setup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(pretty.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
