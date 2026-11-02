package agentposture

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// parsePlist decodes a binary (bplist00) or XML property list into the shapes
// encoding/json produces: map[string]any, []any, string, float64 and bool.
// Data and dates come back as their string forms. A managed preferences file
// is written by MDM, not the user, but it is still read defensively: every
// offset and length is bounds-checked, and nesting and object counts are capped.
func parsePlist(b []byte) (any, error) {
	if bytes.HasPrefix(b, []byte("bplist00")) {
		return parseBinaryPlist(b)
	}
	return parseXMLPlist(b)
}

var errPlist = errors.New("malformed plist")

const (
	maxPlistObjects = 1 << 16
	maxPlistDepth   = 32
)

type bplist struct {
	b       []byte
	offsets []uint64
	refSize int
}

func parseBinaryPlist(b []byte) (any, error) {
	if len(b) < 8+32 {
		return nil, errPlist
	}
	t := b[len(b)-32:]
	offSize, refSize := int(t[6]), int(t[7])
	numObjects := binary.BigEndian.Uint64(t[8:16])
	top := binary.BigEndian.Uint64(t[16:24])
	tableAt := binary.BigEndian.Uint64(t[24:32])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObjects == 0 ||
		numObjects > maxPlistObjects || top >= numObjects {
		return nil, errPlist
	}
	end := uint64(len(b) - 32)
	if tableAt >= end || numObjects*uint64(offSize) > end-tableAt {
		return nil, errPlist
	}
	p := &bplist{b: b[:end], refSize: refSize, offsets: make([]uint64, numObjects)}
	for i := range p.offsets {
		at := tableAt + uint64(i*offSize)
		p.offsets[i] = readUintBE(b[at : at+uint64(offSize)])
		if p.offsets[i] < 8 || p.offsets[i] >= tableAt {
			return nil, errPlist
		}
	}
	return p.object(top, 0)
}

func readUintBE(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func (p *bplist) span(off, n uint64) ([]byte, bool) {
	if off > uint64(len(p.b)) || n > uint64(len(p.b))-off {
		return nil, false
	}
	return p.b[off : off+n], true
}

// count reads an object's length: the marker's low nibble, or an int object
// after it when the nibble is 0xF. It returns the length and where the
// object's body starts.
func (p *bplist) count(off uint64, lo byte) (uint64, uint64, bool) {
	if lo != 0x0F {
		return uint64(lo), off + 1, true
	}
	m, ok := p.span(off+1, 1)
	if !ok || m[0]>>4 != 0x1 {
		return 0, 0, false
	}
	size := uint64(1) << (m[0] & 0x0F)
	if size > 8 {
		return 0, 0, false
	}
	v, ok := p.span(off+2, size)
	if !ok {
		return 0, 0, false
	}
	return readUintBE(v), off + 2 + size, true
}

func (p *bplist) refs(at, n uint64) ([]uint64, bool) {
	if n > maxPlistObjects {
		return nil, false
	}
	raw, ok := p.span(at, n*uint64(p.refSize))
	if !ok {
		return nil, false
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = readUintBE(raw[i*p.refSize : (i+1)*p.refSize])
		if out[i] >= uint64(len(p.offsets)) {
			return nil, false
		}
	}
	return out, true
}

func (p *bplist) object(ref uint64, depth int) (any, error) {
	if depth > maxPlistDepth || ref >= uint64(len(p.offsets)) {
		return nil, errPlist
	}
	off := p.offsets[ref]
	m, ok := p.span(off, 1)
	if !ok {
		return nil, errPlist
	}
	hi, lo := m[0]>>4, m[0]&0x0F
	switch hi {
	case 0x0:
		switch lo {
		case 0x8:
			return false, nil
		case 0x9:
			return true, nil
		}
		return nil, nil
	case 0x1:
		size := uint64(1) << lo
		v, ok := p.span(off+1, size)
		if !ok || size > 16 {
			return nil, errPlist
		}
		if size == 16 {
			v = v[8:]
		}
		u := readUintBE(v)
		if size == 8 || size == 16 {
			return float64(int64(u)), nil
		}
		return float64(u), nil
	case 0x2, 0x3:
		size := uint64(1) << lo
		if hi == 0x3 {
			size = 8
		}
		v, ok := p.span(off+1, size)
		if !ok {
			return nil, errPlist
		}
		switch size {
		case 4:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(v))), nil
		case 8:
			return math.Float64frombits(binary.BigEndian.Uint64(v)), nil
		}
		return nil, errPlist
	case 0x4, 0x5, 0x6, 0x7:
		n, at, ok := p.count(off, lo)
		if !ok {
			return nil, errPlist
		}
		if hi == 0x6 {
			raw, ok := p.span(at, n*2)
			if !ok {
				return nil, errPlist
			}
			units := make([]uint16, n)
			for i := range units {
				units[i] = binary.BigEndian.Uint16(raw[i*2:])
			}
			return string(utf16.Decode(units)), nil
		}
		raw, ok := p.span(at, n)
		if !ok {
			return nil, errPlist
		}
		return string(raw), nil
	case 0x8:
		v, ok := p.span(off+1, uint64(lo)+1)
		if !ok {
			return nil, errPlist
		}
		return float64(readUintBE(v)), nil
	case 0xA, 0xC:
		n, at, ok := p.count(off, lo)
		if !ok {
			return nil, errPlist
		}
		refs, ok := p.refs(at, n)
		if !ok {
			return nil, errPlist
		}
		out := make([]any, 0, len(refs))
		for _, r := range refs {
			v, err := p.object(r, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 0xD:
		n, at, ok := p.count(off, lo)
		if !ok {
			return nil, errPlist
		}
		refs, ok := p.refs(at, 2*n)
		if !ok {
			return nil, errPlist
		}
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := p.object(refs[i], depth+1)
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, errPlist
			}
			v, err := p.object(refs[n+i], depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		return out, nil
	}
	return nil, errPlist
}

func parseXMLPlist(b []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, errPlist
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return xmlPlistValue(dec, se, 0)
		}
	}
}

func xmlPlistValue(dec *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, errPlist
	}
	switch se.Name.Local {
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, errPlist
		}
		return se.Name.Local == "true", nil
	case "string", "data", "date", "key":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return nil, errPlist
		}
		return s, nil
	case "integer", "real":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return nil, errPlist
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, errPlist
		}
		return f, nil
	case "array":
		out := []any{}
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlPlistValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			case xml.EndElement:
				return out, nil
			}
		}
	case "dict":
		out := map[string]any{}
		key := ""
		haveKey := false
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlPlistValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				if t.Name.Local == "key" {
					key, haveKey = v.(string), true
					continue
				}
				if !haveKey {
					return nil, errPlist
				}
				out[key], haveKey = v, false
			case xml.EndElement:
				return out, nil
			}
		}
	}
	return nil, errPlist
}
