package agentposture

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// readItemTable returns the values of the wanted keys in a VS Code-style
// state.vscdb (SQLite, `ItemTable(key TEXT, value BLOB)`), which is where Cursor
// and Antigravity keep the run modes they show in their own settings screens.
// It is a read-only walk of one table's B-tree, page by page with ReadAt, so a
// Cursor database of several hundred megabytes is not read whole, and it runs
// nothing. Pages visited, payload sizes and overflow chains are capped. A
// database in WAL mode may be read as of its last checkpoint.
func readItemTable(path string, wanted map[string]bool) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db, err := openSQLite(f)
	if err != nil {
		return nil, err
	}
	root, err := db.tableRoot("ItemTable")
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	err = db.walk(root, func(rec []sqlValue) bool {
		if len(rec) < 2 {
			return true
		}
		if key := string(rec[0].b); wanted[key] {
			out[key] = rec[1].b
		}
		return len(out) < len(wanted)
	})
	return out, err
}

var errSQLite = errors.New("malformed sqlite database")

const (
	maxSQLitePages   = 1 << 18
	maxSQLitePayload = 4 << 20
)

type sqliteDB struct {
	r        io.ReaderAt
	pageSize int
	usable   int
	visited  int
}

type sqlValue struct {
	b    []byte
	i    int64
	null bool
}

func openSQLite(r io.ReaderAt) (*sqliteDB, error) {
	h := make([]byte, 100)
	if _, err := r.ReadAt(h, 0); err != nil {
		return nil, errSQLite
	}
	if string(h[:16]) != "SQLite format 3\x00" {
		return nil, errSQLite
	}
	ps := int(binary.BigEndian.Uint16(h[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, errSQLite
	}
	usable := ps - int(h[20])
	if usable < 480 || binary.BigEndian.Uint32(h[56:60]) > 1 {
		return nil, errSQLite
	}
	return &sqliteDB{r: r, pageSize: ps, usable: usable}, nil
}

func (db *sqliteDB) page(n uint32) ([]byte, error) {
	if n == 0 {
		return nil, errSQLite
	}
	db.visited++
	if db.visited > maxSQLitePages {
		return nil, errSQLite
	}
	b := make([]byte, db.pageSize)
	if _, err := db.r.ReadAt(b, int64(n-1)*int64(db.pageSize)); err != nil {
		return nil, errSQLite
	}
	return b, nil
}

func (db *sqliteDB) tableRoot(name string) (uint32, error) {
	var root uint32
	err := db.walk(1, func(rec []sqlValue) bool {
		if len(rec) >= 4 && string(rec[0].b) == "table" && string(rec[1].b) == name {
			root = uint32(rec[3].i)
			return false
		}
		return true
	})
	if err == nil && root == 0 {
		err = errSQLite
	}
	return root, err
}

func (db *sqliteDB) walk(n uint32, visit func([]sqlValue) bool) error {
	_, err := db.walkPage(n, visit, 0)
	return err
}

func (db *sqliteDB) walkPage(n uint32, visit func([]sqlValue) bool, depth int) (bool, error) {
	if depth > 32 {
		return false, errSQLite
	}
	p, err := db.page(n)
	if err != nil {
		return false, err
	}
	hdr := 0
	if n == 1 {
		hdr = 100
	}
	if hdr+8 > len(p) {
		return false, errSQLite
	}
	kind := p[hdr]
	cells := int(binary.BigEndian.Uint16(p[hdr+3:]))
	ptrs := hdr + 8
	if kind == 0x05 {
		ptrs = hdr + 12
	} else if kind != 0x0D {
		return false, errSQLite
	}
	if ptrs+2*cells > len(p) {
		return false, errSQLite
	}
	for i := 0; i < cells; i++ {
		off := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
		if off < ptrs || off >= len(p) {
			return false, errSQLite
		}
		if kind == 0x05 {
			if off+4 > len(p) {
				return false, errSQLite
			}
			more, err := db.walkPage(binary.BigEndian.Uint32(p[off:]), visit, depth+1)
			if err != nil || !more {
				return more, err
			}
			continue
		}
		payload, err := db.cellPayload(p, off)
		if err != nil {
			return false, err
		}
		rec, err := parseRecord(payload)
		if err != nil {
			return false, err
		}
		if !visit(rec) {
			return false, nil
		}
	}
	if kind == 0x05 {
		return db.walkPage(binary.BigEndian.Uint32(p[hdr+8:]), visit, depth+1)
	}
	return true, nil
}

// cellPayload reads a table leaf cell's record, following its overflow chain
// with the local-size rule of the SQLite file format.
func (db *sqliteDB) cellPayload(p []byte, off int) ([]byte, error) {
	size, n := sqliteVarint(p[off:])
	if n == 0 {
		return nil, errSQLite
	}
	off += n
	if _, n = sqliteVarint(p[off:]); n == 0 {
		return nil, errSQLite
	}
	off += n
	if size > maxSQLitePayload {
		return nil, errSQLite
	}
	u := uint64(db.usable)
	x := u - 35
	local := size
	if size > x {
		m := (u-12)*32/255 - 23
		k := m + (size-m)%(u-4)
		local = m
		if k <= x {
			local = k
		}
	}
	if uint64(off)+local > uint64(len(p)) {
		return nil, errSQLite
	}
	out := append(make([]byte, 0, size), p[off:off+int(local)]...)
	if local == size {
		return out, nil
	}
	if uint64(off)+local+4 > uint64(len(p)) {
		return nil, errSQLite
	}
	next := binary.BigEndian.Uint32(p[off+int(local):])
	for uint64(len(out)) < size {
		op, err := db.page(next)
		if err != nil {
			return nil, err
		}
		next = binary.BigEndian.Uint32(op)
		chunk := op[4:db.usable]
		if rest := size - uint64(len(out)); uint64(len(chunk)) > rest {
			chunk = chunk[:rest]
		}
		out = append(out, chunk...)
		if next == 0 && uint64(len(out)) < size {
			return nil, errSQLite
		}
	}
	return out, nil
}

func parseRecord(b []byte) ([]sqlValue, error) {
	hlen, n := sqliteVarint(b)
	if n == 0 || hlen > uint64(len(b)) || hlen < uint64(n) {
		return nil, errSQLite
	}
	types := b[n:hlen]
	body := b[hlen:]
	var out []sqlValue
	for len(types) > 0 {
		t, k := sqliteVarint(types)
		if k == 0 {
			return nil, errSQLite
		}
		types = types[k:]
		var v sqlValue
		var size uint64
		switch {
		case t == 0:
			v.null = true
		case t >= 1 && t <= 6:
			size = [...]uint64{0, 1, 2, 3, 4, 6, 8}[t]
		case t == 7:
			size = 8
		case t == 8 || t == 9:
			v.i = int64(t - 8)
		case t >= 12:
			size = (t - 12) / 2
		default:
			return nil, errSQLite
		}
		if size > uint64(len(body)) {
			return nil, errSQLite
		}
		raw := body[:size]
		body = body[size:]
		if t >= 1 && t <= 6 {
			u := uint64(0)
			for _, c := range raw {
				u = u<<8 | uint64(c)
			}
			shift := 64 - 8*size
			v.i = int64(u<<shift) >> shift
		} else if t >= 12 {
			v.b = raw
		}
		out = append(out, v)
	}
	return out, nil
}

// sqliteVarint decodes SQLite's big-endian varint: 7 bits a byte, the ninth
// byte all 8. It returns 0 bytes read when the input runs out.
func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0
		}
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, 9
}
