package gosafe5

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
)

// HashLength is the number of bytes in each list entry.
type HashLength uint8

const (
	HashLength4  HashLength = 4
	HashLength8  HashLength = 8
	HashLength16 HashLength = 16
	HashLength32 HashLength = 32
)

func (n HashLength) valid() bool { return n == 4 || n == 8 || n == 16 || n == 32 }

var (
	ErrInvalidList      = errors.New("gosafe5: invalid hash list")
	ErrInvalidUpdate    = errors.New("gosafe5: invalid list update")
	ErrChecksumMismatch = errors.New("gosafe5: list checksum mismatch")
)

// HashList is an immutable sorted set of fixed-width hashes or prefixes.
// Copies share immutable storage and are safe for concurrent reads.
// The zero value is invalid; use NewHashList(width, nil) for an empty list.
type HashList struct {
	width HashLength
	data  []byte
}

// NewHashList copies and validates packed entries. It rejects unsorted or
// duplicate entries rather than reordering them: update indices depend on order.
func NewHashList(width HashLength, sortedEntries []byte) (HashList, error) {
	if !width.valid() || len(sortedEntries)%int(width) != 0 {
		return HashList{}, fmt.Errorf("%w: width or alignment", ErrInvalidList)
	}
	w := int(width)
	for i := w; i < len(sortedEntries); i += w {
		if bytes.Compare(sortedEntries[i-w:i], sortedEntries[i:i+w]) >= 0 {
			return HashList{}, fmt.Errorf("%w: entries must be strictly increasing", ErrInvalidList)
		}
	}
	return HashList{width: width, data: bytes.Clone(sortedEntries)}, nil
}

// Valid reports whether the list was constructed with a supported width.
func (l HashList) Valid() bool { return l.width.valid() }

// Len returns the entry count, or zero for an invalid list.
func (l HashList) Len() int {
	if !l.Valid() {
		return 0
	}
	return len(l.data) / int(l.width)
}

// HashLength returns the entry width, or zero for an invalid list.
func (l HashList) HashLength() HashLength { return l.width }

// Bytes returns an independent copy of the packed entries.
func (l HashList) Bytes() []byte { return bytes.Clone(l.data) }

// Matches tests membership of h's leading HashLength bytes. An invalid list
// returns false. Membership alone is not a threat verdict.
func (l HashList) Matches(h Hash) bool {
	if !l.Valid() {
		return false
	}
	w := int(l.width)
	i := sort.Search(l.Len(), func(i int) bool {
		return bytes.Compare(l.data[i*w:(i+1)*w], h[:w]) >= 0
	})
	return i < l.Len() && bytes.Equal(l.data[i*w:(i+1)*w], h[:w])
}

// Checksum hashes the packed entries. Invalid zero-value lists return an error;
// a valid empty list has the SHA-256 checksum of the empty byte string.
func (l HashList) Checksum() (ListChecksum, error) {
	if !l.Valid() {
		return ListChecksum{}, ErrInvalidList
	}
	return ListChecksum(sha256.Sum256(l.data)), nil
}

// ListUpdate is a decoded update. Additions must be valid even when empty.
// Removals are strictly increasing indices into the original base list.
// Callers must not mutate Removals or ExpectedChecksum during application.
type ListUpdate struct {
	Partial          bool
	Removals         []uint32
	Additions        HashList
	ExpectedChecksum *ListChecksum
}

// ApplyUpdate creates a verified list without modifying base. Full replacements
// ignore base and reject removals. Partial updates require the exact base used
// to request the update; association with server versions is the caller's job.
// A checksum may be omitted only for a no-change partial update.
func ApplyUpdate(base *HashList, u ListUpdate) (HashList, error) {
	bad := func(reason string) (HashList, error) {
		return HashList{}, fmt.Errorf("%w: %s", ErrInvalidUpdate, reason)
	}
	if !u.Additions.Valid() {
		return bad("invalid additions")
	}
	if !u.Partial {
		if len(u.Removals) != 0 {
			return bad("removals in full replacement")
		}
		if u.ExpectedChecksum == nil {
			return bad("missing checksum")
		}
		sum, _ := u.Additions.Checksum()
		if sum != *u.ExpectedChecksum {
			return HashList{}, ErrChecksumMismatch
		}
		return u.Additions, nil
	}
	if base == nil || !base.Valid() || base.width != u.Additions.width {
		return bad("missing base or mismatched width")
	}
	for i, idx := range u.Removals {
		if uint64(idx) >= uint64(base.Len()) || (i > 0 && idx <= u.Removals[i-1]) {
			return bad("removal indices must be in range and strictly increasing")
		}
	}
	if u.ExpectedChecksum == nil {
		if len(u.Removals) != 0 || u.Additions.Len() != 0 {
			return bad("missing checksum")
		}
		return *base, nil
	}
	w := int(base.width)
	remaining := len(base.data) - len(u.Removals)*w
	if remaining > int(^uint(0)>>1)-len(u.Additions.data) {
		return bad("result too large")
	}
	out := make([]byte, 0, remaining+len(u.Additions.data))
	// Merge survivors and additions in one pass, interpreting every removal
	// against the original base rather than a progressively shortened slice.
	i, j, r := 0, 0, 0
	for i < base.Len() || j < u.Additions.Len() {
		if i < base.Len() && r < len(u.Removals) && uint64(i) == uint64(u.Removals[r]) {
			i++
			r++
			continue
		}
		if i == base.Len() {
			out = append(out, u.Additions.data[j*w:]...)
			break
		}
		if j == u.Additions.Len() {
			out = append(out, base.data[i*w:(i+1)*w]...)
			i++
			continue
		}
		a, b := base.data[i*w:(i+1)*w], u.Additions.data[j*w:(j+1)*w]
		switch bytes.Compare(a, b) {
		case -1:
			out = append(out, a...)
			i++
		case 1:
			out = append(out, b...)
			j++
		default:
			return bad("addition duplicates surviving entry")
		}
	}
	result := HashList{width: base.width, data: out}
	sum, _ := result.Checksum()
	if sum != *u.ExpectedChecksum {
		return HashList{}, ErrChecksumMismatch
	}
	return result, nil
}
