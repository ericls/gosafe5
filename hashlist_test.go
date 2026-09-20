package gosafe5

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"slices"
	"testing"
)

func packed32(values ...uint32) []byte {
	b := make([]byte, 4*len(values))
	for i, v := range values {
		binary.BigEndian.PutUint32(b[i*4:], v)
	}
	return b
}

func list32(t testing.TB, values ...uint32) HashList {
	t.Helper()
	l, err := NewHashList(HashLength4, packed32(values...))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func checksum(t testing.TB, l HashList) *ListChecksum {
	t.Helper()
	sum, err := l.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	return &sum
}

func TestHashList(t *testing.T) {
	for _, width := range []HashLength{4, 8, 16, 32} {
		data := make([]byte, int(width)*2)
		data[int(width)-1], data[len(data)-1] = 1, 3
		l, err := NewHashList(width, data)
		if err != nil {
			t.Fatal(err)
		}
		var h Hash
		h[int(width)-1] = 3
		if !l.Matches(h) || l.Len() != 2 || l.HashLength() != width {
			t.Fatal("membership/metadata")
		}
		h[int(width)-1] = 2
		if l.Matches(h) {
			t.Fatal("false match")
		}
		want := ListChecksum(sha256.Sum256(data))
		data[0] = 255
		copy := l.Bytes()
		copy[0] = 254
		if *checksum(t, l) != want {
			t.Fatal("list aliases mutable storage")
		}
	}
	for _, tc := range []struct {
		width HashLength
		data  []byte
	}{
		{0, nil}, {5, nil}, {4, []byte{1}}, {4, packed32(2, 1)}, {4, packed32(1, 1)},
	} {
		if _, err := NewHashList(tc.width, tc.data); !errors.Is(err, ErrInvalidList) {
			t.Fatalf("accepted %v", tc)
		}
	}
	var zero HashList
	if zero.Valid() || zero.Len() != 0 || zero.Matches(Hash{}) {
		t.Fatal("zero value")
	}
	if _, err := zero.Checksum(); !errors.Is(err, ErrInvalidList) {
		t.Fatal(err)
	}
	empty := list32(t)
	if *checksum(t, empty) != ListChecksum(sha256.Sum256(nil)) {
		t.Fatal("empty checksum")
	}
	h := Hash{1, 2, 3, 4, 5}
	if h.Prefix4() != (Prefix4{1, 2, 3, 4}) {
		t.Fatal("prefix byte order")
	}
}

func TestApplyUpdate(t *testing.T) {
	base := list32(t, 1, 3, 5, 7)
	want := list32(t, 2, 3, 7, 9)
	u := ListUpdate{Partial: true, Removals: []uint32{0, 2}, Additions: list32(t, 2, 9), ExpectedChecksum: checksum(t, want)}
	got, err := ApplyUpdate(&base, u)
	if err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("update: %v, %v", got, err)
	}
	if !bytes.Equal(base.Bytes(), packed32(1, 3, 5, 7)) {
		t.Fatal("base modified")
	}
	// Removing and re-adding the same entry is valid.
	_, err = ApplyUpdate(&base, ListUpdate{true, []uint32{1}, list32(t, 3), checksum(t, base)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyUpdate(&base, ListUpdate{Partial: true, Additions: list32(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyUpdate(nil, ListUpdate{Additions: want, ExpectedChecksum: checksum(t, want)})
	if err != nil {
		t.Fatal(err)
	}
	// Full replacement can be empty and ignores the base.
	empty := list32(t)
	got, err = ApplyUpdate(&base, ListUpdate{Additions: empty, ExpectedChecksum: checksum(t, empty)})
	if err != nil || got.Len() != 0 {
		t.Fatal("empty replacement", err)
	}
	badWidth, _ := NewHashList(8, nil)
	for name, update := range map[string]ListUpdate{
		"zero additions":        {Partial: true},
		"wrong width":           {Partial: true, Additions: badWidth},
		"descending":            {true, []uint32{2, 1}, empty, checksum(t, empty)},
		"duplicate removal":     {true, []uint32{1, 1}, empty, checksum(t, empty)},
		"out of range":          {true, []uint32{4}, empty, checksum(t, empty)},
		"huge index":            {true, []uint32{^uint32(0)}, empty, checksum(t, empty)},
		"full removals":         {false, []uint32{0}, empty, checksum(t, empty)},
		"duplicate addition":    {true, nil, list32(t, 3), checksum(t, base)},
		"missing checksum":      {true, nil, list32(t, 9), nil},
		"missing full checksum": {Additions: empty},
		"checksum mismatch":     {true, nil, empty, checksum(t, empty)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ApplyUpdate(&base, update)
			if err == nil || got.Valid() {
				t.Fatal("invalid update accepted")
			}
			if !bytes.Equal(base.Bytes(), packed32(1, 3, 5, 7)) {
				t.Fatal("failed update modified base")
			}
		})
	}
	if _, err := ApplyUpdate(nil, u); !errors.Is(err, ErrInvalidUpdate) {
		t.Fatal(err)
	}
	if _, err := ApplyUpdate(&HashList{}, u); !errors.Is(err, ErrInvalidUpdate) {
		t.Fatal(err)
	}
}

func TestUpdateAgainstSetModel(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := range 200 {
		var original, added []uint32
		var removals []uint32
		model := map[uint32]bool{}
		for v := uint32(0); v < 200; v++ {
			if rng.Intn(2) == 0 {
				original = append(original, v)
				if rng.Intn(3) == 0 {
					removals = append(removals, uint32(len(original)-1))
				} else {
					model[v] = true
				}
			}
			if !model[v] && rng.Intn(3) == 0 {
				added = append(added, v)
				model[v] = true
			}
		}
		var expected []uint32
		for v := range model {
			expected = append(expected, v)
		}
		slices.Sort(expected)
		base, want := list32(t, original...), list32(t, expected...)
		got, err := ApplyUpdate(&base, ListUpdate{true, removals, list32(t, added...), checksum(t, want)})
		if err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("trial %d: %v", trial, err)
		}
	}
}

func FuzzHashList(f *testing.F) {
	f.Add(byte(4), packed32(1, 2))
	f.Fuzz(func(t *testing.T, width byte, data []byte) {
		l, err := NewHashList(HashLength(width), data)
		if err != nil {
			return
		}
		if !bytes.Equal(l.Bytes(), data) {
			t.Fatal("round trip")
		}
		for i := 0; i < l.Len(); i++ {
			var h Hash
			copy(h[:], data[i*int(width):(i+1)*int(width)])
			if !l.Matches(h) {
				t.Fatal("missing member")
			}
		}
	})
}
