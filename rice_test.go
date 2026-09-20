package gosafe5

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestRiceOfficialVector(t *testing.T) {
	// Google's Local.Database worked example: these are the prefixes of
	// b.example.com/, a.example.com/, and y.example.com/, in sorted order.
	encoded, _ := hex.DecodeString("7400d2971bed497400")
	block := &RiceBlock{FirstValue: packed32(0x1d32c508), RiceParameter: 30, EntriesCount: 2, EncodedData: encoded}
	l, err := DecodeRiceHashes(4, block, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := packed32(0x1d32c508, 0x291bc542, 0xf7a502e5)
	if !bytes.Equal(l.Bytes(), want) {
		t.Fatalf("got %x; want %x", l.Bytes(), want)
	}
	indices, err := DecodeRiceIndices(block, 3)
	if err != nil || len(indices) != 3 || indices[2] != 0xf7a502e5 {
		t.Fatal(indices, err)
	}
}

func TestRiceWidthsAndCarries(t *testing.T) {
	for _, width := range []HashLength{4, 8, 16, 32} {
		w := int(width)
		first := bytes.Repeat([]byte{255}, w)
		first[0] = 0
		k := w*8 - 29
		encoded := make([]byte, (k+1+7)/8)
		encoded[0] = 2 // quotient 0, remainder 1, LSB first.
		block := &RiceBlock{first, uint8(k), 1, encoded}
		l, err := DecodeRiceHashes(width, block, 2)
		if err != nil {
			t.Fatal(width, err)
		}
		want := append(bytes.Clone(first), make([]byte, w)...)
		want[w] = 1
		if !bytes.Equal(l.Bytes(), want) {
			t.Fatalf("%d-byte carry: %x", width, l.Bytes())
		}
		// The decoder owns its returned storage.
		first[0] = 2
		if !bytes.Equal(l.Bytes(), want) {
			t.Fatal("aliased first value")
		}
		first[0] = 255
		if _, err := DecodeRiceHashes(width, block, 2); !errors.Is(err, ErrInvalidRice) {
			t.Fatal("overflow accepted", width, err)
		}
	}
	// quotient=3, remainder=3, k=3 -> delta=27.
	l, err := DecodeRiceHashes(4, &RiceBlock{packed32(0), 3, 1, []byte{0x37}}, 2)
	if err != nil || !bytes.Equal(l.Bytes(), packed32(0, 27)) {
		t.Fatal("unary quotient", err)
	}
	// Most significant delta bit exercises the quotient at k=30.
	l, err = DecodeRiceHashes(4, &RiceBlock{packed32(0), 30, 1, []byte{3, 0, 0, 0, 0}}, 2)
	if err != nil || !bytes.Equal(l.Bytes(), packed32(0, 0x80000000)) {
		t.Fatal("high quotient", err)
	}
}

func TestRiceEmptyAndSingleton(t *testing.T) {
	l, err := DecodeRiceHashes(4, nil, 1)
	if err != nil || !l.Valid() || l.Len() != 0 {
		t.Fatal("absent block", err)
	}
	l, err = DecodeRiceHashes(4, &RiceBlock{FirstValue: packed32(0)}, 1)
	if err != nil || l.Len() != 1 || !l.Matches(Hash{}) {
		t.Fatal("present zero singleton", err)
	}
	indices, err := DecodeRiceIndices(nil, 1)
	if err != nil || len(indices) != 0 {
		t.Fatal("absent removals", err)
	}
}

func TestRiceRejectsMalformed(t *testing.T) {
	for name, block := range map[string]*RiceBlock{
		"bad first width":     {FirstValue: []byte{1}},
		"low parameter":       {packed32(0), 2, 1, []byte{2}},
		"high parameter":      {packed32(0), 31, 1, []byte{2, 0, 0, 0}},
		"truncated":           {packed32(0), 30, 1, nil},
		"truncated quotient":  {packed32(0), 3, 1, []byte{255}},
		"truncated remainder": {packed32(0), 3, 1, []byte{0x3f}},
		"quotient overflow":   {packed32(0), 30, 1, []byte{15, 0, 0, 0}},
		"duplicate":           {packed32(0), 3, 1, []byte{0}},
		"nonzero padding":     {packed32(0), 3, 1, []byte{0x82}},
		"trailing data":       {packed32(0), 3, 1, []byte{2, 0}},
		"singleton trailing":  {packed32(0), 0, 0, []byte{0}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRiceHashes(4, block, 10); !errors.Is(err, ErrInvalidRice) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := DecodeRiceHashes(5, nil, 10); !errors.Is(err, ErrInvalidRice) {
		t.Fatal(err)
	}
	if _, err := DecodeRiceHashes(4, nil, 0); !errors.Is(err, ErrDecodeLimit) {
		t.Fatal(err)
	}
	if _, err := DecodeRiceHashes(4, &RiceBlock{FirstValue: packed32(0), EntriesCount: ^uint32(0)}, 10); !errors.Is(err, ErrDecodeLimit) {
		t.Fatal(err)
	}
}

func FuzzRice(f *testing.F) {
	f.Add(byte(4), packed32(0), byte(3), uint32(1), []byte{2})
	f.Add(byte(32), make([]byte, 32), byte(227), uint32(0), []byte{})
	f.Fuzz(func(t *testing.T, width byte, first []byte, k byte, count uint32, data []byte) {
		block := &RiceBlock{first, k, count, data}
		l, err := DecodeRiceHashes(HashLength(width), block, 1024)
		if err != nil {
			return
		}
		if l.Len() != int(count)+1 {
			t.Fatal("entry count")
		}
		if _, err := NewHashList(l.HashLength(), l.Bytes()); err != nil {
			t.Fatal("invalid decoder result", err)
		}
	})
}
