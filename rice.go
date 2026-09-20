package gosafe5

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// REF: https://developers.google.com/safe-browsing/reference/Local.Database
// REF: https://developers.google.com/safe-browsing/reference/rest/v5/hashList

// ErrInvalidRice identifies malformed or overflowing Rice data.
var ErrInvalidRice = errors.New("gosafe5: invalid Rice data")

// ErrDecodeLimit means a decoded result exceeds the caller's entry limit.
var ErrDecodeLimit = errors.New("gosafe5: Rice decode limit exceeded")

// RiceBlock is a transport-independent v5 Rice-delta block. FirstValue is
// exactly the list width in big-endian bytes; EntriesCount counts deltas, not
// total entries. EncodedData is read least-significant-bit first. A nil block
// represents no entries, while a present block with zero deltas has one entry.
// Callers must not mutate its byte slices while decoding.
type RiceBlock struct {
	FirstValue    []byte
	RiceParameter uint8
	EntriesCount  uint32
	EncodedData   []byte
}

// DecodeRiceHashes decodes a sorted list of 4-, 8-, 16-, or 32-byte entries.
// maxEntries must be positive and bounds allocation, including the first value.
func DecodeRiceHashes(width HashLength, block *RiceBlock, maxEntries int) (HashList, error) {
	data, err := decodeRice(width, block, maxEntries)
	if err != nil {
		return HashList{}, err
	}
	return HashList{width: width, data: data}, nil
}

// DecodeRiceIndices decodes strictly increasing 32-bit removal indices.
func DecodeRiceIndices(block *RiceBlock, maxEntries int) ([]uint32, error) {
	data, err := decodeRice(HashLength4, block, maxEntries)
	if err != nil {
		return nil, err
	}
	indices := make([]uint32, len(data)/4)
	for i := range indices {
		indices[i] = binary.BigEndian.Uint32(data[i*4:])
	}
	return indices, nil
}

func decodeRice(width HashLength, block *RiceBlock, maxEntries int) ([]byte, error) {
	bad := func(reason string) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRice, reason)
	}
	if !width.valid() {
		return bad("unsupported width")
	}
	if maxEntries <= 0 {
		return nil, ErrDecodeLimit
	}
	if block == nil {
		return nil, nil
	}
	w := int(width)
	if len(block.FirstValue) != w {
		return bad("first value width")
	}
	n := uint64(block.EntriesCount) + 1
	if n > uint64(maxEntries) || n > uint64(int(^uint(0)>>1)/w) {
		return nil, ErrDecodeLimit
	}
	k := int(block.RiceParameter)
	// A single value needs no Rice parameter; protobuf may omit it.
	if block.EntriesCount != 0 {
		minK := w*8 - 29
		if k < minK || k > w*8-2 {
			return bad("Rice parameter out of range")
		}
		if uint64(block.EntriesCount)*uint64(k+1) > uint64(len(block.EncodedData))*8 {
			return bad("truncated deltas")
		}
	}
	out := make([]byte, int(n)*w)
	copy(out, block.FirstValue)
	reader := riceBits{data: block.EncodedData}
	for i := 1; i < int(n); i++ {
		var delta [32]byte
		var quotient uint32
		maxQuotient := uint32(1)<<uint(w*8-k) - 1
		for {
			bit, ok := reader.next()
			if !ok {
				return bad("truncated quotient")
			}
			if bit == 0 {
				break
			}
			if quotient == maxQuotient {
				return bad("quotient overflow")
			}
			quotient++
		}
		for bit := range k {
			v, ok := reader.next()
			if !ok {
				return bad("truncated remainder")
			}
			delta[w-1-bit/8] |= v << uint(bit%8)
		}
		for bit := k; bit < w*8; bit++ {
			delta[w-1-bit/8] |= byte(quotient&1) << uint(bit%8)
			quotient >>= 1
		}
		var carry uint16
		var nonzero byte
		for b := w - 1; b >= 0; b-- {
			nonzero |= delta[b]
			sum := uint16(out[(i-1)*w+b]) + uint16(delta[b]) + carry
			out[i*w+b] = byte(sum)
			carry = sum >> 8
		}
		if carry != 0 {
			return bad("value overflow")
		}
		if nonzero == 0 {
			return bad("duplicate value")
		}
	}
	// Only zero padding to the next byte boundary is permitted.
	consumedBytes := reader.byteIndex
	if reader.bitIndex != 0 {
		consumedBytes++
	}
	if consumedBytes != len(reader.data) {
		return bad("trailing data")
	}
	if reader.bitIndex != 0 && reader.data[reader.byteIndex]>>reader.bitIndex != 0 {
		return bad("nonzero padding")
	}
	return out, nil
}

type riceBits struct {
	data      []byte
	byteIndex int
	bitIndex  uint8
}

func (r *riceBits) next() (byte, bool) {
	if r.byteIndex == len(r.data) {
		return 0, false
	}
	v := r.data[r.byteIndex] >> r.bitIndex & 1
	r.bitIndex++
	if r.bitIndex == 8 {
		r.bitIndex = 0
		r.byteIndex++
	}
	return v, true
}
