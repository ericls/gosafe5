package gosafe5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"time"

	pb "github.com/ericls/gosafe5/internal/sbproto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func decodeDuration(d *durationpb.Duration) (time.Duration, error) {
	if d == nil {
		return 0, nil
	}
	if d.CheckValid() != nil || d.Seconds < 0 || d.Nanos < 0 || d.Seconds > math.MaxInt64/int64(time.Second) ||
		d.Seconds == math.MaxInt64/int64(time.Second) && int64(d.Nanos) > math.MaxInt64%int64(time.Second) {
		return 0, fmt.Errorf("%w: invalid or overflowing duration", ErrInvalidAPIResponse)
	}
	return time.Duration(d.Seconds)*time.Second + time.Duration(d.Nanos), nil
}

func metadataWidth(v int32) HashLength {
	switch v {
	case 2:
		return 4
	case 3:
		return 8
	case 4:
		return 16
	case 5:
		return 32
	}
	return 0
}

func threatName(v int32) string {
	switch v {
	case 1:
		return string(ThreatMalware)
	case 2:
		return string(ThreatSocialEngineering)
	case 3:
		return string(ThreatUnwantedSoftware)
	case 4:
		return string(ThreatPotentiallyHarmfulApplication)
	}
	return ""
}

func decodeMetadata(m *pb.HashListMetadata) (*ListMetadata, error) {
	if m == nil {
		return nil, nil
	}
	if len(m.ThreatTypes) != 0 && len(m.LikelySafeTypes) != 0 {
		return nil, fmt.Errorf("%w: conflicting metadata types", ErrInvalidAPIResponse)
	}
	result := &ListMetadata{Description: m.Description}
	for _, v := range m.ThreatTypes {
		name := threatName(v)
		if name == "" {
			name = strconv.FormatInt(int64(v), 10)
		}
		result.ThreatTypes = append(result.ThreatTypes, name)
	}
	for _, v := range m.LikelySafeTypes {
		name := strconv.FormatInt(int64(v), 10)
		switch v {
		case 1:
			name = "GENERAL_BROWSING"
		case 2:
			name = "CSD"
		case 3:
			name = "DOWNLOAD"
		}
		result.LikelySafeTypes = append(result.LikelySafeTypes, name)
	}
	return result, nil
}

func makeRice(first []byte, k, count int32, data []byte) (*RiceBlock, error) {
	if k < 0 || k > 255 || count < 0 {
		return nil, fmt.Errorf("%w: Rice parameter or count", ErrInvalidAPIResponse)
	}
	return &RiceBlock{FirstValue: first, RiceParameter: uint8(k), EntriesCount: uint32(count), EncodedData: data}, nil
}

func rice32(r *pb.RiceDeltaEncoded32Bit) (*RiceBlock, error) {
	if r == nil {
		return nil, nil
	}
	first := make([]byte, 4)
	binary.BigEndian.PutUint32(first, r.FirstValue)
	return makeRice(first, r.RiceParameter, r.EntriesCount, r.EncodedData)
}

func first64(parts ...uint64) []byte {
	b := make([]byte, 8*len(parts))
	for i, part := range parts {
		binary.BigEndian.PutUint64(b[i*8:], part)
	}
	return b
}

func (a *HTTPAPI) decodeList(r HashListRequest, l *pb.HashList) (DatabaseUpdate, error) {
	bad := func(reason string) (DatabaseUpdate, error) {
		return DatabaseUpdate{}, fmt.Errorf("%w: %s", ErrInvalidAPIResponse, reason)
	}
	if l == nil || l.Name != r.Name || len(l.Version) == 0 {
		return bad("list name or version")
	}
	if l.PartialUpdate && len(r.Version) == 0 {
		return bad("partial update without base version")
	}
	if !l.PartialUpdate && l.CompressedRemovals != nil {
		return bad("full replacement has removals")
	}
	wait, err := decodeDuration(l.MinimumWaitDuration)
	if err != nil {
		return DatabaseUpdate{}, err
	}
	metadata, err := decodeMetadata(l.Metadata)
	if err != nil {
		return DatabaseUpdate{}, err
	}
	if l.Metadata != nil && metadataWidth(l.Metadata.HashLength) != r.HashLength {
		return bad("metadata width mismatch")
	}
	var block *RiceBlock
	width := r.HashLength
	switch addition := l.CompressedAdditions.(type) {
	case nil:
	case *pb.HashList_AdditionsFourBytes:
		width = 4
		block, err = rice32(addition.AdditionsFourBytes)
	case *pb.HashList_AdditionsEightBytes:
		width = 8
		b := addition.AdditionsEightBytes
		block, err = makeRice(first64(b.GetFirstValue()), b.GetRiceParameter(), b.GetEntriesCount(), b.GetEncodedData())
	case *pb.HashList_AdditionsSixteenBytes:
		width = 16
		b := addition.AdditionsSixteenBytes
		block, err = makeRice(first64(b.GetFirstValueHi(), b.GetFirstValueLo()), b.GetRiceParameter(), b.GetEntriesCount(), b.GetEncodedData())
	case *pb.HashList_AdditionsThirtyTwoBytes:
		width = 32
		b := addition.AdditionsThirtyTwoBytes
		block, err = makeRice(first64(b.GetFirstValueFirstPart(), b.GetFirstValueSecondPart(), b.GetFirstValueThirdPart(), b.GetFirstValueFourthPart()), b.GetRiceParameter(), b.GetEntriesCount(), b.GetEncodedData())
	default:
		return bad("unsupported additions")
	}
	if err != nil {
		return DatabaseUpdate{}, err
	}
	if width != r.HashLength {
		return bad("addition width mismatch")
	}
	additions, err := DecodeRiceHashes(width, block, a.maxEntries)
	if err != nil {
		return DatabaseUpdate{}, fmt.Errorf("%w: %w", ErrInvalidAPIResponse, err)
	}
	removalBlock, err := rice32(l.CompressedRemovals)
	if err != nil {
		return DatabaseUpdate{}, err
	}
	removals, err := DecodeRiceIndices(removalBlock, a.maxEntries)
	if err != nil {
		return DatabaseUpdate{}, fmt.Errorf("%w: %w", ErrInvalidAPIResponse, err)
	}
	var checksum *ListChecksum
	if len(l.Sha256Checksum) != 0 {
		if len(l.Sha256Checksum) != 32 {
			return bad("checksum length")
		}
		sum := ListChecksum(l.Sha256Checksum)
		checksum = &sum
	} else if !l.PartialUpdate || additions.Len() != 0 || len(removals) != 0 {
		return bad("missing checksum for changed list")
	}
	update := ListUpdate{Partial: l.PartialUpdate, Additions: additions, Removals: removals, ExpectedChecksum: checksum}
	if !l.PartialUpdate {
		if _, err := ApplyUpdate(nil, update); err != nil {
			return DatabaseUpdate{}, fmt.Errorf("%w: %w", ErrInvalidAPIResponse, err)
		}
	}
	return DatabaseUpdate{Name: l.Name, BaseVersion: bytes.Clone(r.Version), Version: bytes.Clone(l.Version),
		MinimumWaitDuration: wait, Metadata: metadata, Update: update}, nil
}
