package gosafe5

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/ericls/gosafe5/internal/sbproto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func apiServer(t *testing.T, handler http.HandlerFunc) *HTTPAPI {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	a, err := NewHTTPAPI(APIConfig{APIKey: "secret-key", BaseURL: s.URL, HTTPClient: s.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func writeProto(t *testing.T, w http.ResponseWriter, m proto.Message) {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(b)
}

func TestAPIGetWireFixture(t *testing.T) {
	// Hand-encoded according to Google's field numbers, independent of our
	// generated encoder: name mw-4b, version v2, partial=true, wait=3 seconds.
	fixture, _ := hex.DecodeString("0a056d772d346212027632180132020803")
	version := []byte{0, 255, 251}
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method != "GET" || r.URL.Path != "/v5/hashList/mw-4b" || q.Get("key") != "secret-key" || q.Get("alt") != "proto" || r.Header.Get("Accept") != "application/x-protobuf" {
			t.Error("request", r.Method, r.URL.Path)
		}
		got, err := base64.URLEncoding.DecodeString(q.Get("version"))
		if err != nil || !bytes.Equal(got, version) || q.Get("sizeConstraints.maxUpdateEntries") != "1024" || q.Get("sizeConstraints.maxDatabaseEntries") != "5000" {
			t.Error("query encoding")
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(fixture)
	})
	u, err := a.GetHashList(context.Background(), HashListRequest{"mw-4b", version, 4}, SizeConstraints{1024, 5000})
	if err != nil {
		t.Fatal(err)
	}
	if string(u.Version) != "v2" || !bytes.Equal(u.BaseVersion, version) || u.MinimumWaitDuration != 3*time.Second || !u.Update.Partial || u.Update.Additions.Len() != 0 || u.Update.Additions.HashLength() != 4 || u.Update.ExpectedChecksum != nil {
		t.Fatal("decoded update", u)
	}
	version[0] = 9
	if u.BaseVersion[0] != 0 {
		t.Fatal("aliased request")
	}
}

func TestAPIWideFixed64WireFixture(t *testing.T) {
	// The low 64 bits use protobuf fixed64 little-endian wire encoding, but
	// the decoded hash itself is big-endian. No Rice deltas (one entry).
	fixture, _ := hex.DecodeString("0a0161120176520b0801110807060504030201")
	data, _ := hex.DecodeString("00000000000000010102030405060708")
	l, _ := NewHashList(16, data)
	sum := checksum(t, l)
	fixture = append(fixture, 0x3a, 0x20)
	fixture = append(fixture, sum[:]...)
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) })
	u, err := a.GetHashList(context.Background(), HashListRequest{Name: "a", HashLength: 16}, SizeConstraints{})
	if err != nil || !bytes.Equal(u.Update.Additions.Bytes(), data) {
		t.Fatal("fixed64 decode", err)
	}
}

func TestAPIBatchAndDatabase(t *testing.T) {
	want := list32(t, 1, 2)
	sum := checksum(t, want)
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v5/hashLists:batchGet" || !reflect.DeepEqual(r.URL.Query()["names"], []string{"mw-4b", "se-4b"}) || len(r.URL.Query()["version"]) != 1 {
			t.Error("batch query")
		}
		writeProto(t, w, &pb.BatchGetHashListsResponse{HashLists: []*pb.HashList{
			{Name: "mw-4b", Version: []byte("v1"), Sha256Checksum: sum[:], CompressedAdditions: &pb.HashList_AdditionsFourBytes{AdditionsFourBytes: &pb.RiceDeltaEncoded32Bit{FirstValue: 1, RiceParameter: 3, EntriesCount: 1, EncodedData: []byte{2}}}},
			{Name: "se-4b", Version: []byte("v2"), PartialUpdate: true},
		}})
	})
	updates, err := a.BatchGetHashLists(context.Background(), []HashListRequest{{Name: "mw-4b", HashLength: 4}, {"se-4b", []byte("v1"), 4}}, SizeConstraints{})
	if err != nil {
		t.Fatal(err)
	}
	var db LocalDatabase
	if err := db.Apply(updates[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	s, _ := db.Get("mw-4b")
	if !bytes.Equal(s.Hashes.Bytes(), want.Bytes()) {
		t.Fatal("database mapping")
	}
	if string(updates[1].BaseVersion) != "v1" {
		t.Fatal("base version lost")
	}
}

func TestAPIListPagination(t *testing.T) {
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v5/hashLists" || r.URL.Query().Get("pageToken") != "opaque+/=" || r.URL.Query().Get("pageSize") != "2" {
			t.Error("pagination")
		}
		writeProto(t, w, &pb.ListHashListsResponse{NextPageToken: "next", HashLists: []*pb.HashList{
			{Name: "gc-32b", Metadata: &pb.HashListMetadata{HashLength: 5, LikelySafeTypes: []int32{1}, Description: "Global cache"}},
			{Name: "mw-4b", Metadata: &pb.HashListMetadata{HashLength: 2, ThreatTypes: []int32{1, 99}}},
		}})
	})
	page, err := a.ListHashLists(context.Background(), ListHashListsRequest{2, "opaque+/="})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextPageToken != "next" || len(page.Lists) != 2 || page.Lists[0].HashLength != 32 || page.Lists[1].Metadata.ThreatTypes[1] != "99" {
		t.Fatal(page)
	}
}

func TestAPISearchHashes(t *testing.T) {
	h := Hash{255, 254, 0, 1}
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()["hashPrefixes"]
		if r.URL.Path != "/v5/hashes:search" || len(q) != 1 {
			t.Error("search query")
		}
		p, err := base64.URLEncoding.DecodeString(q[0])
		if err != nil || !bytes.Equal(p, h[:4]) {
			t.Error("prefix encoding")
		}
		writeProto(t, w, &pb.SearchHashesResponse{CacheDuration: durationpb.New(1500 * time.Millisecond), FullHashes: []*pb.FullHash{{FullHash: h[:], FullHashDetails: []*pb.FullHashDetail{
			{ThreatType: 1}, {ThreatType: 2, Attributes: []int32{1, 2}}, {ThreatType: 99}, {ThreatType: 1, Attributes: []int32{1, 99}}, {ThreatType: 0},
		}}}})
	})
	result, err := a.SearchHashes(context.Background(), []Prefix4{h.Prefix4(), h.Prefix4()})
	if err != nil {
		t.Fatal(err)
	}
	if result.CacheDuration != 1500*time.Millisecond || len(result.FullHashes) != 1 || result.FullHashes[0].Hash != h || len(result.FullHashes[0].Details) != 2 || result.FullHashes[0].Details[1].Attributes[0] != AttributeCanary {
		t.Fatal(result)
	}
	negative := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeProto(t, w, &pb.SearchHashesResponse{CacheDuration: durationpb.New(time.Minute)})
	})
	result, err = negative.SearchHashes(context.Background(), []Prefix4{{}})
	if err != nil || len(result.FullHashes) != 0 || result.CacheDuration != time.Minute {
		t.Fatal("negative caching", err)
	}
}

func TestAPIHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		limit                   int64
		target                  error
	}{
		{"json", "application/json", `{}`, 200, 100, ErrInvalidAPIResponse},
		{"malformed protobuf", "application/x-protobuf", "\xff", 200, 100, ErrInvalidAPIResponse},
		{"too large", "application/x-protobuf", strings.Repeat("x", 101), 200, 100, ErrAPIResponseTooLarge},
		{"rate limited", "application/json", "secret-key", 429, 100, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			a.maxBytes = tc.limit
			_, err := a.SearchHashes(context.Background(), []Prefix4{{}})
			if err == nil || strings.Contains(err.Error(), "secret-key") {
				t.Fatal("error or credential leak", err)
			}
			if tc.target != nil && !errors.Is(err, tc.target) {
				t.Fatal(err)
			}
			if tc.status == 429 {
				var status *HTTPError
				if !errors.As(err, &status) || status.StatusCode != 429 || status.RetryAfter != "30" {
					t.Fatal(err)
				}
			}
		})
	}
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled request reached server") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.SearchHashes(ctx, []Prefix4{{}}); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "secret-key") {
		t.Fatal(err)
	}
}

func TestAPIRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) })
	_, err := a.SearchHashes(context.Background(), []Prefix4{{}})
	var status *HTTPError
	if !errors.As(err, &status) || status.StatusCode != 302 {
		t.Fatal(err)
	}
}

func TestAPIValidation(t *testing.T) {
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid request reached server") })
	ctx := context.Background()
	for _, r := range []HashListRequest{{}, {Name: "../x", HashLength: 4}, {Name: "mw-4b", HashLength: 5}} {
		if _, err := a.GetHashList(ctx, r, SizeConstraints{}); !errors.Is(err, ErrInvalidAPIRequest) {
			t.Fatal(err)
		}
	}
	r := HashListRequest{Name: "mw-4b", HashLength: 4}
	if _, err := a.GetHashList(ctx, r, SizeConstraints{MaxUpdateEntries: 1}); !errors.Is(err, ErrInvalidAPIRequest) {
		t.Fatal(err)
	}
	if _, err := a.BatchGetHashLists(ctx, []HashListRequest{r, r}, SizeConstraints{}); !errors.Is(err, ErrInvalidAPIRequest) {
		t.Fatal(err)
	}
	if _, err := a.BatchGetHashLists(ctx, nil, SizeConstraints{}); !errors.Is(err, ErrInvalidAPIRequest) {
		t.Fatal(err)
	}
	if _, err := a.ListHashLists(ctx, ListHashListsRequest{PageSize: -1}); !errors.Is(err, ErrInvalidAPIRequest) {
		t.Fatal(err)
	}
	for _, p := range [][]Prefix4{nil, make([]Prefix4, 1001)} {
		if _, err := a.SearchHashes(ctx, p); !errors.Is(err, ErrInvalidAPIRequest) {
			t.Fatal(err)
		}
	}
	for _, d := range []*durationpb.Duration{{Seconds: -1}, {Nanos: -1}, {Nanos: 1e9}, {Seconds: math.MaxInt64}, {Seconds: math.MaxInt64 / int64(time.Second), Nanos: 999999999}} {
		if _, err := decodeDuration(d); !errors.Is(err, ErrInvalidAPIResponse) {
			t.Fatal("invalid duration", err)
		}
	}
}

func TestAPIRejectsListResponses(t *testing.T) {
	for name, response := range map[string]*pb.HashList{
		"wrong name":           {Name: "other", Version: []byte("v")},
		"empty version":        {Name: "mw-4b"},
		"missing checksum":     {Name: "mw-4b", Version: []byte("v")},
		"bad checksum":         {Name: "mw-4b", Version: []byte("v"), Sha256Checksum: make([]byte, 32)},
		"negative count":       {Name: "mw-4b", Version: []byte("v"), CompressedAdditions: &pb.HashList_AdditionsFourBytes{AdditionsFourBytes: &pb.RiceDeltaEncoded32Bit{EntriesCount: -1}}},
		"width mismatch":       {Name: "mw-4b", Version: []byte("v"), CompressedAdditions: &pb.HashList_AdditionsEightBytes{AdditionsEightBytes: &pb.RiceDeltaEncoded64Bit{}}},
		"full removals":        {Name: "mw-4b", Version: []byte("v"), CompressedRemovals: &pb.RiceDeltaEncoded32Bit{}},
		"partial without base": {Name: "mw-4b", Version: []byte("v"), PartialUpdate: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := apiServer(t, func(w http.ResponseWriter, r *http.Request) { writeProto(t, w, response) })
			if _, err := a.GetHashList(context.Background(), HashListRequest{Name: "mw-4b", HashLength: 4}, SizeConstraints{}); !errors.Is(err, ErrInvalidAPIResponse) {
				t.Fatal(err)
			}
		})
	}
}

// A domain-only fake implements the same interface without protobuf or HTTP.
type fakeAPI struct{ update DatabaseUpdate }

var _ API = fakeAPI{}

func (f fakeAPI) ListHashLists(context.Context, ListHashListsRequest) (HashListsPage, error) {
	return HashListsPage{}, nil
}
func (f fakeAPI) GetHashList(context.Context, HashListRequest, SizeConstraints) (DatabaseUpdate, error) {
	return f.update, nil
}
func (f fakeAPI) BatchGetHashLists(context.Context, []HashListRequest, SizeConstraints) ([]DatabaseUpdate, error) {
	return []DatabaseUpdate{f.update}, nil
}
func (f fakeAPI) SearchHashes(context.Context, []Prefix4) (HashSearchResult, error) {
	return HashSearchResult{CacheDuration: time.Minute}, nil
}

func TestMockAPI(t *testing.T) {
	var api API = fakeAPI{update: databaseFull(t, "mw-4b", "v1", 1)}
	u, err := api.GetHashList(context.Background(), HashListRequest{Name: "mw-4b", HashLength: 4}, SizeConstraints{})
	if err != nil {
		t.Fatal(err)
	}
	var db LocalDatabase
	if err := db.Apply(u, time.Now()); err != nil {
		t.Fatal(err)
	}
}
