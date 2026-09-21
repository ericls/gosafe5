package gosafe5

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type searchFunc func(context.Context, []Prefix4) (HashSearchResult, error)

func (f searchFunc) SearchHashes(ctx context.Context, p []Prefix4) (HashSearchResult, error) {
	return f(ctx, p)
}

type listSourceFunc func() []ListState

func (f listSourceFunc) Lists() []ListState { return f() }

const testSearchURL = "https://example.com/"

func searchFixture(t *testing.T, present bool, api HashSearcher) (*URLChecker, *LocalDatabase, Hash) {
	t.Helper()
	hashes, err := URLHashes(testSearchURL)
	if err != nil {
		t.Fatal(err)
	}
	db := &LocalDatabase{}
	var data []byte
	if present {
		data = hashes[0][:4]
	}
	putSearchList(t, db, "mw-4b", 4, data)
	c, err := NewURLChecker(URLCheckerConfig{API: api, Lists: db, ThreatLists: []string{"mw-4b"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, db, hashes[0]
}

func putSearchList(t *testing.T, db *LocalDatabase, name string, width HashLength, data []byte) {
	t.Helper()
	l, err := NewHashList(width, data)
	if err != nil {
		t.Fatal(err)
	}
	u := DatabaseUpdate{Name: name, Version: []byte("v1"), Update: ListUpdate{Additions: l, ExpectedChecksum: checksum(t, l)}}
	if s, ok := db.Get(name); ok {
		u.BaseVersion = s.Version
	}
	if err := db.Apply(u, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSearchLocalCacheAndCollision(t *testing.T) {
	for _, positive := range []bool{false, true} {
		t.Run(map[bool]string{false: "collision", true: "threat"}[positive], func(t *testing.T) {
			calls := 0
			var target Hash
			c, _, h := searchFixture(t, true, searchFunc(func(_ context.Context, p []Prefix4) (HashSearchResult, error) {
				calls++
				if len(p) != 1 || p[0] != target.Prefix4() {
					t.Fatalf("prefixes: %v", p)
				}
				m := target
				if !positive {
					m[31] ^= 1
				}
				return HashSearchResult{FullHashes: []FullHashMatch{{Hash: m, Details: []FullHashDetail{{ThreatType: ThreatMalware}}}}, CacheDuration: time.Minute}, nil
			}))
			target = h
			now := time.Now()
			c.now = func() time.Time { return now }
			for i := 0; i < 2; i++ {
				r, err := c.SearchURLs(context.Background(), []string{testSearchURL, testSearchURL}, ModeLocalList)
				if err != nil || (len(r.Threats) == 1) != positive {
					t.Fatalf("result=%+v err=%v", r, err)
				}
			}
			if calls != 1 {
				t.Fatalf("calls=%d", calls)
			}
			now = now.Add(time.Minute)
			if _, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeLocalList); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("expired cache reused")
			}
		})
	}
}

func TestSearchModesAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		name              string
		mode              SearchMode
		gc, missing, fail bool
		calls             int
		notReady          bool
	}{
		{"local miss", ModeLocalList, false, false, false, 0, false},
		{"realtime", ModeRealTime, false, false, false, 1, false},
		{"global hit", ModeRealTime, true, false, false, 0, false},
		{"fallback", ModeRealTime, false, false, true, 1, false},
		{"missing local", ModeLocalList, false, true, false, 0, true},
		{"missing online succeeds", ModeRealTime, false, true, false, 1, false},
		{"missing fallback", ModeRealTime, false, true, true, 1, true},
		{"global hit missing local", ModeRealTime, true, true, false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c, db, h := searchFixture(t, false, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
				calls++
				if tc.fail {
					return HashSearchResult{}, errors.New("offline")
				}
				return HashSearchResult{}, nil
			}))
			if tc.gc {
				putSearchList(t, db, "gc-32b", 32, h[:])
			}
			if tc.missing {
				if err := db.Invalidate("mw-4b", []byte("v1")); err != nil {
					t.Fatal(err)
				}
			}
			_, err := c.SearchURLs(context.Background(), []string{testSearchURL}, tc.mode)
			if errors.Is(err, ErrNotReady) != tc.notReady || (err != nil && !tc.notReady) || calls != tc.calls {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestSearchFailOpenNotCached(t *testing.T) {
	calls := 0
	c, _, _ := searchFixture(t, true, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		calls++
		return HashSearchResult{}, errors.New("offline")
	}))
	var events []SearchDiagnostic
	c.config.Diagnostic = func(d SearchDiagnostic) { events = append(events, d) }
	for i := 0; i < 2; i++ {
		r, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeRealTime)
		if err != nil || len(r.Threats) != 0 {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if calls != 4 || len(events) != 4 || events[0].Event != "fallback" || events[1].Event != "fail-open" {
		t.Fatalf("calls=%d events=%v", calls, events)
	}
}

func TestSearchValidationAndCancellation(t *testing.T) {
	calls := 0
	c, _, _ := searchFixture(t, true, searchFunc(func(ctx context.Context, _ []Prefix4) (HashSearchResult, error) {
		calls++
		<-ctx.Done()
		return HashSearchResult{}, ctx.Err()
	}))
	for _, urls := range [][]string{nil, {testSearchURL, "invalid"}, make([]string, 51)} {
		if _, err := c.SearchURLs(context.Background(), urls, ModeLocalList); !errors.Is(err, ErrInvalidAPIRequest) {
			t.Fatal(err)
		}
	}
	if _, err := c.SearchURLs(context.Background(), []string{testSearchURL}, "bad"); !errors.Is(err, ErrInvalidAPIRequest) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.SearchURLs(ctx, []string{testSearchURL}, ModeLocalList); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("validation performed I/O")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := c.SearchURLs(ctx, []string{testSearchURL}, ModeRealTime); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("cancellation triggered fallback")
	}
}

func TestSearchAttributesAndRequestMemo(t *testing.T) {
	var target Hash
	calls := 0
	c, _, h := searchFixture(t, true, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		calls++
		return HashSearchResult{FullHashes: []FullHashMatch{{Hash: target, Details: []FullHashDetail{
			{ThreatType: ThreatMalware}, {ThreatType: ThreatMalware},
			{ThreatType: ThreatSocialEngineering, Attributes: []ThreatAttribute{AttributeCanary}},
			{ThreatType: ThreatUnwantedSoftware, Attributes: []ThreatAttribute{AttributeFrameOnly}},
			{ThreatType: ThreatSocialEngineering, Attributes: []ThreatAttribute{"UNKNOWN"}},
			{ThreatType: "UNKNOWN"},
		}}}}, nil
	}))
	target = h
	urls := []string{testSearchURL, "https://EXAMPLE.com/", testSearchURL}
	r, err := c.SearchURLs(context.Background(), urls, ModeLocalList)
	if err != nil || len(r.Threats) != 2 || calls != 1 {
		t.Fatalf("%+v %v calls=%d", r, err, calls)
	}
	for i, v := range r.Threats {
		if v.URL != urls[i] || !reflect.DeepEqual(v.ThreatTypes, []ThreatType{ThreatMalware}) {
			t.Fatal(v)
		}
	}
	_, _ = c.SearchURLs(context.Background(), urls, ModeLocalList)
	if calls != 2 {
		t.Fatal("zero TTL persisted")
	}
}

func TestSearchCacheSharedAcrossModes(t *testing.T) {
	calls := 0
	c, _, _ := searchFixture(t, false, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		calls++
		return HashSearchResult{CacheDuration: time.Hour}, nil
	}))
	for _, mode := range []SearchMode{ModeRealTime, ModeLocalList, ModeRealTime} {
		if _, err := c.SearchURLs(context.Background(), []string{testSearchURL}, mode); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestSearchPartialFailureAndBatching(t *testing.T) {
	c, db, _ := searchFixture(t, false, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) { return HashSearchResult{}, nil }))
	// Exercise batching independently of the URL expression limit.
	var hashes []Hash
	var data []byte
	for i := byte(1); i <= 31; i++ {
		h := Hash{i}
		hashes = append(hashes, h)
		data = append(data, h[:4]...)
	}
	putSearchList(t, db, "mw-4b", 4, data)
	calls := 0
	c.config.API = searchFunc(func(_ context.Context, p []Prefix4) (HashSearchResult, error) {
		calls++
		if calls == 1 {
			if len(p) != 30 {
				t.Fatal(len(p))
			}
			return HashSearchResult{FullHashes: []FullHashMatch{{Hash: hashes[0], Details: []FullHashDetail{{ThreatType: ThreatMalware}}}}}, nil
		}
		if len(p) != 1 {
			t.Fatal(len(p))
		}
		return HashSearchResult{}, errors.New("offline")
	})
	types := map[ThreatType]bool{}
	s, _ := db.Get("mw-4b")
	if err := c.check(context.Background(), hashes, true, map[string]HashList{"mw-4b": s.Hashes}, map[Prefix4][]FullHashMatch{}, types); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !types[ThreatMalware] {
		t.Fatalf("calls=%d types=%v", calls, types)
	}
}

func TestSearchConcurrentDatabaseChanges(t *testing.T) {
	var calls atomic.Int32
	c, db, _ := searchFixture(t, false, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		calls.Add(1)
		return HashSearchResult{CacheDuration: time.Minute}, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeRealTime)
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for j := 0; j < 20; j++ {
		putSearchList(t, db, "mw-4b", 4, nil)
	}
	wg.Wait()
}

func TestPrefixCacheLRU(t *testing.T) {
	c := newPrefixCache(2)
	now := time.Now()
	p, q, r := Prefix4{1}, Prefix4{2}, Prefix4{3}
	c.put(p, nil, now.Add(time.Minute))
	c.put(q, nil, now.Add(time.Minute))
	if _, ok := c.get(p, now); !ok {
		t.Fatal("negative hit missing")
	}
	c.put(r, nil, now.Add(time.Minute))
	if _, ok := c.get(q, now); ok {
		t.Fatal("LRU not evicted")
	}
	c.put(p, nil, now.Add(2*time.Minute))
	if _, ok := c.get(p, now.Add(time.Minute)); !ok {
		t.Fatal("replacement lost")
	}
	if _, ok := c.get(p, now.Add(2*time.Minute)); ok {
		t.Fatal("expired hit")
	}
	c = newPrefixCache(-1)
	c.put(p, nil, now.Add(time.Minute))
	if _, ok := c.get(p, now); ok {
		t.Fatal("disabled cache")
	}
}

func TestSearchGlobalHitStillConfirmsThreat(t *testing.T) {
	var target Hash
	calls := 0
	c, db, h := searchFixture(t, true, searchFunc(func(_ context.Context, prefixes []Prefix4) (HashSearchResult, error) {
		calls++
		if len(prefixes) != 1 || prefixes[0] != target.Prefix4() {
			t.Fatal(prefixes)
		}
		return HashSearchResult{FullHashes: []FullHashMatch{{Hash: target, Details: []FullHashDetail{{ThreatType: ThreatMalware}}}}}, nil
	}))
	target = h
	putSearchList(t, db, "gc-32b", 32, h[:])
	r, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeRealTime)
	if err != nil || len(r.Threats) != 1 || calls != 1 {
		t.Fatalf("%+v %v calls=%d", r, err, calls)
	}
}

func TestSearchOneSnapshotPerRequest(t *testing.T) {
	c, db, _ := searchFixture(t, true, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		return HashSearchResult{}, nil
	}))
	// Invalidate the live database during I/O; the second URL must still use
	// the coherent snapshot obtained at the start of this request.
	c.config.API = searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) {
		return HashSearchResult{}, db.Invalidate("mw-4b", []byte("v1"))
	})
	snapshots := 0
	c.config.Lists = listSourceFunc(func() []ListState { snapshots++; return db.Lists() })
	_, err := c.SearchURLs(context.Background(), []string{testSearchURL, "https://other.example/"}, ModeLocalList)
	if err != nil || snapshots != 1 {
		t.Fatalf("err=%v snapshots=%d", err, snapshots)
	}
	if _, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeLocalList); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
}

func TestSearchMalformedResponseNotCached(t *testing.T) {
	for _, response := range []HashSearchResult{
		{CacheDuration: -time.Second},
		{FullHashes: []FullHashMatch{{Hash: Hash{255}}}, CacheDuration: time.Minute},
	} {
		calls := 0
		c, _, _ := searchFixture(t, true, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) { calls++; return response, nil }))
		for i := 0; i < 2; i++ {
			r, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeLocalList)
			if err != nil || len(r.Threats) != 0 {
				t.Fatalf("%+v %v", r, err)
			}
		}
		if calls != 2 {
			t.Fatal("malformed response was cached")
		}
	}
}

func TestSearchCacheOwnsResponse(t *testing.T) {
	var response HashSearchResult
	c, _, h := searchFixture(t, true, searchFunc(func(context.Context, []Prefix4) (HashSearchResult, error) { return response, nil }))
	response = HashSearchResult{CacheDuration: time.Hour, FullHashes: []FullHashMatch{{Hash: h, Details: []FullHashDetail{{ThreatType: ThreatMalware}}}}}
	if _, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeLocalList); err != nil {
		t.Fatal(err)
	}
	response.FullHashes[0].Details[0].ThreatType = ThreatSocialEngineering
	response.FullHashes[0].Hash = Hash{}
	r, err := c.SearchURLs(context.Background(), []string{testSearchURL}, ModeLocalList)
	if err != nil || len(r.Threats) != 1 || r.Threats[0].ThreatTypes[0] != ThreatMalware {
		t.Fatalf("%+v %v", r, err)
	}
}
