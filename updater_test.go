package gosafe5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

type updaterAPI struct {
	API
	batch func(context.Context, []HashListRequest, SizeConstraints) ([]DatabaseUpdate, error)
}

func (a updaterAPI) BatchGetHashLists(ctx context.Context, r []HashListRequest, c SizeConstraints) ([]DatabaseUpdate, error) {
	return a.batch(ctx, r, c)
}

type testUpdaterClock struct {
	mu    sync.Mutex
	now   time.Time
	waits chan time.Duration
	ticks chan time.Time
}

func newUpdaterClock() *testUpdaterClock {
	return &testUpdaterClock{now: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC), waits: make(chan time.Duration), ticks: make(chan time.Time)}
}
func (c *testUpdaterClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testUpdaterClock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = t }
func (c *testUpdaterClock) Wait(ctx context.Context, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.waits <- delay:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case now := <-c.ticks:
		c.set(now)
		return nil
	}
}

func testUpdater(t *testing.T, api API, store SnapshotStore, names ...string) (*ListUpdater, *testUpdaterClock) {
	t.Helper()
	var lists []HashListInfo
	for _, name := range names {
		lists = append(lists, HashListInfo{Name: name, HashLength: 4, Metadata: ListMetadata{ThreatTypes: []string{"MALWARE"}}})
	}
	u, err := NewListUpdater(UpdaterConfig{API: api, Lists: lists, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	clock := newUpdaterClock()
	u.clock = clock
	u.jitter = func(d time.Duration) time.Duration { return d }
	return u, clock
}

func fullForRequest(t *testing.T, r HashListRequest, version string, wait time.Duration) DatabaseUpdate {
	t.Helper()
	u := databaseFull(t, r.Name, version, 1)
	u.BaseVersion = bytes.Clone(r.Version)
	u.MinimumWaitDuration = wait
	return u
}

func TestUpdaterDueBatching(t *testing.T) {
	calls := 0
	api := updaterAPI{batch: func(ctx context.Context, r []HashListRequest, c SizeConstraints) ([]DatabaseUpdate, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("missing request deadline")
		}
		if calls == 1 {
			if len(r) != 2 || r[0].Name != "a" || r[1].Name != "b" || len(r[0].Version) != 0 {
				t.Fatal("initial batch", r)
			}
			return []DatabaseUpdate{fullForRequest(t, r[0], "v1", time.Second), fullForRequest(t, r[1], "v1", 3*time.Second)}, nil
		}
		if len(r) != 1 || r[0].Name != "a" || string(r[0].Version) != "v1" {
			t.Fatal("due batch", r)
		}
		return []DatabaseUpdate{{Name: "a", BaseVersion: []byte("v1"), Version: []byte("v2"), MinimumWaitDuration: 5 * time.Second, Update: ListUpdate{Partial: true, Additions: list32(t)}}}, nil
	}}
	u, clock := testUpdater(t, api, nil, "b", "a")
	if _, err := u.Lookup(Hash{}); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := clock.Now()
	if err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if !u.Status().Ready || u.Status().Dirty {
		t.Fatal(u.Status())
	}
	s, _ := u.Get("a")
	s.Metadata.ThreatTypes[0] = "changed"
	if got, _ := u.Get("a"); got.Metadata.ThreatTypes[0] != "MALWARE" {
		t.Fatal("snapshot alias")
	}
	var hash Hash
	copy(hash[:], packed32(1))
	if matches, err := u.Lookup(hash); err != nil || len(matches) != 2 {
		t.Fatal("membership", err)
	}
	if err := u.Update(ctx); err != nil || calls != 1 {
		t.Fatal("early fetch", err)
	}
	clock.set(now.Add(time.Second))
	if err := u.Update(ctx); err != nil || calls != 2 {
		t.Fatal(err)
	}
	if u.nextDelay() != 2*time.Second {
		t.Fatal("wrong wakeup", u.nextDelay())
	}
}

func TestUpdaterNetworkRetryAndRecovery(t *testing.T) {
	calls := 0
	api := updaterAPI{batch: func(ctx context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		calls++
		switch calls {
		case 1:
			return []DatabaseUpdate{fullForRequest(t, r[0], "v1", time.Second)}, nil
		case 2:
			return nil, &HTTPError{StatusCode: 429, RetryAfter: "10"}
		case 3:
			return nil, context.DeadlineExceeded
		default:
			if string(r[0].Version) != "v1" {
				t.Fatal("network failure discarded version")
			}
			return []DatabaseUpdate{fullForRequest(t, r[0], "v2", time.Minute)}, nil
		}
	}}
	u, clock := testUpdater(t, api, nil, "a")
	ctx := context.Background()
	if err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	clock.set(clock.Now().Add(time.Second))
	if err := u.Update(ctx); err == nil {
		t.Fatal("missing error")
	}
	s := u.Status()
	if !s.Ready || s.Lists[0].ConsecutiveFailures != 1 || s.Lists[0].NextAttempt != clock.Now().Add(10*time.Second) {
		t.Fatal(s)
	}
	if err := u.Update(ctx); err != nil || calls != 2 {
		t.Fatal("retry too soon", err)
	}
	clock.set(s.Lists[0].NextAttempt)
	if err := u.Update(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if u.nextDelay() != 2*time.Second {
		t.Fatal("backoff", u.nextDelay())
	}
	clock.set(clock.Now().Add(2 * time.Second))
	if err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if s := u.Status().Lists[0]; s.LastError != nil || s.ConsecutiveFailures != 0 {
		t.Fatal(s)
	}
	if u.retryDelay(10000) != 15*time.Minute {
		t.Fatal("uncapped retry")
	}
	now := clock.Now()
	if retryAfter(now.Add(time.Minute).Format(http.TimeFormat), now).Sub(now) != time.Minute {
		t.Fatal("HTTP date")
	}
}

func TestUpdaterCorruptUpdatePartialSuccess(t *testing.T) {
	calls := 0
	api := updaterAPI{batch: func(_ context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		calls++
		var updates []DatabaseUpdate
		for _, req := range r {
			updates = append(updates, fullForRequest(t, req, "v2", 2*time.Second))
		}
		if calls == 2 {
			updates[0].Update.ExpectedChecksum = &ListChecksum{}
		}
		if calls == 3 && len(r[0].Version) != 0 {
			t.Fatal("rebuild did not clear version")
		}
		return updates, nil
	}}
	u, clock := testUpdater(t, api, nil, "a", "b")
	ctx := context.Background()
	if err := u.Update(ctx); err != nil {
		t.Fatal(err)
	}
	clock.set(clock.Now().Add(2 * time.Second))
	if err := u.Update(ctx); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatal(err)
	}
	if u.Status().Ready {
		t.Fatal("corrupt list still ready")
	}
	if _, ok := u.Get("a"); ok {
		t.Fatal("invalidated list visible")
	}
	if _, ok := u.Get("b"); !ok {
		t.Fatal("successful list lost")
	}
	if _, err := u.Lookup(Hash{}); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	if u.nextDelay() != 2*time.Second {
		t.Fatal("server deadline bypassed")
	}
	clock.set(clock.Now().Add(2 * time.Second))
	if err := u.Update(ctx); err != nil || !u.Status().Ready {
		t.Fatal("recovery", err)
	}
}

func TestUpdaterRejectsMockResponses(t *testing.T) {
	for _, kind := range []string{"count", "name", "base", "width", "scoped", "unscoped"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			api := updaterAPI{batch: func(_ context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
				calls++
				updates := []DatabaseUpdate{fullForRequest(t, r[0], "v1", 0), fullForRequest(t, r[1], "v1", 0)}
				if calls == 1 {
					return updates, nil
				}
				switch kind {
				case "count":
					return nil, nil
				case "name":
					updates[0].Name = "unknown"
				case "base":
					updates[0].BaseVersion = []byte("wrong")
				case "width":
					updates[0].Update.Additions, _ = NewHashList(8, nil)
				case "scoped":
					return nil, &ListResponseError{Name: "a", Err: ErrInvalidAPIResponse}
				case "unscoped":
					return nil, ErrInvalidAPIResponse
				}
				return updates, nil
			}}
			u, _ := testUpdater(t, api, nil, "a", "b")
			if err := u.Update(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := u.Update(context.Background()); err == nil {
				t.Fatal("accepted bad response")
			}
			if _, ok := u.Get("a"); ok {
				t.Fatal("bad list retained")
			}
			_, b := u.Get("b")
			if b != (kind == "scoped" || kind == "base" || kind == "width") {
				t.Fatal("incorrect invalidation scope")
			}
		})
	}
}

type updaterStore struct {
	memoryStore
	loadErr, saveErr error
	loads, saves     int
}

func (s *updaterStore) Load(ctx context.Context) (io.ReadCloser, error) {
	s.loads++
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.memoryStore.Load(ctx)
}
func (s *updaterStore) Save(ctx context.Context, r io.Reader) error {
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.memoryStore.Save(ctx, r)
}

func TestUpdaterPersistenceRetry(t *testing.T) {
	store := &updaterStore{saveErr: errors.New("storage unavailable")}
	calls := 0
	api := updaterAPI{batch: func(_ context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		calls++
		return []DatabaseUpdate{fullForRequest(t, r[0], "v1", time.Hour)}, nil
	}}
	u, clock := testUpdater(t, api, store, "a")
	if err := u.Update(context.Background()); !errors.Is(err, store.saveErr) {
		t.Fatal(err)
	}
	s := u.Status()
	if !s.Ready || !s.Dirty || s.PersistenceError == nil || store.saves != 1 {
		t.Fatal(s)
	}
	if err := u.Update(context.Background()); err != nil || store.saves != 1 || calls != 1 {
		t.Fatal("early retry", err)
	}
	store.saveErr = nil
	clock.set(s.NextSave)
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u.Status().Dirty || u.Status().PersistenceError != nil || calls != 1 || store.saves != 2 {
		t.Fatal("persistence-only retry")
	}
	restarted, newClock := testUpdater(t, api, store, "a")
	newClock.set(clock.Now())
	if err := restarted.Update(context.Background()); err != nil || !restarted.Status().Ready || calls != 1 {
		t.Fatal("restart", err)
	}
}

func TestUpdaterStartup(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "unsupported", "permission", "read error", "too large", "filter"} {
		t.Run(kind, func(t *testing.T) {
			store := &updaterStore{}
			switch kind {
			case "corrupt":
				store.data = []byte("broken")
			case "unsupported":
				store.data = []byte(`{"format":"gosafe5","version":2,"lists":[]}`)
			case "permission":
				store.loadErr = fs.ErrPermission
			case "read error":
				store.loadErr = io.ErrClosedPipe
			case "too large":
				store.data = bytes.Repeat([]byte(" "), 20)
			case "filter":
				db := &LocalDatabase{}
				now := newUpdaterClock().Now()
				for _, name := range []string{"a", "extra"} {
					update := databaseFull(t, name, "old", 1)
					update.MinimumWaitDuration = time.Hour
					if err := db.Apply(update, now); err != nil {
						t.Fatal(err)
					}
				}
				wide, _ := NewHashList(8, nil)
				if err := db.Apply(DatabaseUpdate{Name: "b", Version: []byte("old"), Update: ListUpdate{Additions: wide, ExpectedChecksum: checksum(t, wide)}}, now); err != nil {
					t.Fatal(err)
				}
				if err := db.Save(context.Background(), store); err != nil {
					t.Fatal(err)
				}
				store.saves = 0
			}
			calls := 0
			api := updaterAPI{batch: func(_ context.Context, requests []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
				calls++
				if kind == "filter" && (len(requests) != 1 || requests[0].Name != "b" || len(requests[0].Version) != 0) {
					t.Fatal("restored selection", requests)
				}
				var result []DatabaseUpdate
				for _, r := range requests {
					result = append(result, fullForRequest(t, r, "v1", time.Hour))
				}
				return result, nil
			}}
			u, _ := testUpdater(t, api, store, "a", "b")
			if kind == "too large" {
				u.config.MaxSnapshotBytes = 10
			}
			err := u.Update(context.Background())
			fatal := kind == "unsupported" || kind == "permission" || kind == "read error" || kind == "too large"
			if fatal {
				if err == nil || calls != 0 || store.saves != 0 || u.Status().Initialized {
					t.Fatal("startup should fail", err)
				}
			} else {
				if err != nil || !u.Status().Ready || len(u.Lists()) != 2 || store.saves != 1 {
					t.Fatal("startup", err)
				}
				if kind == "corrupt" && !errors.Is(u.Status().LoadError, ErrInvalidSnapshot) {
					t.Fatal("corruption not visible")
				}
			}
		})
	}
}

func TestUpdaterRunLifecycle(t *testing.T) {
	calls := 0
	api := updaterAPI{batch: func(_ context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		calls++
		wait := time.Duration(0)
		if calls > 1 {
			wait = time.Hour
		}
		return []DatabaseUpdate{fullForRequest(t, r[0], "v1", wait)}, nil
	}}
	u, clock := testUpdater(t, api, nil, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	if delay := <-clock.waits; delay != 0 {
		t.Fatal("zero wait was delayed", delay)
	}
	if !u.Status().Running || !u.Status().Ready {
		t.Fatal("running status")
	}
	if err := u.Update(ctx); !errors.Is(err, ErrUpdaterRunning) {
		t.Fatal(err)
	}
	if err := u.Run(ctx); !errors.Is(err, ErrUpdaterRunning) {
		t.Fatal(err)
	}
	clock.ticks <- clock.Now()
	if delay := <-clock.waits; delay != time.Hour {
		t.Fatal("server wait", delay)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if u.Status().Running || u.Status().Lists[0].LastError != nil {
		t.Fatal("cancellation health")
	}
	if err := u.Update(context.Background()); err != nil || calls != 2 {
		t.Fatal("resume state", err)
	}
}

func TestUpdaterCancellationDuringAPI(t *testing.T) {
	started := make(chan struct{})
	api := updaterAPI{batch: func(ctx context.Context, _ []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	u, _ := testUpdater(t, api, nil, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	<-started
	// These reads complete while the API call is blocked.
	u.Get("a")
	u.Lists()
	u.Lookup(Hash{})
	u.Status()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if u.Status().Lists[0].ConsecutiveFailures != 0 {
		t.Fatal("cancellation treated as failure")
	}
}

func TestDatabaseInvalidate(t *testing.T) {
	var db LocalDatabase
	if err := db.Apply(databaseFull(t, "a", "v1", 1), time.Now()); err != nil {
		t.Fatal(err)
	}
	before := db.Lists()
	if err := db.Invalidate("a", []byte("old")); !errors.Is(err, ErrVersionMismatch) || !reflect.DeepEqual(before, db.Lists()) {
		t.Fatal(err)
	}
	if err := db.Invalidate("a", []byte("v1")); err != nil || len(db.Lists()) != 0 {
		t.Fatal(err)
	}
	if err := db.Invalidate("a", nil); err != nil {
		t.Fatal(err)
	}
}

func TestUpdaterConfiguration(t *testing.T) {
	base := UpdaterConfig{API: updaterAPI{}, Lists: []HashListInfo{{Name: "a", HashLength: 4}}}
	for _, change := range []func(*UpdaterConfig){
		func(c *UpdaterConfig) { c.API = nil },
		func(c *UpdaterConfig) { c.Lists = nil },
		func(c *UpdaterConfig) {
			c.Lists = []HashListInfo{{Name: "a", HashLength: 4}, {Name: "a", HashLength: 4}}
		},
		func(c *UpdaterConfig) { c.Lists = []HashListInfo{{Name: "a", HashLength: 5}} },
		func(c *UpdaterConfig) { c.RequestTimeout = -1 },
		func(c *UpdaterConfig) { c.MaxSnapshotBytes = -1 },
		func(c *UpdaterConfig) { c.RetryInitial = time.Hour; c.RetryMax = time.Second },
		func(c *UpdaterConfig) { c.RetryInitial = -1 },
		func(c *UpdaterConfig) { c.SizeConstraints.MaxUpdateEntries = 1 },
	} {
		c := base
		change(&c)
		if _, err := NewListUpdater(c); err == nil {
			t.Fatal("accepted invalid config", c)
		}
	}
	base.Lists[0].Metadata.ThreatTypes = []string{"MALWARE"}
	u, err := NewListUpdater(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Lists[0].Name = "changed"
	base.Lists[0].Metadata.ThreatTypes[0] = "changed"
	if u.config.Lists[0].Name != "a" || u.config.Lists[0].Metadata.ThreatTypes[0] != "MALWARE" {
		t.Fatal("config alias")
	}
	for i := 0; i < 100; i++ {
		d := u.retryDelay(1)
		if d < time.Second/2 || d > time.Second {
			t.Fatal("jitter out of bounds", d)
		}
	}
}

type blockedUpdaterStore struct {
	memoryStore
	started chan struct{}
}

func (s *blockedUpdaterStore) Save(ctx context.Context, r io.Reader) error {
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

func TestUpdaterCancellationDuringSave(t *testing.T) {
	store := &blockedUpdaterStore{started: make(chan struct{})}
	api := updaterAPI{batch: func(_ context.Context, r []HashListRequest, _ SizeConstraints) ([]DatabaseUpdate, error) {
		return []DatabaseUpdate{fullForRequest(t, r[0], "v1", time.Hour)}, nil
	}}
	u, _ := testUpdater(t, api, store, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	<-store.started
	if !u.Status().Ready {
		t.Fatal("blocked storage blocked readiness")
	}
	if _, err := u.Lookup(Hash{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s := u.Status(); !s.Dirty || s.PersistenceError != nil {
		t.Fatal("canceled save state", s)
	}
}

func TestSnapshotReadFailureIsNotCorruption(t *testing.T) {
	failure := errors.New("backend read failed")
	_, err := decodeDatabase(context.Background(), io.MultiReader(bytes.NewBufferString(`{"format":`), failingReader{failure}), 1024)
	if !errors.Is(err, failure) || errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("read error was classified as corruption", err)
	}
	_, err = decodeDatabase(context.Background(), bytes.NewBufferString(`{"format":"gosafe5","version":1,"lists":[{"updated_at":"bad time"}]}`), 1024)
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("bad time not classified as corruption", err)
	}
}

func TestListResponseErrorScope(t *testing.T) {
	a := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Empty protobuf HashList lacks the requested name/version.
		w.Header().Set("Content-Type", "application/x-protobuf")
	})
	_, err := a.GetHashList(context.Background(), HashListRequest{Name: "a", HashLength: 4}, SizeConstraints{})
	var scoped *ListResponseError
	if !errors.As(err, &scoped) || scoped.Name != "a" || !errors.Is(err, ErrInvalidAPIResponse) {
		t.Fatal("lost response scope", err)
	}
}
