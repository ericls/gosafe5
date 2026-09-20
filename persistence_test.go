package gosafe5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *memoryStore) Load(ctx context.Context) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(s.data))), nil
}
func (s *memoryStore) Save(ctx context.Context, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = b
	return nil
}

func persistenceDatabase(t *testing.T) *LocalDatabase {
	t.Helper()
	db := &LocalDatabase{}
	now := time.Date(2026, 9, 20, 12, 34, 56, 123456789, time.UTC)
	for _, width := range []HashLength{4, 8, 16, 32} {
		l, err := NewHashList(width, make([]byte, int(width)))
		if err != nil {
			t.Fatal(err)
		}
		u := DatabaseUpdate{Name: string(rune('a' + width)), Version: []byte{0, 255, byte(width)},
			MinimumWaitDuration: 123456789 * time.Nanosecond,
			Metadata:            &ListMetadata{Description: "test", ThreatTypes: []string{"UNKNOWN_FUTURE_TYPE"}},
			Update:              ListUpdate{Additions: l, ExpectedChecksum: checksum(t, l)}}
		if err := db.Apply(u, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Apply(databaseFull(t, "empty", "v1"), now); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, store := range []SnapshotStore{&memoryStore{}, FileStore{Path: filepath.Join(t.TempDir(), "snapshot")}} {
		db := persistenceDatabase(t)
		if err := db.Save(ctx, store); err != nil {
			t.Fatal(err)
		}
		restored, err := LoadDatabase(ctx, store, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(db.Lists(), restored.Lists()) {
			t.Fatal("round trip changed state")
		}
		u := databaseFull(t, "empty", "v2", 1)
		u.BaseVersion = []byte("v1")
		u.Update.Partial = true
		if err := restored.Apply(u, time.Now()); err != nil {
			t.Fatal("cannot continue updates", err)
		}
		if err := restored.Save(ctx, store); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadDatabase(ctx, store, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if s, _ := loaded.Get("empty"); string(s.Version) != "v2" {
			t.Fatal("replacement not saved")
		}
		if err := (&LocalDatabase{}).Save(ctx, store); err != nil {
			t.Fatal(err)
		}
		empty, err := LoadDatabase(ctx, store, 1<<20)
		if err != nil || len(empty.Lists()) != 0 {
			t.Fatal("empty database", err)
		}
	}
}

func TestPersistenceValidation(t *testing.T) {
	ctx := context.Background()
	store := &memoryStore{}
	if err := persistenceDatabase(t).Save(ctx, store); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(store.data)
	for name, mutate := range map[string]func(*persistedSnapshot){
		"format":          func(s *persistedSnapshot) { s.Format = "other" },
		"version":         func(s *persistedSnapshot) { s.Version++ },
		"missing lists":   func(s *persistedSnapshot) { s.Lists = nil },
		"duplicate":       func(s *persistedSnapshot) { s.Lists = append(s.Lists, s.Lists[0]) },
		"hash corruption": func(s *persistedSnapshot) { s.Lists[0].Hashes[0] = 1 },
		"checksum length": func(s *persistedSnapshot) { s.Lists[0].Checksum = nil },
		"hash alignment":  func(s *persistedSnapshot) { s.Lists[0].Hashes = []byte{0} },
		"width":           func(s *persistedSnapshot) { s.Lists[0].Width = 3 },
		"name":            func(s *persistedSnapshot) { s.Lists[0].Name = "" },
		"list version":    func(s *persistedSnapshot) { s.Lists[0].Version = nil },
		"time":            func(s *persistedSnapshot) { s.Lists[0].UpdatedAt = time.Time{} },
		"wait":            func(s *persistedSnapshot) { s.Lists[0].MinimumWaitDuration = -1 },
		"metadata":        func(s *persistedSnapshot) { s.Lists[0].Metadata.LikelySafeTypes = []string{"GENERAL_BROWSING"} },
	} {
		t.Run(name, func(t *testing.T) {
			var s persistedSnapshot
			if err := json.Unmarshal(original, &s); err != nil {
				t.Fatal(err)
			}
			mutate(&s)
			store.data, _ = json.Marshal(s)
			loaded, err := LoadDatabase(ctx, store, 1<<20)
			if loaded != nil || !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v, %v", loaded, err)
			}
		})
	}
	for _, data := range [][]byte{original[:len(original)/2], append(bytes.Clone(original), []byte("{}")...), []byte("not JSON")} {
		store.data = data
		if _, err := LoadDatabase(ctx, store, 1<<20); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatal(err)
		}
	}
	store.data = original
	if _, err := LoadDatabase(ctx, store, int64(len(original))); err != nil {
		t.Fatal("exact limit", err)
	}
	for _, limit := range []int64{0, -1, 10, int64(len(original) - 2)} {
		if _, err := LoadDatabase(ctx, store, limit); !errors.Is(err, ErrSnapshotTooLarge) {
			t.Fatalf("limit %d: %v", limit, err)
		}
	}
	store.data = append(bytes.Clone(original), bytes.Repeat([]byte(" "), 20)...)
	if _, err := LoadDatabase(ctx, store, int64(len(original))); !errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatal("trailing whitespace limit", err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestFileStoreFailureAndCancellation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := FileStore{Path: filepath.Join(dir, "snapshot")}
	if _, err := LoadDatabase(ctx, store, 100); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := store.Save(ctx, bytes.NewBufferString("original")); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("source failed")
	if err := store.Save(ctx, io.MultiReader(bytes.NewBufferString("partial"), failingReader{failure})); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Save(canceled, bytes.NewBufferString("bad")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := store.Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path)
	if err != nil || string(data) != "original" {
		t.Fatal("old file lost", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary file leaked", err)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("permissions", err)
	}
	if err := store.Save(ctx, bytes.NewBufferString("new")); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(store.Path)
	if string(data) != "new" {
		t.Fatal("replacement failed")
	}
}

type errorStore struct{ err error }

func (s errorStore) Load(context.Context) (io.ReadCloser, error) { return nil, s.err }
func (s errorStore) Save(context.Context, io.Reader) error       { return s.err }

func TestPersistenceErrors(t *testing.T) {
	db := persistenceDatabase(t)
	before := db.Lists()
	failure := errors.New("backend unavailable")
	store := errorStore{failure}
	if err := db.Save(context.Background(), store); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := LoadDatabase(context.Background(), store, 100); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := db.Save(ctx, store); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := LoadDatabase(ctx, store, 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, db.Lists()) {
		t.Fatal("storage error modified database")
	}
}

type trackedReader struct {
	io.Reader
	closed   bool
	closeErr error
}

func (r *trackedReader) Close() error { r.closed = true; return r.closeErr }

type readStore struct {
	errorStore
	reader io.ReadCloser
}

func (s readStore) Load(context.Context) (io.ReadCloser, error) { return s.reader, nil }

func TestLoadClosesReaders(t *testing.T) {
	for _, data := range []string{`{"format":"gosafe5","version":1,"lists":[]}`, `broken`} {
		closeErr := errors.New("close failed")
		r := &trackedReader{Reader: bytes.NewBufferString(data), closeErr: closeErr}
		db, err := LoadDatabase(context.Background(), readStore{reader: r}, 1024)
		if !r.closed || db != nil || err == nil {
			t.Fatal("reader lifecycle", err)
		}
		if data != "broken" && !errors.Is(err, closeErr) {
			t.Fatal("close error lost", err)
		}
	}
}

func TestEncodingFailurePreservesFile(t *testing.T) {
	ctx := context.Background()
	store := FileStore{Path: filepath.Join(t.TempDir(), "snapshot")}
	db := persistenceDatabase(t)
	if err := db.Save(ctx, store); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	// time.Time accepts years outside JSON's representable range.
	u := databaseFull(t, "unencodable", "v1")
	if err := db.Apply(u, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(ctx, store); err == nil {
		t.Fatal("encoding unexpectedly succeeded")
	}
	after, err := os.ReadFile(store.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("encoding failure replaced snapshot", err)
	}
}

type blockingStore struct {
	memoryStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingStore) Save(ctx context.Context, r io.Reader) error {
	s.once.Do(func() { close(s.started); <-s.release })
	return s.memoryStore.Save(ctx, r)
}

func TestSaveConcurrentWithUpdates(t *testing.T) {
	db := persistenceDatabase(t)
	store := &blockingStore{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 2)
	go func() { done <- db.Save(context.Background(), store) }()
	<-store.started
	u := databaseFull(t, "empty", "v2", 1)
	u.BaseVersion = []byte("v1")
	if err := db.Apply(u, time.Now()); err != nil {
		t.Fatal(err)
	}
	go func() { done <- db.Save(context.Background(), store) }()
	close(store.release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	restored, err := LoadDatabase(context.Background(), store, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := restored.Get("empty"); string(s.Version) != "v2" {
		t.Fatal("older save overwrote newer snapshot")
	}
}
