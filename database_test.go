package gosafe5

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func databaseFull(t testing.TB, name, version string, values ...uint32) DatabaseUpdate {
	t.Helper()
	l := list32(t, values...)
	return DatabaseUpdate{Name: name, Version: []byte(version),
		Update: ListUpdate{Additions: l, ExpectedChecksum: checksum(t, l)}}
}

func TestLocalDatabaseLifecycle(t *testing.T) {
	var db LocalDatabase
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if _, ok := db.Get("mw-4b"); ok || len(db.Lists()) != 0 || len(db.DueLists(now)) != 0 || len(db.Lookup(Hash{})) != 0 {
		t.Fatal("nonempty zero database")
	}
	u := databaseFull(t, "mw-4b", "\x00\xffv1", 1, 3)
	u.MinimumWaitDuration = 3500 * time.Millisecond
	u.Metadata = &ListMetadata{Description: "Malware", ThreatTypes: []string{"MALWARE"}}
	if err := db.Apply(u, now); err != nil {
		t.Fatal(err)
	}
	s, ok := db.Get("mw-4b")
	if !ok || s.Name != u.Name || !bytes.Equal(s.Version, u.Version) || s.Checksum != *u.Update.ExpectedChecksum || s.UpdatedAt != now || s.MinimumWaitDuration != u.MinimumWaitDuration {
		t.Fatalf("response fields lost: %+v", s)
	}
	if s.Due(now) || s.NextUpdate() != now.Add(3500*time.Millisecond) || !s.Due(s.NextUpdate()) {
		t.Fatal("scheduling boundary")
	}
	if len(db.DueLists(s.NextUpdate().Add(-time.Nanosecond))) != 0 || len(db.DueLists(s.NextUpdate())) != 1 {
		t.Fatal("due lists")
	}

	want := list32(t, 2, 3)
	delta := DatabaseUpdate{Name: u.Name, BaseVersion: bytes.Clone(u.Version), Version: []byte("v2"),
		Update: ListUpdate{true, []uint32{0}, list32(t, 2), checksum(t, want)}}
	if err := db.Apply(delta, s.NextUpdate()); err != nil {
		t.Fatal(err)
	}
	updated, _ := db.Get(u.Name)
	if !bytes.Equal(updated.Hashes.Bytes(), want.Bytes()) || updated.Metadata.Description != "Malware" || !updated.Due(updated.UpdatedAt) {
		t.Fatal("partial update or zero wait", updated)
	}
	if !bytes.Equal(s.Hashes.Bytes(), packed32(1, 3)) {
		t.Fatal("old snapshot changed")
	}

	// A no-change response can advance version and scheduling without checksum.
	noop := DatabaseUpdate{Name: u.Name, BaseVersion: []byte("v2"), Version: []byte("v3"), MinimumWaitDuration: time.Minute,
		Update: ListUpdate{Partial: true, Additions: list32(t)}}
	if err := db.Apply(noop, updated.UpdatedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := db.Get(u.Name)
	if unchanged.Checksum != updated.Checksum || !bytes.Equal(unchanged.Hashes.Bytes(), updated.Hashes.Bytes()) || string(unchanged.Version) != "v3" {
		t.Fatal("no-change response")
	}

	// A server full reset replaces rather than merges with the old list.
	full := databaseFull(t, u.Name, "v4")
	full.BaseVersion = []byte("v3")
	if err := db.Apply(full, unchanged.UpdatedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	reset, _ := db.Get(u.Name)
	if reset.Hashes.Len() != 0 || reset.Checksum != *full.Update.ExpectedChecksum {
		t.Fatal("full reset")
	}
}

func TestDatabaseOwnsSnapshots(t *testing.T) {
	var db LocalDatabase
	now := time.Now()
	u := databaseFull(t, "se-4b", "v1", 1)
	u.Metadata = &ListMetadata{Description: "SE", ThreatTypes: []string{"SOCIAL_ENGINEERING"}}
	if err := db.Apply(u, now); err != nil {
		t.Fatal(err)
	}
	u.Version[0] = 'x'
	u.Metadata.Description = "changed"
	u.Metadata.ThreatTypes[0] = "changed"
	var hash Hash
	copy(hash[:], packed32(1))
	s, _ := db.Get(u.Name)
	for _, snapshot := range []ListState{s, db.Lists()[0], db.DueLists(now)[0], db.Lookup(hash)[0]} {
		snapshot.Version[0] = 'y'
		snapshot.Metadata.ThreatTypes[0] = "changed"
		snapshot.Metadata.Description = "changed"
	}
	actual, _ := db.Get(u.Name)
	if string(actual.Version) != "v1" || actual.Metadata.Description != "SE" || actual.Metadata.ThreatTypes[0] != "SOCIAL_ENGINEERING" {
		t.Fatal("mutable snapshot aliases state")
	}
}

func TestDatabaseRejectsUpdatesAtomically(t *testing.T) {
	var db LocalDatabase
	now := time.Now()
	if err := db.Apply(databaseFull(t, "mw-4b", "v1", 1), now); err != nil {
		t.Fatal(err)
	}
	before := db.Lists()
	for _, name := range []string{"empty name", "empty version", "negative wait", "zero time", "old time", "missing base", "wrong base", "width change", "checksum", "removal", "metadata"} {
		t.Run(name, func(t *testing.T) {
			u := databaseFull(t, "mw-4b", "v2", 2)
			u.BaseVersion = []byte("v1")
			received := now.Add(time.Second)
			wantErr := ErrInvalidUpdate
			switch name {
			case "empty name":
				u.Name = ""
			case "empty version":
				u.Version = nil
			case "negative wait":
				u.MinimumWaitDuration = -1
			case "zero time":
				received = time.Time{}
			case "old time":
				received = now.Add(-time.Second)
			case "missing base":
				u.BaseVersion = nil
				wantErr = ErrVersionMismatch
			case "wrong base":
				u.BaseVersion = []byte("wrong")
				wantErr = ErrVersionMismatch
			case "width change":
				u.Update.Additions, _ = NewHashList(8, nil)
			case "checksum":
				u.Update.ExpectedChecksum = &ListChecksum{}
				wantErr = ErrChecksumMismatch
			case "removal":
				u.Update.Partial = true
				u.Update.Removals = []uint32{1}
			case "metadata":
				u.Metadata = &ListMetadata{ThreatTypes: []string{"MALWARE"}, LikelySafeTypes: []string{"GENERAL_BROWSING"}}
			}
			if err := db.Apply(u, received); !errors.Is(err, wantErr) {
				t.Fatalf("got %v, want %v", err, wantErr)
			}
			if !reflect.DeepEqual(before, db.Lists()) {
				t.Fatal("failed update changed database")
			}
		})
	}
	u := databaseFull(t, "missing", "v1", 1)
	u.Update.Partial = true
	if err := db.Apply(u, now); !errors.Is(err, ErrInvalidUpdate) {
		t.Fatal("partial without base", err)
	}
	if len(db.Lists()) != 1 {
		t.Fatal("failed initial update inserted list")
	}
}

func TestDatabaseLookupAndOrdering(t *testing.T) {
	var db LocalDatabase
	now := time.Now()
	for _, name := range []string{"se-4b", "mw-4b"} {
		if err := db.Apply(databaseFull(t, name, "v1", 1), now); err != nil {
			t.Fatal(err)
		}
	}
	var hash Hash
	copy(hash[:], packed32(1))
	full, _ := NewHashList(32, hash[:])
	u := DatabaseUpdate{Name: "gc-32b", Version: []byte("v1"), Metadata: &ListMetadata{LikelySafeTypes: []string{"GENERAL_BROWSING"}},
		Update: ListUpdate{Additions: full, ExpectedChecksum: checksum(t, full)}}
	if err := db.Apply(u, now); err != nil {
		t.Fatal(err)
	}
	for _, lists := range [][]ListState{db.Lists(), db.DueLists(now), db.Lookup(hash)} {
		if len(lists) != 3 || lists[0].Name != "gc-32b" || lists[1].Name != "mw-4b" || lists[2].Name != "se-4b" {
			t.Fatal("ordering", lists)
		}
	}
	hash[31] = 1
	if len(db.Lookup(hash)) != 2 {
		t.Fatal("full hash vs prefix matching")
	}
	hash[0] = 1
	if len(db.Lookup(hash)) != 0 {
		t.Fatal("unexpected match")
	}
}

func TestDatabaseConcurrentUpdates(t *testing.T) {
	var db LocalDatabase
	now := time.Now()
	if err := db.Apply(databaseFull(t, "mw-4b", "v1", 1), now); err != nil {
		t.Fatal(err)
	}
	u := databaseFull(t, "mw-4b", "v2", 2)
	u.BaseVersion = []byte("v1")
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- db.Apply(u, now.Add(time.Second)) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			db.Get("mw-4b")
			db.Lists()
			db.DueLists(now)
			db.Lookup(Hash{})
		}
	}()
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrVersionMismatch) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}
