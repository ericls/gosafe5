package gosafe5

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrVersionMismatch means an update was requested against a different local
// version. The caller must fetch again using the current version.
var ErrVersionMismatch = errors.New("gosafe5: database version mismatch")

// ListMetadata describes a named list. Enum names are retained as strings so
// unrecognized server values can be preserved without assigning them meaning.
// Hash width is available from ListState.Hashes.HashLength().
type ListMetadata struct {
	Description     string
	ThreatTypes     []string
	LikelySafeTypes []string
}

// ListState is a snapshot of a successfully verified named list. Version and
// metadata slices are owned by the snapshot; changing them cannot alter the
// database. Hashes shares immutable storage with the database.
type ListState struct {
	Name                string
	Hashes              HashList
	Version             []byte
	Checksum            ListChecksum
	MinimumWaitDuration time.Duration
	UpdatedAt           time.Time
	Metadata            *ListMetadata
}

// NextUpdate is the earliest next fetch time indicated by the last response.
// This is a scheduling constraint, not a freshness or expiration guarantee.
func (s ListState) NextUpdate() time.Time {
	return s.UpdatedAt.Add(s.MinimumWaitDuration)
}

// Due reports whether a fetch may start at now. Zero wait is immediately due.
func (s ListState) Due(now time.Time) bool { return !now.Before(s.NextUpdate()) }

// DatabaseUpdate associates a decoded list update with its response fields.
// BaseVersion is the opaque version sent in the request, including for a full
// replacement. An empty BaseVersion requires that the list not yet exist.
// Version is the new opaque version; it must be nonempty and is never parsed.
// Nil Metadata preserves existing metadata, since content responses may omit it.
// Update.Additions must have an explicit width, even when empty.
// Do not mutate the input slices or pointers while Apply is running.
type DatabaseUpdate struct {
	Name                string
	BaseVersion         []byte
	Version             []byte
	MinimumWaitDuration time.Duration
	Metadata            *ListMetadata
	Update              ListUpdate
}

// LocalDatabase holds named hash lists in memory. Its zero value is ready for
// use. Methods are safe for concurrent calls; do not copy it after first use.
// It performs no fetching, persistence, retries, or automatic expiry. Callers
// select lists and decide whether stored data is suitable for live lookups.
type LocalDatabase struct {
	mu    sync.RWMutex
	lists map[string]ListState
}

// Get returns a detached snapshot, or false when name has not been loaded.
func (db *LocalDatabase) Get(name string) (ListState, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	s, ok := db.lists[name]
	return cloneListState(s), ok
}

// Lists returns detached snapshots ordered by name.
func (db *LocalDatabase) Lists() []ListState {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]ListState, 0, len(db.lists))
	for _, s := range db.lists {
		result = append(result, cloneListState(s))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// DueLists returns loaded lists eligible for a fetch at now, ordered by name.
// Lists that have never been loaded must be scheduled by the caller.
func (db *LocalDatabase) DueLists(now time.Time) []ListState {
	lists := db.Lists()
	due := lists[:0]
	for _, s := range lists {
		if s.Due(now) {
			due = append(due, s)
		}
	}
	return due
}

// Lookup returns snapshots of lists containing a prefix of hash, ordered by
// name. These are membership matches, not threat verdicts or freshness checks;
// both threat lists and likely-safe lists may be present in the database.
func (db *LocalDatabase) Lookup(hash Hash) []ListState {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []ListState
	for _, s := range db.lists {
		if s.Hashes.Matches(hash) {
			result = append(result, cloneListState(s))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// Apply atomically publishes a verified list and its response fields. receivedAt
// is when the response was received, supplied by the caller to avoid a hidden
// clock. A zero timestamp or negative wait duration is rejected.
// The expected base version is checked for both full and partial updates.
// On any error all stored fields remain unchanged. The synchronization layer
// must handle invalidation/refetch after corruption or server-directed resets;
// retaining the old snapshot does not imply it remains valid for live lookups.
func (db *LocalDatabase) Apply(u DatabaseUpdate, receivedAt time.Time) error {
	bad := func(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidUpdate, reason) }
	if u.Name == "" {
		return bad("empty list name")
	}
	if len(u.Version) == 0 {
		return bad("empty list version")
	}
	if receivedAt.IsZero() {
		return bad("missing response time")
	}
	if u.MinimumWaitDuration < 0 {
		return bad("negative minimum wait duration")
	}
	if u.Metadata != nil && len(u.Metadata.ThreatTypes) != 0 && len(u.Metadata.LikelySafeTypes) != 0 {
		return bad("metadata specifies both threat and likely-safe types")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	previous, exists := db.lists[u.Name]
	if !bytes.Equal(previous.Version, u.BaseVersion) {
		return fmt.Errorf("%w: %s", ErrVersionMismatch, u.Name)
	}
	var base *HashList
	if exists {
		base = &previous.Hashes
		if u.Update.Additions.HashLength() != base.HashLength() {
			return bad("list width changed")
		}
		if receivedAt.Before(previous.UpdatedAt) {
			return bad("response predates stored state")
		}
	}
	hashes, err := ApplyUpdate(base, u.Update)
	if err != nil {
		return fmt.Errorf("list %q: %w", u.Name, err)
	}
	// ApplyUpdate verified this checksum, or retained a previously verified
	// unchanged base when the response omitted it.
	sum := previous.Checksum
	if u.Update.ExpectedChecksum != nil {
		sum = *u.Update.ExpectedChecksum
	}
	metadata := previous.Metadata
	if u.Metadata != nil {
		metadata = cloneListMetadata(u.Metadata)
	}
	s := ListState{
		Name: u.Name, Hashes: hashes, Version: bytes.Clone(u.Version),
		Checksum: sum, MinimumWaitDuration: u.MinimumWaitDuration,
		UpdatedAt: receivedAt, Metadata: metadata,
	}
	if db.lists == nil {
		db.lists = make(map[string]ListState)
	}
	db.lists[u.Name] = s
	return nil
}

func cloneListMetadata(m *ListMetadata) *ListMetadata {
	if m == nil {
		return nil
	}
	return &ListMetadata{Description: m.Description,
		ThreatTypes:     append([]string(nil), m.ThreatTypes...),
		LikelySafeTypes: append([]string(nil), m.LikelySafeTypes...)}
}

func cloneListState(s ListState) ListState {
	s.Version = bytes.Clone(s.Version)
	s.Metadata = cloneListMetadata(s.Metadata)
	return s
}
