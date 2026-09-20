package gosafe5

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// SnapshotStore stores one complete database snapshot. A filesystem path or an
// S3 bucket/key can identify the snapshot; list names are never storage paths.
// Load must return a reader owned by the caller, or an error wrapping
// fs.ErrNotExist if absent. Save must consume the reader before returning and
// publish the complete object atomically: readers see the old or new snapshot,
// never a partial write. A failed read must not publish a partial snapshot.
// Implementations should honor cancellation. Errors after publication may mean
// the new snapshot is already visible (for example, a directory sync failure).
// Shared destinations require caller coordination: this interface provides no
// cross-process locking or compare-and-swap. Implementations must support calls
// concurrent with Load; distinct writers otherwise have last-writer-wins semantics.
type SnapshotStore interface {
	Load(context.Context) (io.ReadCloser, error)
	Save(context.Context, io.Reader) error
}

// ErrInvalidSnapshot identifies an unsupported, malformed, or corrupt snapshot.
var ErrInvalidSnapshot = errors.New("gosafe5: invalid database snapshot")

// ErrSnapshotTooLarge means loading exceeded the caller's encoded byte limit.
var ErrSnapshotTooLarge = errors.New("gosafe5: snapshot exceeds size limit")

type persistedSnapshot struct {
	Format  string          `json:"format"`
	Version int             `json:"version"`
	Lists   []persistedList `json:"lists"`
}

type persistedList struct {
	Name                string        `json:"name"`
	Width               HashLength    `json:"width"`
	Hashes              []byte        `json:"hashes"`
	Version             []byte        `json:"version"`
	Checksum            []byte        `json:"checksum"`
	MinimumWaitDuration time.Duration `json:"minimum_wait_duration_ns"`
	UpdatedAt           time.Time     `json:"updated_at"`
	Metadata            *ListMetadata `json:"metadata,omitempty"`
}

// Save writes a consistent point-in-time snapshot. Apply may continue while
// storage I/O runs. Concurrent saves on this database are serialized so an older
// snapshot cannot finish after a newer one. Later updates require another Save.
// A storage failure leaves the in-memory database unchanged.
func (db *LocalDatabase) Save(ctx context.Context, store SnapshotStore) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.saveMu.Lock()
	defer db.saveMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	states := db.Lists()
	snapshot := persistedSnapshot{Format: "gosafe5", Version: 1, Lists: make([]persistedList, 0, len(states))}
	for _, s := range states {
		snapshot.Lists = append(snapshot.Lists, persistedList{
			Name:                s.Name,
			Width:               s.Hashes.HashLength(),
			Hashes:              s.Hashes.data,
			Version:             s.Version,
			Checksum:            s.Checksum[:],
			MinimumWaitDuration: s.MinimumWaitDuration,
			UpdatedAt:           s.UpdatedAt,
			Metadata:            s.Metadata,
		})
	}
	// A pipe allows backends to stream the encoding without an additional full
	// encoded buffer. Always close and join the producer, even on backend failure.
	r, w := io.Pipe()
	encoded := make(chan error, 1)
	go func() {
		err := json.NewEncoder(w).Encode(snapshot)
		w.CloseWithError(err)
		encoded <- err
	}()
	err := store.Save(ctx, contextReader{ctx, r})
	r.CloseWithError(io.ErrClosedPipe)
	encodeErr := <-encoded
	if err != nil {
		return err
	}
	return encodeErr
}

// LoadDatabase opens and fully validates a snapshot before returning a new
// database. maxBytes must be positive and limits encoded input size; decoded
// structures and validation require additional memory. All hash lists and their
// checksums are verified. No expiry policy is applied, and monotonic clock data
// cannot survive persistence. Missing storage is returned as fs.ErrNotExist.
func LoadDatabase(ctx context.Context, store SnapshotStore, maxBytes int64) (*LocalDatabase, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: maxBytes must be positive", ErrSnapshotTooLarge)
	}
	r, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	db, decodeErr := decodeDatabase(ctx, r, maxBytes)
	closeErr := r.Close()
	if decodeErr != nil {
		return nil, decodeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return db, nil
}

func decodeDatabase(ctx context.Context, r io.Reader, maxBytes int64) (*LocalDatabase, error) {
	limited := &io.LimitedReader{R: contextReader{ctx, r}, N: maxBytes}
	dec := json.NewDecoder(limited)
	var snapshot persistedSnapshot
	if err := dec.Decode(&snapshot); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if limited.N == 0 {
			return nil, ErrSnapshotTooLarge
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	}
	// Require exactly one document; include trailing whitespace in the limit.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("%w: trailing data: %w", ErrInvalidSnapshot, err)
		}
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidSnapshot)
	}
	if limited.N == 0 {
		var probe [1]byte
		n, err := contextReader{ctx, r}.Read(probe[:])
		if n != 0 {
			return nil, ErrSnapshotTooLarge
		}
		if err != io.EOF {
			if err == nil {
				err = io.ErrNoProgress
			}
			return nil, err
		}
	}
	if snapshot.Format != "gosafe5" || snapshot.Version != 1 || snapshot.Lists == nil {
		return nil, fmt.Errorf("%w: unsupported format or missing lists", ErrInvalidSnapshot)
	}
	db := &LocalDatabase{}
	for _, l := range snapshot.Lists {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, exists := db.lists[l.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate name", ErrInvalidSnapshot)
		}
		if len(l.Checksum) != len(ListChecksum{}) {
			return nil, fmt.Errorf("%w: checksum length", ErrInvalidSnapshot)
		}
		hashes, err := NewHashList(l.Width, l.Hashes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
		}
		sum := ListChecksum(l.Checksum)
		err = db.Apply(DatabaseUpdate{Name: l.Name, Version: l.Version,
			MinimumWaitDuration: l.MinimumWaitDuration, Metadata: l.Metadata,
			Update: ListUpdate{Additions: hashes, ExpectedChecksum: &sum}}, l.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return db, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
