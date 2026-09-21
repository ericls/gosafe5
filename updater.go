package gosafe5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrUpdaterRunning = errors.New("gosafe5: updater already running")
	ErrNotReady       = errors.New("gosafe5: configured lists are not ready")
)

// UpdaterConfig selects lists and services. Construction performs no I/O.
// Lists is copied. API and Store must honor context cancellation. One updater
// must exclusively own its snapshot destination; no cross-process lock is taken.
type UpdaterConfig struct {
	API              API
	Lists            []HashListInfo
	Store            SnapshotStore
	SizeConstraints  SizeConstraints
	MaxSnapshotBytes int64         // Default 256 MiB.
	RequestTimeout   time.Duration // Default 30 seconds, also used for store I/O.
	RetryInitial     time.Duration // Default 1 second.
	RetryMax         time.Duration // Default 15 minutes.
	Logger           *slog.Logger  // Defaults to slog.Default().
}

type ListUpdateStatus struct {
	Name                string
	Available           bool
	LastAttempt         time.Time
	LastSuccess         time.Time
	LastError           error
	ConsecutiveFailures uint
	NextAttempt         time.Time
}

// UpdaterStatus separates availability from freshness and persistence health.
// Ready means every selected list has a verified snapshot, including empty
// lists. It does not mean the snapshots are fresh or that a URL is safe.
type UpdaterStatus struct {
	Running          bool
	Initialized      bool
	Ready            bool
	Lists            []ListUpdateStatus
	LoadError        error // Last initialization error, including a recovered corruption.
	PersistenceError error
	LastSave         time.Time
	NextSave         time.Time
	Dirty            bool // Unsaved state; always false when no store is configured.
}

// ListUpdater owns a database and serializes Run/Update operations. Reads are
// concurrent and do not wait for network or storage I/O. Use NewListUpdater;
// the zero value is not usable. Do not copy an updater after construction.
type ListUpdater struct {
	mu           sync.RWMutex
	config       UpdaterConfig
	db           *LocalDatabase
	status       UpdaterStatus
	busy         bool
	saveFailures uint
	clock        updaterClock
	jitter       func(time.Duration) time.Duration
	logger       *slog.Logger
}

type updaterClock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

type timeUpdaterClock struct{}

func (timeUpdaterClock) Now() time.Time { return time.Now() }
func (timeUpdaterClock) Wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func NewListUpdater(c UpdaterConfig) (*ListUpdater, error) {
	if c.API == nil || len(c.Lists) == 0 {
		return nil, fmt.Errorf("%w: API and lists are required", ErrInvalidAPIRequest)
	}
	if _, err := constraintQuery(c.SizeConstraints); err != nil {
		return nil, err
	}
	if c.MaxSnapshotBytes == 0 {
		c.MaxSnapshotBytes = 256 << 20
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 30 * time.Second
	}
	if c.RetryInitial == 0 {
		c.RetryInitial = time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = 15 * time.Minute
	}
	if c.MaxSnapshotBytes < 0 || c.RequestTimeout < 0 || c.RetryInitial < 0 || c.RetryMax < c.RetryInitial {
		return nil, fmt.Errorf("%w: updater limits", ErrInvalidAPIRequest)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	selected := make([]HashListInfo, len(c.Lists))
	names := map[string]bool{}
	for i, l := range c.Lists {
		if err := validListRequest(HashListRequest{Name: l.Name, HashLength: l.HashLength}); err != nil {
			return nil, err
		}
		if names[l.Name] || len(l.Metadata.ThreatTypes) > 0 && len(l.Metadata.LikelySafeTypes) > 0 {
			return nil, fmt.Errorf("%w: duplicate list or conflicting metadata", ErrInvalidAPIRequest)
		}
		names[l.Name] = true
		selected[i] = l
		selected[i].Metadata = *cloneListMetadata(&l.Metadata)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })
	c.Lists = selected
	u := &ListUpdater{config: c, db: &LocalDatabase{}, clock: timeUpdaterClock{},
		jitter: func(d time.Duration) time.Duration {
			half := d / 2
			return half + time.Duration(rand.Int64N(int64(d-half)+1))
		}, logger: c.Logger.With("component", "gosafe5.updater")}
	for _, l := range selected {
		u.status.Lists = append(u.status.Lists, ListUpdateStatus{Name: l.Name})
	}
	return u, nil
}

func (u *ListUpdater) Get(name string) (ListState, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.db.Get(name)
}

func (u *ListUpdater) Lists() []ListState {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.db.Lists()
}

func (u *ListUpdater) Lookup(hash Hash) ([]ListState, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if !u.readyLocked() {
		return nil, ErrNotReady
	}
	return u.db.Lookup(hash), nil
}

func (u *ListUpdater) readyLocked() bool {
	if !u.status.Initialized {
		return false
	}
	for _, s := range u.status.Lists {
		if !s.Available {
			return false
		}
	}
	return true
}

func (u *ListUpdater) Status() UpdaterStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	s := u.status
	s.Ready = u.readyLocked()
	s.Lists = append([]ListUpdateStatus(nil), s.Lists...)
	return s
}

func (u *ListUpdater) enter(running bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.busy {
		return ErrUpdaterRunning
	}
	u.busy = true
	u.status.Running = running
	return nil
}

func (u *ListUpdater) leave() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.busy = false
	u.status.Running = false
}

// Update initializes if needed and performs one due-list/persistence cycle.
// It never bypasses server or retry deadlines. Service errors are returned and
// recorded for the next call; independent successful list updates are retained.
func (u *ListUpdater) Update(ctx context.Context) error {
	if err := u.enter(false); err != nil {
		return err
	}
	defer u.leave()
	if err := u.initialize(ctx); err != nil {
		return err
	}
	return u.cycle(ctx)
}

// Run initializes, then keeps lists updated until cancellation. Initialization
// failures are returned; subsequent service/storage failures are retried and
// exposed through Status. Cancellation does not initiate a final save. Run may
// be called again after it returns; successfully initialized state is retained.
func (u *ListUpdater) Run(ctx context.Context) error {
	if err := u.enter(true); err != nil {
		return err
	}
	defer u.leave()
	u.logger.Info("updater starting")
	if err := u.initialize(ctx); err != nil {
		u.logger.Error("updater initialization failed", "error", err)
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			u.logger.Info("updater stopping", "error", err)
			return err
		}
		u.cycle(ctx)
		if err := ctx.Err(); err != nil {
			u.logger.Info("updater stopping", "error", err)
			return err
		}
		delay := u.nextDelay()
		u.logger.Debug("updater sleeping", "delay", delay)
		if err := u.clock.Wait(ctx, delay); err != nil {
			u.logger.Info("updater stopping", "error", err)
			return err
		}
	}
}

func (u *ListUpdater) initialize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u.mu.RLock()
	initialized := u.status.Initialized
	u.mu.RUnlock()
	if initialized {
		return nil
	}
	db := &LocalDatabase{}
	var loadErr error
	dirty := false
	if u.config.Store != nil {
		u.logger.Debug("loading snapshot")
		loadCtx, cancel := context.WithTimeout(ctx, u.config.RequestTimeout)
		loaded, err := LoadDatabase(loadCtx, u.config.Store, u.config.MaxSnapshotBytes)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			loadErr = err
			if !errors.Is(err, ErrInvalidSnapshot) || errors.Is(err, ErrUnsupportedSnapshot) || errors.Is(err, ErrSnapshotTooLarge) {
				u.logger.Error("snapshot load failed", "error", err)
				u.mu.Lock()
				u.status.LoadError = err
				u.mu.Unlock()
				return err
			}
			u.logger.Warn("snapshot invalid, discarding", "error", err)
			dirty = true
		} else if err == nil {
			u.logger.Debug("snapshot loaded", "lists", len(loaded.lists))
			db = loaded
		} else {
			u.logger.Debug("no snapshot found")
		}
	}
	// The loaded database is still private here. Keep only selected lists and
	// their expected widths, and populate missing metadata from configuration.
	selected := map[string]HashListInfo{}
	for _, l := range u.config.Lists {
		selected[l.Name] = l
	}
	for name, s := range db.lists {
		l, ok := selected[name]
		if !ok || s.Hashes.HashLength() != l.HashLength {
			delete(db.lists, name)
			dirty = true
			continue
		}
		if s.Metadata == nil {
			s.Metadata = cloneListMetadata(&l.Metadata)
			db.lists[name] = s
			dirty = true
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.db = db
	u.status.Initialized = true
	u.status.LoadError = loadErr
	u.status.Dirty = dirty && u.config.Store != nil
	for i := range u.status.Lists {
		if s, ok := db.Get(u.status.Lists[i].Name); ok {
			u.status.Lists[i].Available = true
			u.status.Lists[i].LastSuccess = s.UpdatedAt
			u.status.Lists[i].NextAttempt = s.NextUpdate()
		}
	}
	u.logger.Info("updater initialized", "ready", u.readyLocked())
	return nil
}

func (u *ListUpdater) cycle(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := u.clock.Now()
	var requests []HashListRequest
	var indices []int
	u.mu.Lock()
	for i, s := range u.status.Lists {
		if now.Before(s.NextAttempt) {
			continue
		}
		l := u.config.Lists[i]
		state, _ := u.db.Get(l.Name)
		requests = append(requests, HashListRequest{Name: l.Name, Version: state.Version, HashLength: l.HashLength})
		indices = append(indices, i)
		u.status.Lists[i].LastAttempt = now
	}
	u.mu.Unlock()
	var cycleErr error
	if len(requests) != 0 {
		u.logger.Debug("fetching lists", "count", len(requests))
		callCtx, cancel := context.WithTimeout(ctx, u.config.RequestTimeout)
		updates, err := u.config.API.BatchGetHashLists(callCtx, requests, u.config.SizeConstraints)
		receivedAt := u.clock.Now()
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		u.mu.Lock()
		if err == nil {
			err = validateUpdateBatch(requests, updates)
		}
		if err != nil {
			u.logger.Debug("fetch cycle failed", "count", len(requests), "error", err)
			var scoped *ListResponseError
			scopedKnown := errors.As(err, &scoped)
			if scopedKnown {
				scopedKnown = false
				for _, r := range requests {
					if r.Name == scoped.Name {
						scopedKnown = true
					}
				}
			}
			invalid := errors.Is(err, ErrInvalidAPIResponse) || errors.Is(err, ErrInvalidUpdate) || errors.Is(err, ErrChecksumMismatch)
			for _, i := range indices {
				u.failLocked(i, err, receivedAt, invalid && (!scopedKnown || scoped.Name == u.status.Lists[i].Name))
			}
			cycleErr = err
		} else {
			u.logger.Debug("fetch cycle complete", "count", len(requests))
			for j, i := range indices {
				update := updates[j]
				if update.Metadata == nil {
					old, _ := u.db.Get(update.Name)
					if old.Metadata == nil {
						update.Metadata = cloneListMetadata(&u.config.Lists[i].Metadata)
					}
				}
				// Even an invalid update cannot make the scheduler fetch before
				// a valid server wait duration supplied in that response.
				if update.MinimumWaitDuration >= 0 {
					u.status.Lists[i].NextAttempt = receivedAt.Add(update.MinimumWaitDuration)
				}
				var applyErr error
				if !bytes.Equal(update.BaseVersion, requests[j].Version) {
					applyErr = ErrVersionMismatch
				} else if update.Update.Additions.HashLength() != requests[j].HashLength {
					applyErr = fmt.Errorf("%w: configured width mismatch", ErrInvalidUpdate)
				} else {
					applyErr = u.db.Apply(update, receivedAt)
				}
				if err := applyErr; err != nil {
					u.failLocked(i, err, receivedAt, true)
					cycleErr = errors.Join(cycleErr, fmt.Errorf("list %q: %w", update.Name, err))
					continue
				}
				s := &u.status.Lists[i]
				s.Available = true
				s.LastSuccess = receivedAt
				s.LastError = nil
				s.ConsecutiveFailures = 0
				u.markDirtyLocked()
				u.logger.Debug("list updated", "list", s.Name)
			}
		}
		u.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(cycleErr, u.save(ctx))
}

func validateUpdateBatch(requests []HashListRequest, updates []DatabaseUpdate) error {
	if len(updates) != len(requests) {
		return fmt.Errorf("%w: batch count", ErrInvalidAPIResponse)
	}
	for i, r := range requests {
		if updates[i].Name != r.Name {
			return fmt.Errorf("%w: batch names or order", ErrInvalidAPIResponse)
		}
	}
	return nil
}

func (u *ListUpdater) markDirtyLocked() {
	if u.config.Store != nil {
		u.status.Dirty = true
	}
}

func (u *ListUpdater) failLocked(i int, err error, now time.Time, invalidate bool) {
	s := &u.status.Lists[i]
	if invalidate {
		if old, ok := u.db.Get(s.Name); ok {
			u.db.Invalidate(s.Name, old.Version)
			u.markDirtyLocked()
		}
		s.Available = false
	}
	s.LastError = err
	s.ConsecutiveFailures++
	next := now.Add(u.retryDelay(s.ConsecutiveFailures))
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if retry := retryAfter(httpErr.RetryAfter, now); retry.After(next) {
			next = retry
		}
	}
	if next.After(s.NextAttempt) {
		s.NextAttempt = next
	}
	u.logger.Warn("list update failed", "list", s.Name, "error", err,
		"consecutiveFailures", s.ConsecutiveFailures, "nextAttempt", s.NextAttempt, "invalidated", invalidate)
}

func (u *ListUpdater) retryDelay(failures uint) time.Duration {
	delay := u.config.RetryInitial
	for n := uint(1); n < failures && delay < u.config.RetryMax; n++ {
		if delay > u.config.RetryMax/2 {
			delay = u.config.RetryMax
		} else {
			delay *= 2
		}
	}
	return u.jitter(delay)
}

func retryAfter(value string, now time.Time) time.Time {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 63); err == nil {
		const maxSeconds = uint64((1<<63 - 1) / int64(time.Second))
		if seconds > maxSeconds {
			seconds = maxSeconds
		}
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(value); err == nil {
		return date
	}
	return time.Time{}
}

func (u *ListUpdater) save(ctx context.Context) error {
	u.mu.RLock()
	shouldSave := u.status.Dirty && !u.clock.Now().Before(u.status.NextSave)
	u.mu.RUnlock()
	if !shouldSave {
		return nil
	}
	u.logger.Debug("saving snapshot")
	callCtx, cancel := context.WithTimeout(ctx, u.config.RequestTimeout)
	err := u.db.Save(callCtx, u.config.Store)
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		u.logger.Warn("snapshot save failed", "error", err, "consecutiveFailures", u.saveFailures+1)
		u.status.PersistenceError = err
		u.saveFailures++
		u.status.NextSave = u.clock.Now().Add(u.retryDelay(u.saveFailures))
		return err
	}
	if u.saveFailures > 0 {
		u.logger.Info("snapshot save recovered", "previousFailures", u.saveFailures)
	} else {
		u.logger.Debug("snapshot saved")
	}
	u.status.PersistenceError = nil
	u.status.Dirty = false
	u.saveFailures = 0
	u.status.LastSave = u.clock.Now()
	u.status.NextSave = time.Time{}
	return nil
}

func (u *ListUpdater) nextDelay() time.Duration {
	u.mu.RLock()
	defer u.mu.RUnlock()
	next := u.status.Lists[0].NextAttempt
	for _, s := range u.status.Lists[1:] {
		if s.NextAttempt.Before(next) {
			next = s.NextAttempt
		}
	}
	if u.status.Dirty && u.status.NextSave.Before(next) {
		next = u.status.NextSave
	}
	delay := next.Sub(u.clock.Now())
	if delay < 0 {
		return 0
	}
	return delay
}
