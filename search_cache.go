package gosafe5

import (
	"container/list"
	"sync"
	"time"
)

type prefixEntry struct {
	prefix  Prefix4
	matches []FullHashMatch // Owned immutable data, never exposed publicly.
	expires time.Time
}

type prefixCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[Prefix4]*list.Element
	lru      *list.List
}

func newPrefixCache(capacity int) *prefixCache {
	return &prefixCache{capacity: capacity, entries: make(map[Prefix4]*list.Element), lru: list.New()}
}

func (c *prefixCache) get(p Prefix4, now time.Time) ([]FullHashMatch, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[p]
	if e == nil {
		return nil, false
	}
	v := e.Value.(prefixEntry)
	if !now.Before(v.expires) {
		delete(c.entries, p)
		c.lru.Remove(e)
		return nil, false
	}
	c.lru.MoveToFront(e)
	return v.matches, true
}

func (c *prefixCache) put(p Prefix4, matches []FullHashMatch, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.capacity <= 0 {
		return
	}
	v := prefixEntry{p, matches, expires}
	if e := c.entries[p]; e != nil {
		e.Value = v
		c.lru.MoveToFront(e)
		return
	}
	c.entries[p] = c.lru.PushFront(v)
	if c.lru.Len() > c.capacity {
		e := c.lru.Back()
		delete(c.entries, e.Value.(prefixEntry).prefix)
		c.lru.Remove(e)
	}
}

func cloneMatches(matches []FullHashMatch) []FullHashMatch {
	out := make([]FullHashMatch, len(matches))
	for i, m := range matches {
		out[i] = FullHashMatch{Hash: m.Hash, Details: append([]FullHashDetail(nil), m.Details...)}
		for j := range out[i].Details {
			out[i].Details[j].Attributes = append([]ThreatAttribute(nil), m.Details[j].Attributes...)
		}
	}
	return out
}
