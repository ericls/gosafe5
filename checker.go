package gosafe5

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

type SearchMode string

const (
	ModeLocalList SearchMode = "local-list"
	ModeRealTime  SearchMode = "real-time"
)

func (m SearchMode) Valid() bool { return m == ModeLocalList || m == ModeRealTime }

// HashSearcher and ListSource are the checker's mockable service boundaries.
// Implementations must support concurrent calls. Lists returns one coherent
// snapshot containing verified, immutable HashLists.
type HashSearcher interface {
	SearchHashes(context.Context, []Prefix4) (HashSearchResult, error)
}

type ListSource interface{ Lists() []ListState }

// SearchDiagnostic contains no URLs or upstream errors that might expose secrets.
type SearchDiagnostic struct {
	Mode  SearchMode
	Event string
}

type URLCheckerConfig struct {
	API             HashSearcher
	Lists           ListSource
	ThreatLists     []string
	GlobalCacheList string                 // Default gc-32b.
	CacheCapacity   int                    // Default 10,000 prefixes; negative disables caching.
	Diagnostic      func(SearchDiagnostic) // Optional; must be concurrency-safe.
	Logger          *slog.Logger           // Defaults to slog.Default().
}

type URLThreat struct {
	URL         string
	ThreatTypes []ThreatType
}

// URLSearchResult makes no downstream caching promise. Prefix caching is internal.
type URLSearchResult struct{ Threats []URLThreat }

// URLChecker is safe for concurrent use. Construct with NewURLChecker.
type URLChecker struct {
	config URLCheckerConfig
	cache  *prefixCache
	now    func() time.Time
	logger *slog.Logger
}

func NewURLChecker(c URLCheckerConfig) (*URLChecker, error) {
	if c.API == nil || c.Lists == nil || len(c.ThreatLists) == 0 {
		return nil, fmt.Errorf("%w: API, lists and threat list names required", ErrInvalidAPIRequest)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.GlobalCacheList == "" {
		c.GlobalCacheList = "gc-32b"
	}
	seen := map[string]bool{c.GlobalCacheList: true}
	for _, name := range c.ThreatLists {
		if name == "" || seen[name] {
			return nil, fmt.Errorf("%w: invalid or duplicate threat list", ErrInvalidAPIRequest)
		}
		seen[name] = true
	}
	c.ThreatLists = append([]string(nil), c.ThreatLists...)
	if c.CacheCapacity == 0 {
		c.CacheCapacity = 10_000
	}
	return &URLChecker{config: c, cache: newPrefixCache(c.CacheCapacity), now: time.Now,
		logger: c.Logger.With("component", "gosafe5.checker")}, nil
}

// ValidateSearchURLs validates the entire input without exposing URL text in errors.
func ValidateSearchURLs(urls []string) error {
	_, err := searchURLHashes(urls)
	return err
}

func searchURLHashes(urls []string) ([][]Hash, error) {
	if len(urls) < 1 || len(urls) > 50 {
		return nil, fmt.Errorf("%w: expected 1–50 URLs", ErrInvalidAPIRequest)
	}
	all := make([][]Hash, len(urls))
	for i, raw := range urls {
		hashes, err := URLHashes(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid URL at index %d", ErrInvalidAPIRequest, i)
		}
		all[i] = hashes
	}
	return all, nil
}

// SearchURLs checks top-level navigations. Caller cancellation is never fail-open.
// Missing required local lists return ErrNotReady, not a safe verdict.
func (c *URLChecker) SearchURLs(ctx context.Context, urls []string, mode SearchMode) (URLSearchResult, error) {
	c.logger.DebugContext(ctx, "SearchURLs", "mode", mode, "urls", len(urls))
	result := URLSearchResult{Threats: []URLThreat{}}
	if !mode.Valid() {
		return result, fmt.Errorf("%w: invalid search mode", ErrInvalidAPIRequest)
	}
	all, err := searchURLHashes(urls)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	lists := map[string]HashList{}
	for _, s := range c.config.Lists.Lists() {
		lists[s.Name] = s.Hashes
	}
	// Per-request memoization also retains successful zero-TTL responses.
	memo := map[Prefix4][]FullHashMatch{}
	seen := map[string]bool{}
	for i, raw := range urls {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		local := mode == ModeLocalList
		if !local {
			gc := lists[c.config.GlobalCacheList]
			if gc.HashLength() == HashLength32 {
				for _, h := range all[i] {
					if gc.Matches(h) {
						local = true
						break
					}
				}
			}
		}
		types := map[ThreatType]bool{}
		if !local {
			err = c.check(ctx, all[i], false, lists, memo, types)
			if err != nil {
				if ctx.Err() != nil {
					return result, ctx.Err()
				}
				c.diagnostic(ModeRealTime, "fallback")
				local = true
			}
		}
		if local {
			if err := c.check(ctx, all[i], true, lists, memo, types); err != nil {
				return result, err
			}
		}
		if len(types) > 0 {
			threat := URLThreat{URL: raw}
			for kind := range types {
				threat.ThreatTypes = append(threat.ThreatTypes, kind)
			}
			sort.Slice(threat.ThreatTypes, func(i, j int) bool { return threat.ThreatTypes[i] < threat.ThreatTypes[j] })
			result.Threats = append(result.Threats, threat)
		}
	}
	return result, ctx.Err()
}

func (c *URLChecker) diagnostic(mode SearchMode, event string) {
	if c.config.Diagnostic != nil {
		c.config.Diagnostic(SearchDiagnostic{mode, event})
	}
}

func (c *URLChecker) check(ctx context.Context, hashes []Hash, local bool, lists map[string]HashList, memo map[Prefix4][]FullHashMatch, types map[ThreatType]bool) error {
	if local {
		for _, name := range c.config.ThreatLists {
			if !lists[name].Valid() {
				return ErrNotReady
			}
		}
	}
	wanted := map[Prefix4][]Hash{}
	var prefixes []Prefix4
	for _, h := range hashes {
		p := h.Prefix4()
		matches, ok := memo[p]
		if !ok {
			matches, ok = c.cache.get(p, c.now())
			if ok {
				memo[p] = matches
			}
		}
		if ok {
			collectThreats(h, matches, types)
			continue
		}
		if local {
			candidate := false
			for _, name := range c.config.ThreatLists {
				if lists[name].Matches(h) {
					candidate = true
					break
				}
			}
			if !candidate {
				continue
			}
		}
		if _, ok := wanted[p]; !ok {
			prefixes = append(prefixes, p)
		}
		wanted[p] = append(wanted[p], h)
	}
	for start := 0; start < len(prefixes); start += 30 {
		batch := prefixes[start:min(start+30, len(prefixes))]
		c.logger.DebugContext(ctx, "SearchHashes", "prefixes", len(batch))
		response, err := c.config.API.SearchHashes(ctx, batch)
		if err != nil {
			c.logger.DebugContext(ctx, "SearchHashes failed", "prefixes", len(batch), "error", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		grouped := map[Prefix4][]FullHashMatch{}
		if err == nil {
			for _, p := range batch {
				grouped[p] = nil
			}
			if response.CacheDuration < 0 {
				err = ErrInvalidAPIResponse
			}
			for _, match := range response.FullHashes {
				p := match.Hash.Prefix4()
				if _, ok := grouped[p]; !ok {
					err = ErrInvalidAPIResponse
					break
				}
				grouped[p] = append(grouped[p], match)
			}
		}
		if err != nil {
			if !local {
				return err
			}
			// Fail open on confirmation errors: https://developers.google.com/safe-browsing/reference/Local.List.Mode
			c.diagnostic(ModeLocalList, "fail-open")
			continue
		}
		expires := c.now().Add(response.CacheDuration)
		for _, p := range batch {
			matches := cloneMatches(grouped[p])
			memo[p] = matches
			if response.CacheDuration > 0 {
				c.cache.put(p, matches, expires)
			}
			for _, h := range wanted[p] {
				collectThreats(h, matches, types)
			}
		}
	}
	return nil
}

func collectThreats(h Hash, matches []FullHashMatch, types map[ThreatType]bool) {
	for _, m := range matches {
		if m.Hash != h {
			continue
		}
		for _, d := range m.Details {
			// All currently recognized attributes exclude top-level enforcement.
			if len(d.Attributes) != 0 {
				continue
			}
			switch d.ThreatType {
			case ThreatMalware, ThreatSocialEngineering, ThreatUnwantedSoftware, ThreatPotentiallyHarmfulApplication:
				types[d.ThreatType] = true
			}
		}
	}
}
