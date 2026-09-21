package gosafe5

import (
	"context"
	"fmt"
	"time"
)

// ListResponseError identifies a list whose response could not be decoded.
// Name is the requested name, not an untrusted response name.
type ListResponseError struct {
	Name string
	Err  error
}

func (e *ListResponseError) Error() string { return fmt.Sprintf("list %q: %v", e.Name, e.Err) }
func (e *ListResponseError) Unwrap() error { return e.Err }

// API is the mockable Safe Browsing service boundary. Implementations return
// decoded domain values; callers need not depend on HTTP or protobuf types.
// Calls do not mutate a database, schedule retries, or cache results.
type API interface {
	ListHashLists(context.Context, ListHashListsRequest) (HashListsPage, error)
	GetHashList(context.Context, HashListRequest, SizeConstraints) (DatabaseUpdate, error)
	BatchGetHashLists(context.Context, []HashListRequest, SizeConstraints) ([]DatabaseUpdate, error)
	SearchHashes(context.Context, []Prefix4) (HashSearchResult, error)
}

// HashListRequest associates a name and opaque version with the expected width.
// Width is required even when the response has no additions. Obtain it from
// ListHashLists, a local snapshot, or a known list's documented width.
type HashListRequest struct {
	Name       string
	Version    []byte
	HashLength HashLength
}

// SizeConstraints are per-list server limits. Zero means unspecified.
// MaxUpdateEntries must be zero or at least 1024.
type SizeConstraints struct {
	MaxUpdateEntries   int32
	MaxDatabaseEntries int32
}

type ListHashListsRequest struct {
	PageSize  int32
	PageToken string
}

type HashListInfo struct {
	Name       string
	HashLength HashLength
	Metadata   ListMetadata
}

type HashListsPage struct {
	Lists         []HashListInfo
	NextPageToken string
}

type ThreatType string

const (
	ThreatMalware                       ThreatType = "MALWARE"
	ThreatSocialEngineering             ThreatType = "SOCIAL_ENGINEERING"
	ThreatUnwantedSoftware              ThreatType = "UNWANTED_SOFTWARE"
	ThreatPotentiallyHarmfulApplication ThreatType = "POTENTIALLY_HARMFUL_APPLICATION"
)

type ThreatAttribute string

const (
	// AttributeCanary must not be used for enforcement.
	AttributeCanary ThreatAttribute = "CANARY"
	// AttributeFrameOnly applies to frame loads, not top-level navigations.
	AttributeFrameOnly ThreatAttribute = "FRAME_ONLY"
)

type FullHashDetail struct {
	ThreatType ThreatType
	Attributes []ThreatAttribute
}

type FullHashMatch struct {
	Hash    Hash
	Details []FullHashDetail
}

// HashSearchResult retains every returned hash, even when all its details were
// discarded as unknown. An empty Details slice must not be treated as a threat.
// CacheDuration applies to every requested prefix, including negative matches.
// No TTL extension or enforcement policy is applied by the transport.
type HashSearchResult struct {
	FullHashes    []FullHashMatch
	CacheDuration time.Duration
}
