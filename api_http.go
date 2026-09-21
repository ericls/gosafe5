package gosafe5

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	pb "github.com/ericls/gosafe5/internal/sbproto"
	"google.golang.org/protobuf/proto"
)

var (
	ErrInvalidAPIRequest   = errors.New("gosafe5: invalid API request")
	ErrInvalidAPIResponse  = errors.New("gosafe5: invalid API response")
	ErrAPIResponseTooLarge = errors.New("gosafe5: API response exceeds size limit")
)

// HTTPError exposes status and Retry-After without including URLs, API keys, or
// response bodies (which may echo credentials). RetryAfter is the raw header.
type HTTPError struct {
	StatusCode int
	RetryAfter string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("gosafe5: Google API returned HTTP %d", e.StatusCode)
}

// APIConfig configures the protobuf-over-HTTP transport. Zero limits default to
// 64 MiB per response and 10 million decoded entries per Rice block. These are
// client safety limits, independent of server SizeConstraints. HTTPClient nil
// uses a 30-second timeout. BaseURL defaults to Google's production endpoint;
// overriding it is useful for tests. Redirects are never followed.
type APIConfig struct {
	APIKey           string
	HTTPClient       *http.Client
	BaseURL          string
	UserAgent        string
	MaxResponseBytes int64
	MaxEntries       int
}

// HTTPAPI implements API using GET query parameters and binary protobuf
// responses. It is safe for concurrent use. It does not use Google's JSON client.
type HTTPAPI struct {
	client                  http.Client
	baseURL, key, userAgent string
	maxBytes                int64
	maxEntries              int
}

var _ API = (*HTTPAPI)(nil)

func NewHTTPAPI(c APIConfig) (*HTTPAPI, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("%w: missing API key", ErrInvalidAPIRequest)
	}
	if c.BaseURL == "" {
		c.BaseURL = "https://safebrowsing.googleapis.com"
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid base URL", ErrInvalidAPIRequest)
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 64 << 20
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 10_000_000
	}
	if c.MaxResponseBytes < 0 || c.MaxResponseBytes == math.MaxInt64 || c.MaxEntries < 0 {
		return nil, fmt.Errorf("%w: invalid limits", ErrInvalidAPIRequest)
	}
	if c.UserAgent == "" {
		c.UserAgent = "gosafe5"
	}
	client := http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPAPI{client: client, baseURL: strings.TrimRight(c.BaseURL, "/"), key: c.APIKey,
		userAgent: c.UserAgent, maxBytes: c.MaxResponseBytes, maxEntries: c.MaxEntries}, nil
}

func (a *HTTPAPI) get(ctx context.Context, path string, q url.Values, result proto.Message) error {
	q.Set("key", a.key)
	q.Set("alt", "proto")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+path+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("%w: cannot construct request", ErrInvalidAPIRequest)
	}
	req.Header.Set("Accept", "application/x-protobuf")
	req.Header.Set("User-Agent", a.userAgent)
	resp, err := a.client.Do(req)
	if err != nil {
		// net/http wraps transport errors in url.Error, whose URL contains key.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("gosafe5: API transport: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{resp.StatusCode, resp.Header.Get("Retry-After")}
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		media, _, err := mime.ParseMediaType(ct)
		if err != nil || (media != "application/x-protobuf" && media != "application/octet-stream" && media != "application/vnd.google.protobuf" && media != "application/protobuf") {
			return fmt.Errorf("%w: expected protobuf content type", ErrInvalidAPIResponse)
		}
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, resp.Body}, a.maxBytes+1))
	if err != nil {
		return fmt.Errorf("gosafe5: read API response: %w", err)
	}
	if int64(len(data)) > a.maxBytes {
		return ErrAPIResponseTooLarge
	}
	if err := proto.Unmarshal(data, result); err != nil {
		return fmt.Errorf("%w: malformed protobuf", ErrInvalidAPIResponse)
	}
	return nil
}

func validListRequest(r HashListRequest) error {
	if !validListName(r.Name) || !r.HashLength.valid() {
		return fmt.Errorf("%w: list name or hash width", ErrInvalidAPIRequest)
	}
	return nil
}

func validListName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func constraintQuery(c SizeConstraints) (url.Values, error) {
	if c.MaxUpdateEntries < 0 || c.MaxUpdateEntries > 0 && c.MaxUpdateEntries < 1024 || c.MaxDatabaseEntries < 0 {
		return nil, fmt.Errorf("%w: size constraints", ErrInvalidAPIRequest)
	}
	q := url.Values{}
	if c.MaxUpdateEntries != 0 {
		q.Set("sizeConstraints.maxUpdateEntries", strconv.FormatInt(int64(c.MaxUpdateEntries), 10))
	}
	if c.MaxDatabaseEntries != 0 {
		q.Set("sizeConstraints.maxDatabaseEntries", strconv.FormatInt(int64(c.MaxDatabaseEntries), 10))
	}
	return q, nil
}

func (a *HTTPAPI) GetHashList(ctx context.Context, r HashListRequest, c SizeConstraints) (DatabaseUpdate, error) {
	if err := validListRequest(r); err != nil {
		return DatabaseUpdate{}, err
	}
	q, err := constraintQuery(c)
	if err != nil {
		return DatabaseUpdate{}, err
	}
	if len(r.Version) != 0 {
		q.Set("version", base64.URLEncoding.EncodeToString(r.Version))
	}
	var response pb.HashList
	if err := a.get(ctx, "/v5/hashList/"+r.Name, q, &response); err != nil {
		return DatabaseUpdate{}, err
	}
	update, err := a.decodeList(r, &response)
	if err != nil {
		return DatabaseUpdate{}, &ListResponseError{Name: r.Name, Err: err}
	}
	return update, nil
}

func (a *HTTPAPI) BatchGetHashLists(ctx context.Context, requests []HashListRequest, c SizeConstraints) ([]DatabaseUpdate, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("%w: empty batch", ErrInvalidAPIRequest)
	}
	q, err := constraintQuery(c)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, r := range requests {
		if err := validListRequest(r); err != nil {
			return nil, err
		}
		if names[r.Name] {
			return nil, fmt.Errorf("%w: duplicate name", ErrInvalidAPIRequest)
		}
		names[r.Name] = true
		q.Add("names", r.Name)
		if len(r.Version) != 0 {
			q.Add("version", base64.URLEncoding.EncodeToString(r.Version))
		}
	}
	var response pb.BatchGetHashListsResponse
	if err := a.get(ctx, "/v5/hashLists:batchGet", q, &response); err != nil {
		return nil, err
	}
	if len(response.HashLists) != len(requests) {
		return nil, fmt.Errorf("%w: batch list count", ErrInvalidAPIResponse)
	}
	updates := make([]DatabaseUpdate, len(requests))
	for i, r := range requests {
		updates[i], err = a.decodeList(r, response.HashLists[i])
		if err != nil {
			return nil, &ListResponseError{Name: r.Name, Err: err}
		}
	}
	return updates, nil
}

func (a *HTTPAPI) ListHashLists(ctx context.Context, r ListHashListsRequest) (HashListsPage, error) {
	if r.PageSize < 0 {
		return HashListsPage{}, fmt.Errorf("%w: negative page size", ErrInvalidAPIRequest)
	}
	q := url.Values{}
	if r.PageSize != 0 {
		q.Set("pageSize", strconv.FormatInt(int64(r.PageSize), 10))
	}
	if r.PageToken != "" {
		q.Set("pageToken", r.PageToken)
	}
	var response pb.ListHashListsResponse
	if err := a.get(ctx, "/v5/hashLists", q, &response); err != nil {
		return HashListsPage{}, err
	}
	page := HashListsPage{NextPageToken: response.NextPageToken}
	seen := map[string]bool{}
	for _, l := range response.HashLists {
		if !validListName(l.GetName()) || l.GetMetadata() == nil || seen[l.Name] {
			return HashListsPage{}, fmt.Errorf("%w: list metadata", ErrInvalidAPIResponse)
		}
		seen[l.Name] = true
		width := metadataWidth(l.Metadata.HashLength)
		if !width.valid() {
			return HashListsPage{}, fmt.Errorf("%w: metadata width", ErrInvalidAPIResponse)
		}
		metadata, err := decodeMetadata(l.Metadata)
		if err != nil {
			return HashListsPage{}, err
		}
		page.Lists = append(page.Lists, HashListInfo{Name: l.Name, HashLength: width, Metadata: *metadata})
	}
	return page, nil
}

func (a *HTTPAPI) SearchHashes(ctx context.Context, prefixes []Prefix4) (HashSearchResult, error) {
	if len(prefixes) == 0 || len(prefixes) > 1000 {
		return HashSearchResult{}, fmt.Errorf("%w: expected 1–1000 prefixes", ErrInvalidAPIRequest)
	}
	q := url.Values{}
	requested := make(map[Prefix4]bool, len(prefixes))
	for _, p := range prefixes {
		if !requested[p] {
			q.Add("hashPrefixes", base64.URLEncoding.EncodeToString(p[:]))
		}
		requested[p] = true
	}
	var response pb.SearchHashesResponse
	if err := a.get(ctx, "/v5/hashes:search", q, &response); err != nil {
		return HashSearchResult{}, err
	}
	duration, err := decodeDuration(response.CacheDuration)
	if err != nil {
		return HashSearchResult{}, err
	}
	result := HashSearchResult{CacheDuration: duration}
	for _, match := range response.FullHashes {
		if len(match.GetFullHash()) != 32 {
			return HashSearchResult{}, fmt.Errorf("%w: full hash length", ErrInvalidAPIResponse)
		}
		h := Hash(match.FullHash)
		if !requested[h.Prefix4()] {
			return HashSearchResult{}, fmt.Errorf("%w: unsolicited full hash", ErrInvalidAPIResponse)
		}
		m := FullHashMatch{Hash: h}
		for _, detail := range match.FullHashDetails {
			threat := threatName(detail.GetThreatType())
			if threat == "" {
				continue
			}
			d := FullHashDetail{ThreatType: ThreatType(threat)}
			valid := true
			for _, attr := range detail.Attributes {
				switch attr {
				case 1:
					d.Attributes = append(d.Attributes, AttributeCanary)
				case 2:
					d.Attributes = append(d.Attributes, AttributeFrameOnly)
				default:
					valid = false
				}
			}
			if valid {
				m.Details = append(m.Details, d)
			}
		}
		result.FullHashes = append(result.FullHashes, m)
	}
	return result, nil
}
