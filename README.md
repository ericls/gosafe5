# gosafe5

`gosafe5` is a Go client/server for [Google Safe Browsing v5](https://developers.google.com/safe-browsing/reference), currently in early
development. Its goal is functional parity with
[`google/safebrowsing`](https://github.com/google/safebrowsing), especially its
local threat database and lookup caching, built around the v5 protocol.

This is not an official client.

## Motivation
- Safe Browsing v4 is being deprecated.
- In practice, I've ran into cases where the v4 online API returns false negatives while v5 online API returns the correct verdict. It seems that v5 matches "transparencyreport.google.com/safe-browsing" results better than v4.

## Project status
- [x] Stateless primitives: URL hashing, Rice encoding/decoding, hash list management.
- [x] In-memory local database: named lists, versioned updates, metadata, lookup, and update timing.
- [x] Snapshot persistence with a pluggable backend and filesystem implementation.
- [x] Mockable v5 API layer: protobuf transport, list discovery/downloads, and hash-prefix searches.
- [ ] Background synchronization.
- [ ] HTTP server: serving `/v5/urls:search` endpoints, with JSON support. (JSON is not supported in from `https://safebrowsing.googleapis.com/v5/urls:search` yet.)

## Development

Requires Go 1.24.5 or later.

## API layer

Construct `NewHTTPAPI(APIConfig{APIKey: key})` and depend on the `API` interface
in application code. It provides `ListHashLists`, `GetHashList`,
`BatchGetHashLists`, and `SearchHashes`. Tests can implement the interface with
ordinary Go values, without an HTTP server or protobuf dependency.

Requests use HTTP GET query parameters and `alt=proto`; responses are decoded
as binary protobuf, with no JSON fallback. List downloads return decoded
`DatabaseUpdate` values for `LocalDatabase.Apply`. Supply the expected hash width
and current opaque version in `HashListRequest`. Discovery exposes pagination
explicitly through `NextPageToken`.

The transport supports context cancellation, configurable HTTP clients and
response/decode limits, and typed HTTP errors with `RetryAfter`. It does not
retry, cache, or apply updates automatically. Hash results retain cache durations
and enforcement attributes; details containing unknown enums are discarded.

Private generated protobuf types are checked in. To regenerate them, install
`protoc` 29.3 and `protoc-gen-go` v1.35.1, then run `go generate ./internal/sbproto`.

## Protocol references

- [URLs and hashing](https://developers.google.com/safe-browsing/reference/URLs.and.Hashing)
- [HashList and Rice messages](https://developers.google.com/safe-browsing/reference/rest/v5/hashList)
- [Local database and encoding example](https://developers.google.com/safe-browsing/reference/Local.Database)
- [Local List Mode](https://developers.google.com/safe-browsing/reference/Local.List.Mode)
