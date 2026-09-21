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
- [x] Managed lists: background synchronization, retry/recovery, health, and automatic persistence.
- [x] URL checking with local-list and real-time modes, shared prefix-response caching, and a JSON `/v5/urls:search` server.


## Development

Requires Go 1.24.5 or later.

Private generated protobuf types are checked in. To regenerate them, install
`protoc` 29.3 and `protoc-gen-go` v1.35.1, then run `go generate ./internal/sbproto`.

### Server

Set `SAFE_BROWSING_API_KEY` in the environment, then run:

```sh
go run ./cmd/sbserver -snapshot ./safebrowsing.snapshot
```

## Protocol references

- [URLs and hashing](https://developers.google.com/safe-browsing/reference/URLs.and.Hashing)
- [HashList and Rice messages](https://developers.google.com/safe-browsing/reference/rest/v5/hashList)
- [Local database and encoding example](https://developers.google.com/safe-browsing/reference/Local.Database)
- [Local List Mode](https://developers.google.com/safe-browsing/reference/Local.List.Mode)
