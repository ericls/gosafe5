# gosafe5

`gosafe5` is a Go client/server for [Google Safe Browsing v5](https://developers.google.com/safe-browsing/reference), currently in early
development. Its goal is functional parity with
[`google/safebrowsing`](https://github.com/google/safebrowsing), especially its
local threat database and lookup caching, built around the v5 protocol.

This is not an official client.

## Motivation
- Safe Browsing v4 is being deprecated.
- In practice, I've ran into cases where the v4 online API returns false negatives while v5 online API returns the correct verdict. It seems that v5 matches "transparencyreport.google.com/safe-browsing" results better than v4.

## Usage

`cmd/sbserver` runs an HTTP server backed by a local threat database, which is synced with Google's safe browsing API database. 
Run with `-h` to see all flags.

The server exposes the following endpoints:
- `GET /v5/urls:search?urls=...&mode=...` checks URLs against the threat
  database. `mode` is optional.

If `mode` is supplied, the endpoint will use the specified mode for the request. If not supplied, it will use the default mode specified by the `-mode` flag. [`local-list`](https://developers.google.com/safe-browsing/reference/Local.List.Mode)
and [`real-time`](https://developers.google.com/safe-browsing/reference/Real.Time.Mode) are supported.

```sh
./sbserver -snapshot ./safebrowsing.snapshot
```

## Development

Requires Go 1.24.5 or later.

Private generated protobuf types are checked in. To regenerate them, install
`protoc` 29.3 and `protoc-gen-go` v1.35.1, then run `go generate ./internal/sbproto`.

## Protocol references

- [URLs and hashing](https://developers.google.com/safe-browsing/reference/URLs.and.Hashing)
- [HashList and Rice messages](https://developers.google.com/safe-browsing/reference/rest/v5/hashList)
- [Local database and encoding example](https://developers.google.com/safe-browsing/reference/Local.Database)
- [Local List Mode](https://developers.google.com/safe-browsing/reference/Local.List.Mode)
- [Real Time Mode](https://developers.google.com/safe-browsing/reference/Real.Time.Mode)
