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
- [ ] Local list: storage, update, and lookup.
- [ ] HTTP server: serving `/v5/urls:search` endpoints, with JSON support. (JSON is not supported in from `https://safebrowsing.googleapis.com/v5/urls:search` yet.)

## Development

Requires Go 1.24.5 or later.

## Protocol references

- [URLs and hashing](https://developers.google.com/safe-browsing/reference/URLs.and.Hashing)
- [HashList and Rice messages](https://developers.google.com/safe-browsing/reference/rest/v5/hashList)
- [Local database and encoding example](https://developers.google.com/safe-browsing/reference/Local.Database)
- [Local List Mode](https://developers.google.com/safe-browsing/reference/Local.List.Mode)
