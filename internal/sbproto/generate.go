// Package sbproto contains private protobuf wire types. Public callers use the
// transport-independent types in gosafe5.
//
// Regenerate with protoc 29.3 and protoc-gen-go v1.35.1.
package sbproto

//go:generate protoc --go_out=. --go_opt=paths=source_relative safebrowsing.proto
