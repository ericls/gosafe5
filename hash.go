package gosafe5

import "crypto/sha256"

// Hash is the SHA-256 digest of a canonical host/path expression.
type Hash [sha256.Size]byte

// Prefix4 is the prefix used by v5 online hash searches.
type Prefix4 [4]byte

// ListChecksum is the SHA-256 digest of a sorted list's concatenated entries.
type ListChecksum [sha256.Size]byte

// Prefix4 returns the first four bytes, without changing their byte order.
func (h Hash) Prefix4() Prefix4 { return Prefix4(h[:4]) }
