package gosafe5

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		raw, host, path, query string
		hasQuery               bool
	}{
		{"HTTP://User:pass@..ExAmPlE...COM.:8080", "example.com", "/", "", false},
		{"http://example.com/a//b/../c/./?x=/../a//b+z#fragment", "example.com", "/a/c/", "x=/../a//b+z", true},
		{"http://example.com/a/..", "example.com", "/", "", false},
		{"http://example.com/../../a/.", "example.com", "/a/", "", false},
		{"http://example.com/?", "example.com", "/", "", true},
		{"http://example.com?x=1", "example.com", "/", "x=1", true},
		{"http://example.com/a%252fb/%252e%252e/c", "example.com", "/a/c", "", false},
		{"http://example.com/%25%32%35", "example.com", "/%25", "", false},
		{"http://example.com/%25%32%35%25%32%35", "example.com", "/%25%25", "", false},
		{"http://example.com/%2525252525252525", "example.com", "/%25", "", false},
		{"http://example.com/asdf%25%32%35asd", "example.com", "/asdf%25asd", "", false},
		{"http://example.com/%%%25%32%35asd%%", "example.com", "/%25%25%25asd%25%25", "", false},
		{"http://example.com/a%23b#gone", "example.com", "/a%23b", "", false},
		{"http://example.com/a\tb\rc\nd%0a%00", "example.com", "/abcd%0A%00", "", false},
		{"http://example.com/a b/%zz", "example.com", "/a%20b/%25zz", "", false},
		{"http://%31%32%37.1/", "127.0.0.1", "/", "", false},
		{"http://0177.0x0.1/", "127.0.0.1", "/", "", false},
		{"http://2130706433/", "127.0.0.1", "/", "", false},
		{"http://0xffffffff/", "255.255.255.255", "/", "", false},
		{"http://0/", "0.0.0.0", "/", "", false},
		{"http://bücher.de/é", "xn--bcher-kva.de", "/%C3%A9", "", false},
		{"http://example。com/", "example.com", "/", "", false},
		{"http://[2001:0db8:0000::1]:80/", "[2001:db8::1]", "/", "", false},
		{"http://[::ffff:192.0.2.1]/", "192.0.2.1", "/", "", false},
		{"http://[64:ff9b::c000:201]/", "192.0.2.1", "/", "", false},
		{"http://[64:ff9b:1::c000:201]/", "[64:ff9b:1::c000:201]", "/", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := Canonicalize(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			q, present := u.Query()
			if u.Host() != tc.host || u.Path() != tc.path || q != tc.query || present != tc.hasQuery {
				t.Fatalf("got %#v; want host=%q path=%q query=%q present=%v", u, tc.host, tc.path, tc.query, tc.hasQuery)
			}
		})
	}
}

func TestInvalidURLs(t *testing.T) {
	for _, raw := range []string{"", "example.com", "//example.com/", "ftp://example.com/", "http:///x", "http://.../", "http://user@/", "http://host:/", "http://host:65536/", "http://host:abc/", "http://host:+80/", "http://[::1", "http://[::1]oops/", "http://[127.0.0.1]/", "http://[fe80::1%25en0]/", "http://a:b:c/", "http://exa\\mple.com/"} {
		if _, err := Canonicalize(raw); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("accepted %q: %v", raw, err)
		}
		if _, err := URLHashes(raw); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("hash accepted %q", raw)
		}
	}
	if _, err := (CanonicalURL{}).Expressions(); !errors.Is(err, ErrInvalidURL) {
		t.Fatal("zero URL", err)
	}
}

func TestExpressions(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"http://a.b.com/1/2.html?param=1", []string{
			"a.b.com/1/2.html?param=1", "a.b.com/1/2.html", "a.b.com/", "a.b.com/1/",
			"b.com/1/2.html?param=1", "b.com/1/2.html", "b.com/", "b.com/1/",
		}},
		{"http://a.b.c.d.e.f.com/1.html", []string{
			"a.b.c.d.e.f.com/1.html", "a.b.c.d.e.f.com/", "c.d.e.f.com/1.html", "c.d.e.f.com/",
			"d.e.f.com/1.html", "d.e.f.com/", "e.f.com/1.html", "e.f.com/", "f.com/1.html", "f.com/",
		}},
		{"http://1.2.3.4/1/", []string{"1.2.3.4/1/", "1.2.3.4/"}},
		{"http://example.co.uk/1", []string{"example.co.uk/1", "example.co.uk/"}},
		{"http://a.example.co.uk/", []string{"a.example.co.uk/", "example.co.uk/"}},
		{"http://tenant.blogspot.com/", []string{"tenant.blogspot.com/"}},
		{"http://localhost/", []string{"localhost/"}},
		{"http://com/", []string{"com/"}},
		{"http://example.com/?", []string{"example.com/?", "example.com/"}},
		{"http://[2001:db8::1]/", []string{"[2001:db8::1]/"}},
	}
	for _, tc := range tests {
		u, err := Canonicalize(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := u.Expressions()
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v (%v), want %v", tc.raw, got, err, tc.want)
		}
		hashes, err := URLHashes(tc.raw)
		if err != nil || len(hashes) != len(tc.want) {
			t.Fatal("hash count", err)
		}
		for i, expression := range tc.want {
			if hashes[i] != Hash(sha256.Sum256([]byte(expression))) {
				t.Fatal("expression hashing")
			}
		}
	}
	u, _ := Canonicalize("https://a.b.c.d.e.f.example.co.uk/1/2/3/4/5?x=1")
	expressions, _ := u.Expressions()
	if len(expressions) != 30 {
		t.Fatalf("max expressions: %d", len(expressions))
	}
	for _, e := range expressions {
		if strings.Contains(e, "/1/2/3/4/") && !strings.Contains(e, "/5") {
			t.Fatal("too many directory prefixes")
		}
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, raw := range []string{"http://example.com/", "http://bücher.de/%252e/?", "http://[::ffff:127.0.0.1]/", "http://example.co.uk/a%23b?x=1#f"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := Canonicalize(raw)
		if err != nil {
			return
		}
		expressions, err := u.Expressions()
		if err != nil || len(expressions) == 0 || len(expressions) > 30 {
			t.Fatal("expression bounds", err)
		}
		seen := map[string]bool{}
		for _, e := range expressions {
			if seen[e] {
				t.Fatal("duplicate expression")
			}
			seen[e] = true
			for _, b := range []byte(e) {
				if b <= 32 || b >= 127 || b == '#' {
					t.Fatal("unescaped byte")
				}
			}
		}
	})
}
