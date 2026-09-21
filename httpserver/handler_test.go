package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sb "github.com/ericls/gosafe5"
)

type searchFunc func(context.Context, []string, sb.SearchMode) (sb.URLSearchResult, error)

func (f searchFunc) SearchURLs(ctx context.Context, u []string, m sb.SearchMode) (sb.URLSearchResult, error) {
	return f(ctx, u, m)
}

func TestHandlerModeAndJSON(t *testing.T) {
	for _, tc := range []struct {
		override string
		mode     sb.SearchMode
	}{{"", sb.ModeRealTime}, {"&mode=local-list", sb.ModeLocalList}} {
		h, err := NewHandler(Config{DefaultMode: sb.ModeRealTime, Checker: searchFunc(func(ctx context.Context, urls []string, mode sb.SearchMode) (sb.URLSearchResult, error) {
			if mode != tc.mode || len(urls) != 2 || urls[1] != "https://two.example/" {
				t.Fatalf("%v %v", mode, urls)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("no timeout")
			}
			return sb.URLSearchResult{Threats: []sb.URLThreat{{URL: urls[0], ThreatTypes: []sb.ThreatType{sb.ThreatMalware}}}}, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/v5/urls:search?urls=https://one.example/&urls=https://two.example/"+tc.override, nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w)
		}
		var response struct {
			Threats []struct {
				URL         string
				ThreatTypes []string
			}
			CacheDuration string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.CacheDuration != "0s" || len(response.Threats) != 1 || response.Threats[0].URL != "https://one.example/" || response.Threats[0].ThreatTypes[0] != "MALWARE" {
			t.Fatal(w.Body.String())
		}
	}
}

func TestHandlerValidation(t *testing.T) {
	calls := 0
	h, _ := NewHandler(Config{Checker: searchFunc(func(context.Context, []string, sb.SearchMode) (sb.URLSearchResult, error) {
		calls++
		return sb.URLSearchResult{}, nil
	})})
	base := "/v5/urls:search"
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"POST", base, 405}, {"GET", "/other", 404}, {"GET", base, 400},
		{"GET", base + "?urls=invalid", 400},
		{"GET", base + "?urls=https://example.com/&urls=invalid", 400},
		{"GET", base + "?urls=https://example.com/&mode=bad", 400},
		{"GET", base + "?urls=https://example.com/&mode=", 400},
		{"GET", base + "?urls=https://example.com/&mode=local-list&mode=real-time", 400},
		{"GET", base + "?urls=%zz", 400},
		{"GET", base + "?" + strings.Repeat("urls=https://example.com/&", 51), 400},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
		if tc.code == 405 && w.Header().Get("Allow") != "GET" {
			t.Fatal("missing Allow")
		}
	}
	if calls != 0 {
		t.Fatal("invalid input reached checker")
	}
}

func TestHandlerErrorsAndEmpty(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{nil, 200}, {sb.ErrNotReady, 503}, {sb.ErrInvalidAPIRequest, 400}, {context.DeadlineExceeded, 504}, {context.Canceled, 503}, {errors.New("SECRET"), 503}} {
		h, _ := NewHandler(Config{Checker: searchFunc(func(context.Context, []string, sb.SearchMode) (sb.URLSearchResult, error) {
			return sb.URLSearchResult{}, tc.err
		})})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/v5/urls:search?urls="+url.QueryEscape("https://example.com/"), nil))
		if w.Code != tc.code || strings.Contains(w.Body.String(), "SECRET") {
			t.Fatal(w)
		}
		if tc.err == nil && w.Body.String() != "{\"threats\":[],\"cacheDuration\":\"0s\"}\n" {
			t.Fatal(w.Body.String())
		}
	}
}

func TestHandlerTimeout(t *testing.T) {
	h, _ := NewHandler(Config{SearchTimeout: time.Millisecond, Checker: searchFunc(func(ctx context.Context, _ []string, _ sb.SearchMode) (sb.URLSearchResult, error) {
		<-ctx.Done()
		return sb.URLSearchResult{}, ctx.Err()
	})})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v5/urls:search?urls=https://example.com/", nil))
	if w.Code != 504 {
		t.Fatal(w.Code)
	}
}
