// Package httpserver provides a JSON Safe Browsing URL-search endpoint.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	sb "github.com/ericls/gosafe5"
)

type URLSearcher interface {
	SearchURLs(context.Context, []string, sb.SearchMode) (sb.URLSearchResult, error)
}

type Config struct {
	Checker       URLSearcher
	DefaultMode   sb.SearchMode // Defaults to local-list.
	SearchTimeout time.Duration // Defaults to 30 seconds.
}

type Handler struct{ config Config }

func NewHandler(c Config) (*Handler, error) {
	if c.DefaultMode == "" {
		c.DefaultMode = sb.ModeLocalList
	}
	if c.SearchTimeout == 0 {
		c.SearchTimeout = 30 * time.Second
	}
	if c.Checker == nil || !c.DefaultMode.Valid() || c.SearchTimeout < 0 {
		return nil, fmt.Errorf("%w: invalid handler configuration", sb.ErrInvalidAPIRequest)
	}
	return &Handler{c}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/v5/urls:search" {
		writeError(w, 404, "not found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, 405, "method not allowed")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid query")
		return
	}
	mode := h.config.DefaultMode
	if values, ok := query["mode"]; ok {
		if len(values) != 1 || !sb.SearchMode(values[0]).Valid() {
			writeError(w, 400, "invalid mode")
			return
		}
		mode = sb.SearchMode(values[0])
	}
	urls := query["urls"]
	if err := sb.ValidateSearchURLs(urls); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.config.SearchTimeout)
	defer cancel()
	result, err := h.config.Checker.SearchURLs(ctx, urls, mode)
	if err != nil {
		switch {
		case errors.Is(err, sb.ErrInvalidAPIRequest):
			writeError(w, 400, "invalid search request")
		case errors.Is(err, sb.ErrNotReady):
			writeError(w, 503, "required threat lists are not ready")
		case errors.Is(err, context.DeadlineExceeded):
			writeError(w, 504, "search timed out")
		case errors.Is(err, context.Canceled):
			writeError(w, 503, "search canceled")
		default:
			writeError(w, 503, "search unavailable")
		}
		return
	}
	type threat struct {
		URL         string          `json:"url"`
		ThreatTypes []sb.ThreatType `json:"threatTypes"`
	}
	response := struct {
		Threats       []threat `json:"threats"`
		CacheDuration string   `json:"cacheDuration"`
	}{Threats: []threat{}, CacheDuration: "0s"}
	for _, t := range result.Threats {
		response.Threats = append(response.Threats, threat{t.URL, t.ThreatTypes})
	}
	_ = json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
