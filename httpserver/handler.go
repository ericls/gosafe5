// Package httpserver provides a JSON Safe Browsing URL-search endpoint.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	Logger        *slog.Logger  // Defaults to slog.Default().
}

type Handler struct {
	config Config
	logger *slog.Logger
}

func NewHandler(c Config) (*Handler, error) {
	if c.DefaultMode == "" {
		c.DefaultMode = sb.ModeLocalList
	}
	if c.SearchTimeout == 0 {
		c.SearchTimeout = 30 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Checker == nil || !c.DefaultMode.Valid() || c.SearchTimeout < 0 {
		return nil, fmt.Errorf("%w: invalid handler configuration", sb.ErrInvalidAPIRequest)
	}
	return &Handler{config: c, logger: c.Logger.With("component", "httpserver")}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.logger.DebugContext(r.Context(), "request", "method", r.Method, "path", r.URL.Path)
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
	h.logger.DebugContext(r.Context(), "search", "mode", mode, "urls", len(urls))
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
		h.logger.DebugContext(r.Context(), "search failed", "mode", mode, "error", err)
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
	h.logger.DebugContext(r.Context(), "search complete", "mode", mode, "threats", len(response.Threats))
	_ = json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
