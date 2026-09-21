package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sb "github.com/ericls/gosafe5"
	"github.com/ericls/gosafe5/httpserver"
)

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprint(out, `sbserver runs an HTTP server backed by a synchronized local
threat database.

Requires the SAFE_BROWSING_API_KEY environment variable to be set.

Usage:
  sbserver [flags]

Flags:
`)
		flag.PrintDefaults()
	}
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	mode := flag.String("mode", string(sb.ModeLocalList), "default mode: local-list or real-time")
	names := flag.String("threat-lists", "mw-4b,se-4b,uws-4b", "comma-separated documented threat list names")
	snapshot := flag.String("snapshot", "", "optional snapshot file (parent directory must exist)")
	capacity := flag.Int("cache-capacity", 10_000, "prefix cache capacity; negative disables caching")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, or error")
	flag.Parse()

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if flag.NArg() != 0 {
		logger.Error("unexpected positional arguments")
		os.Exit(1)
	}
	if !sb.SearchMode(*mode).Valid() {
		logger.Error("invalid mode")
		os.Exit(1)
	}
	lists, threatNames, err := selectedLists(*names)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	api, err := sb.NewHTTPAPI(sb.APIConfig{APIKey: os.Getenv("SAFE_BROWSING_API_KEY"), Logger: logger})
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	config := sb.UpdaterConfig{API: api, Lists: lists, Logger: logger}
	if *snapshot != "" {
		config.Store = sb.FileStore{Path: *snapshot}
	}
	updater, err := sb.NewListUpdater(config)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	checker, err := sb.NewURLChecker(sb.URLCheckerConfig{
		API: api, Lists: updater, ThreatLists: threatNames, CacheCapacity: *capacity, Logger: logger,
		Diagnostic: func(d sb.SearchDiagnostic) { logger.Debug("search", "mode", d.Mode, "event", d.Event) },
	})
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	handler, err := httpserver.NewHandler(httpserver.Config{Checker: checker, DefaultMode: sb.SearchMode(*mode), Logger: logger})
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("sbserver listening", "addr", listener.Addr(), "mode", *mode)
	if err := serve(ctx, listener, handler, updater); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid -log-level %q: must be debug, info, warn, or error", s)
	}
}

// Names and widths: https://developers.google.com/safe-browsing/reference/Local.Database
func selectedLists(value string) ([]sb.HashListInfo, []string, error) {
	known := map[string]sb.ThreatType{
		"mw-4b":   sb.ThreatMalware,
		"se-4b":   sb.ThreatSocialEngineering,
		"uws-4b":  sb.ThreatUnwantedSoftware,
		"uwsa-4b": sb.ThreatUnwantedSoftware,
		"pha-4b":  sb.ThreatPotentiallyHarmfulApplication,
	}
	var lists []sb.HashListInfo
	var names []string
	seen := map[string]bool{}
	for name := range strings.SplitSeq(value, ",") {
		name = strings.TrimSpace(name)
		kind, ok := known[name]
		if !ok || seen[name] {
			return nil, nil, fmt.Errorf("unknown or duplicate threat list name")
		}
		seen[name] = true
		names = append(names, name)
		lists = append(lists, sb.HashListInfo{Name: name, HashLength: sb.HashLength4, Metadata: sb.ListMetadata{ThreatTypes: []string{string(kind)}}})
	}
	lists = append(lists, sb.HashListInfo{Name: "gc-32b", HashLength: sb.HashLength32, Metadata: sb.ListMetadata{LikelySafeTypes: []string{"GENERAL_BROWSING"}}})
	return lists, names, nil
}

type runner interface{ Run(context.Context) error }

// serve owns the listener and joins both workers before returning.
func serve(ctx context.Context, listener net.Listener, handler http.Handler, updater runner) error {
	defer listener.Close()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return workerCtx },
	}
	updateDone, httpDone := make(chan error, 1), make(chan error, 1)
	go func() { updateDone <- updater.Run(workerCtx) }()
	go func() { httpDone <- server.Serve(listener) }()
	var result error
	var updaterStopped, httpStopped bool
	select {
	case <-ctx.Done():
	case result = <-updateDone:
		updaterStopped = true
	case result = <-httpDone:
		httpStopped = true
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		if result == nil {
			result = err
		}
	}
	if !updaterStopped {
		err := <-updateDone
		if result == nil && !errors.Is(err, context.Canceled) {
			result = err
		}
	}
	if !httpStopped {
		err := <-httpDone
		if result == nil && !errors.Is(err, http.ErrServerClosed) {
			result = err
		}
	}
	if errors.Is(result, context.Canceled) || errors.Is(result, http.ErrServerClosed) {
		return nil
	}
	return result
}
