package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
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
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	mode := flag.String("mode", string(sb.ModeLocalList), "default mode: local-list or real-time")
	names := flag.String("threat-lists", "mw-4b,se-4b,uws-4b", "comma-separated documented threat list names")
	snapshot := flag.String("snapshot", "", "optional snapshot file (parent directory must exist)")
	capacity := flag.Int("cache-capacity", 10_000, "prefix cache capacity; negative disables caching")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	if !sb.SearchMode(*mode).Valid() {
		log.Fatal("invalid mode")
	}
	lists, threatNames, err := selectedLists(*names)
	if err != nil {
		log.Fatal(err)
	}
	api, err := sb.NewHTTPAPI(sb.APIConfig{APIKey: os.Getenv("SAFE_BROWSING_API_KEY")})
	if err != nil {
		log.Fatal(err)
	}
	config := sb.UpdaterConfig{API: api, Lists: lists}
	if *snapshot != "" {
		config.Store = sb.FileStore{Path: *snapshot}
	}
	updater, err := sb.NewListUpdater(config)
	if err != nil {
		log.Fatal(err)
	}
	checker, err := sb.NewURLChecker(sb.URLCheckerConfig{
		API: api, Lists: updater, ThreatLists: threatNames, CacheCapacity: *capacity,
		Diagnostic: func(d sb.SearchDiagnostic) { log.Printf("search mode=%s event=%s", d.Mode, d.Event) },
	})
	if err != nil {
		log.Fatal(err)
	}
	handler, err := httpserver.NewHandler(httpserver.Config{Checker: checker, DefaultMode: sb.SearchMode(*mode)})
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("sbserver listening on %s (default mode=%s)", listener.Addr(), *mode)
	if err := serve(ctx, listener, handler, updater); err != nil {
		log.Fatal(err)
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
